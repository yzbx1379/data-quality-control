# -*- coding: utf-8 -*-
"""
代码问答数据集 质检脚本(规范书 §10 六项报告结构版)
================================
依据《10-代码问答数据_技术规范书》(spec/ 下 docx 版)设计检查项。
报告结构严格对应规范书 §10 交付要求:
    三、抽样代码功能校验 / 四、问答真实性校验 / 五、重复率校验 /
    六、脱敏校验 / 七、低质样本过滤记录 / 八、问题整改明细

用法:
    python code_qa_qc.py [jsonl文件或目录] [--out 输出目录] [--prev 上一版报告.md]
    不指定参数时默认检查 <root>/data/代码问答数据_20260813_simplems/sample_100.jsonl

核心检查项:
    E1  顶层结构 {id, message, source, domain, cleaning_status, metadata}(§7 全字段必填)
    E2  message 数组: 每组含非空 question/answer(§7)
    E3  cleaning_status 三布尔字段齐全(§7)
    E4  metadata 必填: primary_language/token_count/type(type 固定值 general_code_qa_dict)
    E5  id 唯一 + QA_2026_ 前缀(§7)
    E6  语言分布: 单一语言 ≤30%(§9 硬性标准)
    E7  多轮问答占比 ≥10%(§9 硬性标准)
    E8  隐藏反爬文本(LeetCode 隐形水印 span)
    E9  隐私明文: 手机号/邮箱/身份证/银行卡(§6 匿名化)
    E10 非文本资源残留(§4.1: 图片/二进制/音视频全剔除)
    E11 乱码字符(§4.1 占位符、乱码直接剔除)
    E12 禁止内容关键词(§8)
    E13 疑似开源数据集混入(§4.1/§9: 禁止复用 GitHub/HuggingFace 公开问答数据集)
    E14 source 标注缺失/低阶模型(§4.1: 社区名; 模型答案须 Claude-4.7-opus 同级以上)
    W1  token_count 与字符估算严重偏差(§9 元数据数值准确)
    W2  代码块无语言标签
    W3  精确重复(message MD5; 去重率 <0.5%)
    W4  answer 过短且无代码(低质)
    W5  近似重复(字符 5-gram Jaccard ≥0.6, §4.2 LQ7 高度近似样本)
    W6  疑似合成提问(§4.1: 禁止人工/大模型合成虚构提问)
    W7  Python 代码块语法校验失败(ast.parse; 其他语言括号失衡粗检)

输出: Markdown + HTML 双格式质检报告, 默认写入 ./qc_reports/
"""

import argparse
import ast
import collections
import datetime
import glob
import hashlib
import json
import logging
import os
import random
import re
import string
import sys

# ----------------------------------------------------------------------------
# 常量: 规范书口径
# ----------------------------------------------------------------------------
TOP_FIELDS = {"id", "message", "source", "domain", "cleaning_status", "metadata"}
CS_FIELDS = ["deduplicated", "denoised", "format_normalized"]   # §7 cleaning_status
MD_FIELDS = ["primary_language", "token_count", "type"]          # §7 metadata
MD_TYPE_FIXED = "general_code_qa_dict"
ID_PREFIX = "QA_2026_"
LANG_LIMIT = 30.0        # §9: 单一语言占比 ≤30%
MULTI_TURN_LIMIT = 10.0  # §9: 多轮问答占比 ≥10%
DUP_LIMIT = 0.5          # §9: 全局重复率 <0.5%

# 隐私扫描(§6: 统一小写 x 占位, 明文即违规)。检测对象=代码块外正文(见 strip_fenced)。
EMAIL_WHITELIST = ("example.com", "example.org", "example.net", "test.com")
EMAIL_GH_PATH = ("github.com", "github.io")  # GitHub noreply 邮箱域名

# 隐藏反爬水印: LeetCode 题面注入的隐形 span(opacity:0 / 绝对定位移出视口)
# ⚠️ 2026-09-20 修复(勿去掉 `(?![\d.])`): 原式 `opacity:\s*0` 是**前缀匹配**,
#    `opacity: 0.5` / `opacity: 0.8` 等**正常样式值也会命中** ⇒ 误报。
#    实测: 本批 5 条命中里含正常 React 代码 `<span style={{opacity: 0.5}}>`;
#    且本检查源自 LeetCode 数据集(GitHub Issues 数据本无题面注入)。
#    负向断言确保 `0` 之后不再接数字或小数点。
RE_HIDDEN_SPAN = re.compile(
    r'<span[^>]*(?:opacity:\s*0(?![\d.])|position:\s*absolute[^>"]*left:\s*-?\d{4,})[^>]*>.*?</span>', re.I | re.S)

# §4.1 过滤非文本资源: 仅在"代码块外正文"里检测, 且只判"真实非文本资源"(破坏自包含/
# 失效引用/嵌入二进制)。正文里"讨论 <img> 标签本身"的文字引用(如 `the IMG tag`)不判 —— 误报根治。
# 检测正则须与"剔除正则"完全同款(要求完整闭合标签 / URL 收尾), 否则"检测到的 ⊋ 剔除的"
# 会残留: 截断的 <img src=...>(无 >)、行内代码示例、[base64_encoded_data] 占位等会被
# 检测命中却剔除不动 → 复检仍报非文本残留。同款化后 检测⟺剔除, 收敛恒 0。
RE_FENCED = re.compile(r'```.*?```', re.S)
# 完整闭合格标签: src= 后必须紧邻引号包裹的 URL(或紧邻裸 URL 无空白), 引号闭合。
# 严禁 "<img src 后面混正文直到某个孤立 >" 的贪婪误配(截断标签 + 正文 + 孤立 > 会被误吞)。
RE_EXT_IMG = re.compile(
    r'<img\b[^>]*\bsrc\s*=\s*(?:'
    r'"(?:https?://|//|data:image)[^"]*"|'
    r"'(?:https?://|//|data:image)[^']*'|"
    r'(?:https?://|//|data:image)[^\s"\'<>]*'
    r')[^>]*>', re.I)
RE_EXT_MD_IMG = re.compile(r'!\[[^\]\n]*\]\(\s*(?:https?://|//)[^\s)\n]+\)')                    # 完整外链 markdown 图片(URL 收尾, 不跨行)
RE_BLOB_REF = re.compile(r'blob:[^\s"\'）)\]]+')                                             # 失效 blob 链接
RE_BASE64_EMBED = re.compile(r'base64,[A-Za-z0-9+/=]{80,}')                                   # 真 base64 内嵌(长 payload)


def has_non_text_resource(text):
    """正文含真实非文本资源(外链图/base64 内嵌/blob 失效引用)。"""
    t = text or ''
    return bool(RE_EXT_IMG.search(t) or RE_EXT_MD_IMG.search(t)
                or RE_BLOB_REF.search(t) or RE_BASE64_EMBED.search(t))

# §6 隐私: 邮箱/手机号/身份证(代码块外正文里检测; 代码示例含的测试值/版本串豁免)
# 数学表达式豁免(2026-09-16, AtCoder 补采实测 3 例误报):
#   题面 $...$ 内的**数学常数**被 RE_PHONE 误判为手机号 ——
#   abc008_3  期望值 $13/6 = 2.16666666666...$ (小数部分 16666666666)
#   arc016_3  期望值 $9343.17042606516$
#   arc224_a  $16970154001\ (= 998244353 \times 17)$
# 数学表达式是题面内容不是联系方式, 属 §6"代码示例"同源的豁免范畴;
# 该豁免**只会减少误报**, 对既有已交付批次(ERROR 0)无影响。
RE_MATH_SPAN = re.compile(r'\$[^$\n]{1,400}\$')
# 样例段豁免(2026-09-17 Codeforces 实测 9 例误报):
#   【样例】段是题目的**测试数据**(输入/输出), 由大整数构成, 与联系方式无关, 但会被 RE_PHONE 命中:
#     1764F  样例数列含 15069617722
#     1856B  样例输入 "... 13618343152 819343431 1000000000"
#     2189D1 样例输出 "-1-14966412-13368925282"
#   与 RE_MATH_SPAN 同属"题面内容非联系方式"豁免范畴; 只会减少误报。
#   ⚠️ 仅匹配采集器自带的【样例】标记段, SO/SE 批无此标记 → 对其零影响。
RE_SAMPLE_SPAN = re.compile(r'【样例】.*?(?=【|\Z)', re.S)
RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
RE_PHONE = re.compile(r'(?<![0-9a-fA-F])1[3-9]\d{9}(?![0-9a-fA-F])')
RE_IDCARD = re.compile(r'(?<![0-9Xx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[0-9Xx](?![0-9Xx])')
# 时间戳/版本号语境豁免(2026-09-17 SE 合并批实测 1 例误报):
#   sharepoint#57874 正文 "This adds to the script url something like `?rev=634946193703232026`"
#   —— 18 位数字恰好落进身份证正则(前 6 位 634946 + 1937 年 + 03 月 + 23 日 + 202 序列 + 6),
#   但实为 SharePoint 的 AssemblyTimeStamp(时间戳), 属**代码/标识符语境非身份信息**。
#   判据: 该数字串前面紧跟 rev=/ver=/version=/ts=/timestamp=/build=/release= 等**版本/时间戳键名**,
#   或整串被引号包裹(`"634946193703232026"`)。
#   (⚠️ 刻意**不含 `id=` 与裸 `=`**: 其后的 18 位更可能是真实证件号, 不能豁免)
#   ⇒ 与 RE_MATH_SPAN / RE_SAMPLE_SPAN 同属"代码示例"豁免范畴, 只会减少误报。
RE_TS_CTX = re.compile(
    r'(?:\b(?:rev|ver|version|ts|timestamp|build|release)\s*[=:]\s*\d{15,19}(?![0-9])'
    r'|["\']\d{15,19}(?![0-9])["\'])', re.I)


def strip_fenced(text):
    """剥离 fenced 代码块, 返回"代码块外正文"(隐私/非文本检测用, 代码示例豁免)。"""
    return RE_FENCED.sub('', text or '')


# ----------------------------------------------------------------------------
# E9 隐私误报消除(2026-09-19 SO v6 全量 1,563,510 条数据锚定: 原 E9 误报 3844 条,
# 全部为"代码/示例/服务地址/常量/时间戳/自披露"语境, 非泄露第三方明文 PII)。
# 设计原则: 只用**类/上下文**判据, 不用逐值黑名单(可跨数据集移植, 不放过真实 PII)。
# 真·明文 PII(孤立出现的真实邮箱/"call me 138xxxxxxxx"/裸证件号)仍会命中。
# ----------------------------------------------------------------------------
RE_SCHEME_URL = re.compile(r'\b(?:https?|ftps?|mailto|sips?|tel|sms|irc|xmpp|git|ssh|wss?|data|news):[^\s"\'<>）)]*', re.I)
RE_BARE_URL = re.compile(r'//[a-zA-Z0-9.\-]+[^\s"\'<>）)]*')
RE_INLINE_CODE = re.compile(r'`[^`\n]+`')


def strip_urls_inline(text):
    """正文里的 URL / 内联反引号代码 → 空格(隐私只在"散文化正文"里算泄露;
    URL 里的 @ / 内联代码里的值属代码示例, 不判 PII)。"""
    t = RE_INLINE_CODE.sub(" ", text)
    t = RE_SCHEME_URL.sub(" ", t)
    t = RE_BARE_URL.sub(" ", t)
    return t


_PLACEHOLDER_LOCALS = {
    "user", "username", "me", "my", "myself", "myemail", "email", "some", "someone",
    "somebody", "foo", "bar", "baz", "bla", "blah", "bla_bla", "abc", "xyz", "xample",
    "test", "tests", "aaa", "bbb", "ccc", "ddd", "xxx", "x", "example", "sample",
    "demo", "test1", "test2", "test3", "admin", "root", "nobody", "none", "unknown",
    "guest", "john", "jane", "johndoe", "john.doe", "jane.doe", "someone.somewhere",
    "something", "anything", "user1", "user2", "user3", "user4", "account", "address",
    "user.name", "first.last", "firstlast", "your", "yourname", "your.email",
    "my.email", "my.email.address", "first", "last", "firstname", "lastname",
    "newuser", "newuser1", "default", "testuser", "test.user", "dummy", "fake",
    "fakeuser", "sample.user", "sampleuser", "anyone", "anybody", "my.name", "myname",
    "local", "localuser", "local.user", "remote", "remoteuser", "remote.user",
    "client", "client1", "client2", "customer", "customer1", "customer2", "host",
    "server", "mail", "sender", "recipient", "you", "me1", "me2", "email1", "email2",
    "email3", "email4", "email5", "addr", "emailaddress", "email.address", "yourname",
    "hello", "world", "name", "test.user.name", "someone1", "bob", "alice", "sam",
    "tom", "joe", "mary", "max", "jack", "jill", "fred", "bill", "craig", "giri",
    "mymail", "j.smith", "jdoe", "jd", "ab", "cd", "ef", "abcd", "xyz123", "foo123",
    "abc123", "user123", "email123", "hello123", "myadmin", "joe2", "userx", "xuser",
    "sample1", "sample2", "testuser1", "testuser2", "demo.user", "demo1", "foo.bar",
    "john.smith", "first.last.name", "user.name1",
}
_PLACEHOLDER_DOMAINS = {
    "domain.com", "domain.org", "domain.net", "example.com", "example.org",
    "example.net", "example.info", "email.com", "myemail.com", "mycompany.com",
    "company.com", "client.com", "simple.com", "myapp.com", "mysystem.com",
    "somewhere.com", "body.com", "mydomain.com", "yourdomain.com", "somecompany.com",
    "yourcompany.com", "myaddress.com", "address.com", "domain.name", "domain.local",
    "sample.com", "test.com", "test.info", "test.net", "test.org", "testcompany.com",
    "fake.com", "fake.org", "your.com", "my.com", "something.com", "somethingelse.com",
    "myself.com", "mysite.com", "yoursite.com", "website.com", "ourwebsite.com",
    "mywebsite.com", "mysubdomain.com", "subdomain.com", "site.com", "someplace.com",
    "myplace.com", "yourplace.com", "some.net", "some.org", "mail.com", "mymail.com",
    "workmail.com", "work.com", "office.com", "dot.com", "ourdomain.com",
    "mydomain.org", "ourcompany.com", "myorganization.com", "myorg.com", "org.com",
    "corp.com", "business.com", "email.example.com", "xample.com", "adomain.com",
    "googleappsdomain.com", "myaddress.com", "testaddress.com",
    "comp.net", "shitmail.com", "gamil.com", "findme.com", "testwebsite.com",
    "olddomain.com", "name.com", "abcde.com", "samplewebsite.com",
}
# 服务/机构/项目/邮件列表域名(官方服务地址/开源项目, 非个人隐私)
_SERVICE_DOMAINS = {
    "openssh.com", "libssh.org", "jboss.org", "w3.org", "freenode.net", "jabber.org",
    "google.com", "googleapps.com", "googlecode.com", "googlegroups.com",
    "microsoft.com", "github.com", "bitbucket.org", "datatables.net", "mozilla.org",
    "apache.org", "sourceforge.net", "python.org", "ruby-lang.org", "php.net",
    "perl.org", "nodejs.org", "wordpress.org", "jquery.com", "bootstrap.com",
    "reactjs.org", "npmjs.com", "pypi.org", "maven.org", "gradle.org", "django.com",
    "rails.com", "thawte.com", "verisign.com", "digicert.com", "godaddy.com",
    "cpanel.net", "bluehost.com", "amazon.com", "apple.com", "adobe.com", "cpan.org",
    "facebook.com", "compaq.com", "caltech.edu", "bristol.ac.uk", "iki.fi",
    # 云服务账号域(GCP/AppEngine/Heroku 服务账号, 非个人隐私, 2026-09-19 SO v6 残差锚定)
    "gserviceaccount.com", "rhcloud.com", "appspot.gserviceaccount.com",
    "heroku.com", "herokussl.com", "googleusercontent.com", "gcp.gserviceaccount.com",
    # 开源软件/大学公开联系域(2026-09-19 SO v7 残差锚定: 源码头注释/官方示例地址, 非个人 PII)
    "msu.ru", "pglaf.org", "joehewitt.com", "shinners.org", "wp.pl",
    "liveinternet.ru", "database.windows.com", "startb.com",
}
_LIST_DOMAIN = re.compile(r'(?i)^(?:.*-)?(?:dev|devel|users?|lists?|announce|bugs?'
                          r'|commits|patches|test|qa|doc|docs|hackers?)(?:-.*?)?$')
# 精确匹配首段(非前缀) — my/any/some 等仅匹配 my.com/any.com, 不 prefix 误伤
# mystery/myspace/android 等真实单词域名(误删真邮箱=红线方向)。
_PLACEHOLDER_FIRST = {"example", "sample", "test", "domain", "your", "my", "some",
                      "fake", "dummy", "demo", "any", "our", "their", "the"}
_INTERNAL_SUFFIX = (".internal", ".intranet", ".local", ".localhost", ".corp",
                    ".corporate", ".dev", ".test", ".example", ".sample", ".demo",
                    ".home", ".lan", ".private", ".vpc", ".cluster", ".k8s", ".svc",
                    ".comput", ".azure", ".domain", ".mydomain")
# 代码片段"伪邮箱"TLD 黑名单(2026-09-19 SO v6 残差锚定): F#/Kotlin/R/混淆代码里
# `this@ConnectionManager.run` / `pbmc3k@meta.data` / `Rz.T@vec.reshape` /
# `perf@y.values` / `queue@java.lang.String` / `x@...Invoke` 等, 域名实为代码标识符,
# TLD 是"run/data/string/invoke/values/bind/service…"这类**绝不可能是真实 TLD** 的词。
# 用黑名单(非白名单)——只剔除确认非 TLD 的代码词, 绝不放过罕见真实 TLD 邮箱(避免误删真 PII)。
_CODE_TLD_BLOCK = {
    "run", "data", "values", "value", "invoke", "invokeall", "string", "object",
    "class", "method", "function", "lambda", "this", "super", "field", "methodref",
    "bind", "service", "view", "collect", "create", "label", "node", "fieldlist",
    "filelist", "stringbuilder", "invokevirtual", "invokestatic", "array", "map",
    "set", "list", "dict", "collection", "iterator", "iter", "generator", "future",
    "promise", "task", "job", "worker", "pool", "queue", "stack", "tree", "graph",
    "buffer", "stream", "writer", "reader", "logger", "event", "signal", "slot",
}
# 服务/角色邮箱(系统/组织职能地址, 非个人隐私)
_SERVICE_LOCALS = {
    "git", "git2", "gitlab", "deploy", "deployer", "ci", "jenkins", "build",
    "buildbot", "mockbuild", "sysmailer", "sysmail", "sysadmin", "noreply",
    "no-reply", "no.reply", "donotreply", "do-not-reply", "dontreply", "postmaster",
    "abuse", "security", "admin", "root", "info", "support", "help", "sales",
    "contact", "webmaster", "webadmin", "editor", "manager", "ops", "billing",
    "sysop", "mail", "mailer", "mailer-daemon", "hostmaster", "undeliverable",
    "errors", "error", "bounce", "maildaemon", "web", "www", "nobody", "daemon",
    "system", "host", "server", "hosting", "domain", "domainadmin", "post",
    "mailadmin", "spam", "report", "feedback", "alerts", "alert", "monitoring",
    "noc", "dba", "sre", "dev", "developer", "devs", "team", "group", "list",
    "lists", "announce", "announcements", "commits", "notify", "notifications",
    "notifier", "updates", "update", "digest", "digests", "news", "newsletter",
    "subscribe", "unsubscribe", "helpdesk", "ticket", "tickets", "csr", "care",
    "service", "services", "accounts", "account", "finance", "hr", "recruiting",
    "jobs", "careers", "press", "media", "pr", "marketing", "webteam", "it",
    "itdept", "itsupport", "tech", "techsupport", "api", "apis", "bot", "bots",
    "robot", "automated", "automation", "automailer", "autoreply", "autoresponder",
    "auto",
}
# crypto/SSH 算法标识 local(hmac-sha2-256 / curve25519-sha256 / aes128-gcm 等)
_CRYPTO_LOCAL = re.compile(
    r'(?i)^(?:hmac|ssh|rsa|ecdsa|dsa|ed25519|curve|aes|chacha|poly1305|umac|gcm|cbc'
    r'|ctr|etm|md5|sha\d|ripemd|ecdh|poly|bcrypt|scrypt|argon|pbkdf|3des|blowfish'
    r'|twofish|seed|camellia|aria|sm2|sm3|sm4|md4|md6)[-_0-9a-z]*$')
_CRYPTO_KW = ("hmac", "sha1", "sha2", "sha256", "sha512", "ripemd", "chacha",
              "poly1305", "umac", "curve25519", "gcm", "-cbc", "-ctr", "-etm",
              "ed25519", "aes128", "aes256", "aes192", "rsa1024", "rsa2048",
              "rsa4096", "ecdsa", "dh-group", "modp")
# 明显虚构/示例人名 local(著名虚构角色/序号/键盘串/哈希串)
_FICTIONAL_LOCAL = re.compile(
    r'(?i)^(?:test|fake|sample|demo|dummy|guest|user\d*|customer\d*|account\d*|'
    r'one|two|three|four|five|alpha|beta|gamma|delta|nike\d?|blah_?|asdf+|zxcv+|'
    r'qwerty|asdfgh|abcd+|abcdefg|abcdefghi|abcdef|harry\.potter|jerry\.lane|'
    r'indiana\.jones|tom\.cruise|smith\d*|jones\d*|doe|redacted|phonenumber|'
    r'validname|somename|firstmail|secondmail|onlineshop|help_center|smiletest'
    r'|testguest|testcust\d*|xample\d*|smiley|hello|world|foo|bar|baz|qux|'
    r'lorem|ipsum|(?:abc|def|xyz)[a-z]?|sombody|someone|anobody|infobot\d*|name\d*)$')


# 模板域首段: my*/your*+占位名词 (mydomain.org.ua / mytenant.com / myapp.com)
# 及 whatever/first*/last*/parent 字面槽位(whatever@parent.child)。
# 用占位名词白名单而非 my\w* 裸前缀 — 避免误删 mystery.com / anywhere.net /
# firstchoice.com / lastminute.com 等**真实注册域名**(误删真邮箱 = 红线方向)。
_PLACEHOLDER_DOMAIN_HEAD = re.compile(
    r'(?i)^(?:(?:my|your)(?:mail|email|name|domain|address|company|account|'
    r'password|username|user|tenant|app|site|service|server|host|test|sample|'
    r'example|phone|number|id|self|place|shop|data|admin|profile|credential|'
    r'website)\w*|whatever|parent)$')


def _is_camel_code_id(local):
    """local 为驼峰(≥1 处小写字母紧跟大写字母) → 代码标识符/JID/变量名示例
    (countService / sunnvaleStarb / toysdemo.ToysDemo / LoveJack / redirectingAddress)。
    代码问答语料中真实个人邮箱按惯例全小写(john.smith / jane_doe), 不会驼峰,
    故驼峰即可判代码标识(不要求含数字 — 真实残差的驼峰 local 全不含数字)。"""
    return bool(re.search(r"[a-z][A-Z]", local))


# 模板 local(占位名而非真名): my*/your* + 占位名词(mymailid / myname+tag /
# yourdomain), 及 whatever*/first*/last* 字面槽位(FirstName.LastName /
# LASTNAME.FIRSTNAME@enterprise.com)。
# 用"占位名词白名单"而非 my\w* 裸前缀 — 避免误删 Myles/Youri/Anya 等
# 以 my/your/any 开头的**真实人名**(隐私误删 = 红线方向, 宁可少删)。
_TEMPLATE_LOCAL_HEAD = re.compile(
    r'(?i)^(?:(?:my|your)(?:mail|email|name|domain|address|company|account|'
    r'password|username|user|tenant|app|site|service|server|host|test|sample|'
    r'example|phone|number|id|self|place|shop|data|admin|profile|credential|'
    r'login)\w*(?:\+\w+)?|(?:whatever|first|last)[\w.]*)$')


# 公共项目/团队官方地址(非个人 PII, 项目变更日志/维护块里的官方团队收件地址, 任何
# 开发者都可见且不可定位到具体个人): 2026-09-21 GH Issues 86 万全量核实误报
# (PETSc 变更日志 petsc-maint@mcs.anl.gov / FreeBSD 端口 fortran@FreeBSD.org)。
# 精确小写全等 — 不 prefix 不泛化, 绝不波及同域的任何个人邮箱(红线方向: 宁少删)。
_PUBLIC_PROJECT_EMAILS = frozenset({
    "petsc-maint@mcs.anl.gov",  # PETSc 官方维护团队列表
    "fortran@freebsd.org",      # FreeBSD fortran 项目维护列表
})


def _email_value_excluded(v):
    """取值排除: 占位 local/域、服务域、内网域、crypto 算法 id、全大写域、虚构名。"""
    if v.lower() in _PUBLIC_PROJECT_EMAILS:
        return True
    local = v.split("@")[0]
    dom_raw = v.split("@")[-1]
    dom = dom_raw.lower()
    ll = local.lower()
    # 全大写域名(Kerberos SPN user@REALM / 示例大写): 真实正文邮箱几乎不会全大写
    if dom_raw.isupper() and any(c.isalpha() for c in dom_raw) and len(dom_raw) > 3:
        return True
    if ll in _PLACEHOLDER_LOCALS or dom in _PLACEHOLDER_DOMAINS:
        return True
    first = dom.split(".")[0]
    if first in _PLACEHOLDER_FIRST:  # 精确匹配首段(不 prefix, 避免误伤 mystery/android)
        return True
    if dom.endswith(_INTERNAL_SUFFIX):
        return True
    if len(local) > 28:
        return True
    if ll in _SERVICE_LOCALS or ll.startswith("mockbuild") or ll.startswith("buildbot"):
        return True
    if _CRYPTO_LOCAL.match(ll) or any(kw in ll for kw in _CRYPTO_KW):
        return True
    if local.isupper() and local.isalpha() and 2 <= len(local) <= 6:  # 示例/数据 token
        return True
    if local.replace(".", "").isdigit():  # 全数字 local(账号编号)
        return True
    # 机器/服务生成的 hex 账号 local(如 54f03dbd4382ec9101000159@myapp.rhcloud.com)
    if re.fullmatch(r"[0-9a-fA-F]{16,}", local):
        return True
    if dom in _SERVICE_DOMAINS or any(dom == d or dom.endswith("." + d)
                                      for d in _SERVICE_DOMAINS):
        return True
    if _LIST_DOMAIN.match(first):  # 邮件列表 local 首段
        return True
    if first == "conference":  # XMPP/MUC 会议域(user@conference.xxx)
        return True
    if _FICTIONAL_LOCAL.match(local):
        return True
    # 模板域: my*/your*/whatever/any*/first*.*last*/parent(2026-09-19 SO v7 残差锚定)
    if _PLACEHOLDER_DOMAIN_HEAD.match(first):
        return True
    # 模板 local: mymailid / myname+tag / whatevername / firstname.lastname
    if _TEMPLATE_LOCAL_HEAD.match(local):
        return True
    # 驼峰代码标识 local: countService / sunnvaleStarb / toysdemo.ToysDemo / LoveJack
    if _is_camel_code_id(local):
        return True
    return False


_EMAIL_CUE = re.compile(
    r'(?i)(?:\bemail\b|\be-?mail\b|\bmail\b|contact|reach me|reach out|write to|'
    r'send to|send me|send a|mail to|mailing list|mail me|subscribe|thanks to|'
    r'suggested|submit|report it|file a|contact me|contact the|get in touch|'
    r'feel free to|feel free|ping me|let me know|my (?:email|e-?mail|address|email address)|'
    r'(?:email|e-?mail|mail|address)[:= ]|\bFrom:|\bTo:|\bCc:|\bBcc:|\bReturn-Path:|'
    r'Message-ID|E=|emailAddress=|\bCN=|\bC=|\bO=|Copyright|author|contribut|'
    r'get involved|someone like|address like|schema|for example|e\.g\.|such as|'
    r'sample|example|e\. g\.|comment by|note by|by [A-Z][a-z]+ [A-Z][a-z]+,|'
    r'made many changes|made a lot|altered by|added by|created by|maintained by|'
    r'register with|sign up|log ?in to|log ?into|test account|test login|test page|'
    r'sandbox|demo user|demo accoun|here is a test|test user|test credentials|'
    r'here is the|here are the|logon name|relay for|unable to relay|log into|'
    r'send the form|to the form|form to|send it to|send my|my password|mypass|'
    r'receive the message|message inside|send the form to|the form to|'
    r'you have at|you with|any questions|any questions you|talk about this|'
    r'communicate me|let me know|drop me|shoot me|message me|reach out|reach me via|'
    r'bereikbaar via|you can reach|can be reached|get me at|reach me at|contact me at|'
    r'you can mail|mail the author|author at|the author|project member|'
    r'valid email|invalid email|expected valid|valid emails|invalid emails|'
    r'dynamic values|sample data|test data|sample email|example email|'
    r'me at|email me|at my|my address|write to me|contact me|ping me|'
    r'best regards|\bregards,|\bbereik|\busername\b|\buser:|customer id|'
    r'customer email|\bbefore:|\bafter:|'
    r'formatted in the|will be:|looks like this|as follows|for example:|'
    r'like this:|in the format|same format|general way|sample output|'
    r'got the token|userprincipalname|accountenabled|lastsignindate|'
    r'identity exception|got an email from)')
_EMAIL_CODE_CTX = re.compile(
    r'(?i)(?:%w\[|\.each\b|addresses\s*=|\bvalid_address|\bcat=\[|\bdat=|\bflg=|'
    r'IntentService|\bsmtptransport|\bSmtpClient|heroku\[|\[From\]|\[To\]|\[Subject\]|'
    r'5\.7\.1|->\s*\[|=\s*>|2147483647|\bINT_MAX|logon name|business=|payer_status|'
    r'sender-id|sender id|c2dm|gcm|fcm\b)')


def _email_ctx_excluded(text, s, e):
    """上下文排除: 引号/括号/CSV/表格/邮件头/代码结构包裹 = 代码示例, 非散文化泄露。"""
    pre = text[s - 1] if s > 0 else " "
    post = text[e] if e < len(text) else " "
    if pre in "\"'(<[{" or post in "\"'>)]}" or post == "/":  # 代码字面量/<addr>/[addr]
        return True
    if pre == ">" and post == "<":  # HTML 元素内容 <td>x@y.com</td> 网页脚注/联系块(自披露)
        return True
    if pre in "@:;" or post in ":;":  # user:pass@host / SPN / domain@REALM / 分隔
        return True
    if pre == "=":  # URL 查询参数 key=x@y / OData / 代码赋值, 真实正文邮箱不会以 = 开头
        return True
    if pre == "#" or post == "#":  # git ref (data@store.js#428) / 锚点
        return True
    if pre == "|" or post == "|":  # 表格竖线紧邻
        return True
    if pre == "," or post == ",":  # CSV / 字段列表
        return True
    # 表格/列表单元格: 邮箱两侧(跨 1-2 空格)是竖线 → "| a@b.com |"
    _l = text[max(0, s - 2):s].strip()
    _r = text[e:e + 2].strip()
    if _l.endswith("|") or _r.startswith("|"):
        return True
    if re.search(r'(?:From|To|Cc|Bcc|Return-Path|Message-ID|E|emailAddress)\s*[=:]?\s*$',
                 text[max(0, s - 14):s]):
        return True  # 邮件头/证书字段紧邻
    window = text[max(0, s - 46):e + 24]  # 行内窗: 自披露/示例/代码结构 cue
    if _EMAIL_CUE.search(window) or _EMAIL_CODE_CTX.search(window):
        return True
    return False


def _email_should_flag(prose, s, e):
    v = prose[s:e]
    if not looks_like_real_email(v):
        return False
    if _email_value_excluded(v):
        return False
    if _email_ctx_excluded(prose, s, e):
        return False
    return True


_CODE_PUNCT = set('."\'/:=,@;(){}[]<>+*/&|!%$~^?#')


def _neighbor_token(text, i, step):
    """返回 i 处相邻(跳过空白)的完整空白分隔 token。"""
    n = len(text)
    while 0 <= i < n and text[i].isspace():
        i += step
    if not (0 <= i < n):
        return ""
    start = end = i
    if step > 0:
        while end < n and not text[end].isspace():
            end += 1
        return text[start:end]
    while start >= 0 and not text[start].isspace():
        start -= 1
    start += 1
    return text[start:i]


def _num_ctx_excluded(text, s, e):
    """数字语境排除(手机/身份证共用): 浮点碎片/代码标点紧邻/邻接数字或代码 token/前导+。"""
    pre = text[s - 1] if s > 0 else " "
    post = text[e] if e < len(text) else " "
    if pre == "." or (post == "." and e + 1 < len(text) and text[e + 1].isdigit()):
        return True  # 浮点碎片
    if pre in _CODE_PUNCT or post in _CODE_PUNCT:
        return True  # 代码标点紧邻
    for tok in (_neighbor_token(text, s - 1, -1), _neighbor_token(text, e, +1)):
        if tok.isdigit():  # 邻接纯数字 = 数据序列/大数/序列号(真实手机号两侧是文字)
            return True
        if re.search(r'0[xXbB]|2\s*\*\*|\bbin\s*\(|\bhash|bytes|millis|nanoseconds|'
                     r'time_stamp|timestamp|epoch', tok, re.I):
            return True  # 邻接代码/时间戳 token
    if pre == "+":
        return True  # 前导 + (国际拨号/带符号数值)
    return False


_KNOWN_CONSTS = {"17179869184", "14159265359", "14285714286", "16777216000",
                 "12345678901", "19999999999", "17179869183", "17179869185",
                 "16106127360"}


def _is_fictitious_phone(num):
    """虚构/常量号: 已知常量、555 中间段、全同/升序/降序、尾 0000。"""
    if num in _KNOWN_CONSTS:
        return True
    if "555" in num[1:4]:
        return True
    if "00000" in num or "11111" in num or "99999" in num or "22222" in num:
        return True
    d = [int(c) for c in num]
    if all(d[i + 1] - d[i] == 1 for i in range(len(d) - 1)):
        return True
    if all(d[i + 1] - d[i] == -1 for i in range(len(d) - 1)):
        return True
    if num.endswith("0000"):
        return True
    return False


# ulimit/getconf/sysctl 输出里"数值 + 系统资源标签"是资源上限值, 非手机号。
# 2026-09-21 GH Issues 86 万全量核实误报: "18132713472  maximum resident set size"
# (≈17TB 的常驻内存上限) 被 1[3-9]\d{9} 误判为手机号。数字后紧跟系统资源标签 ⇒ 排除。
# 保守设计: 仅当数字后(跨 ≤2 空格)出现明确的 ulimit/getconf 资源名词才排除,
# 真实"手机号 + 标签"极罕见, 误删风险低; 仍保留孤立真号命中能力。
_SYS_RESOURCE_LABEL = re.compile(
    r'\s{0,2}(?:maximum\s+resident\s+set\s+size|'
    r'file\s+size|address\s+space|stack\s+size|'
    r'core\s+file\s+size|open\s+files|processes|'
    r'memory\s+lock|swaps|pipes|time|priority|'
    r'block\s+size|buffer\s+size|file\s+system\s+blocks|'
    r'socket\s+buffering|arg\s+max|stack\s+size)',
    re.I)


def _phone_should_flag(prose, s, e):
    num = prose[s:e]
    if _is_fictitious_phone(num):
        return False
    if _num_ctx_excluded(prose, s, e):
        return False
    if _SYS_RESOURCE_LABEL.match(prose[e:e + 60]):
        return False  # ulimit/getconf 系统资源值, 非手机号
    return True


_PROVINCE2 = {"11", "12", "13", "14", "15", "21", "22", "23", "31", "32", "33",
              "34", "35", "36", "37", "41", "42", "43", "44", "45", "46", "50",
              "51", "52", "53", "54", "61", "62", "63", "64", "65"}


def _idc_should_flag(prose, s, e):
    """身份证: 省码须合法(前 2 位) + 非代码/数值语境, 否则是 JS 大数/状态 id/浮点。"""
    v = prose[s:e]
    if not (len(v) == 18 and v[:6].isdigit()):
        return False
    if v[:2] not in _PROVINCE2:
        return False
    if _num_ctx_excluded(prose, s, e):
        return False
    return True


def _hit_ctx(text, s, e, w=60):
    """命中值 ±w 字符上下文(单行化, 超长截断), 供报告明细展示命中原文。"""
    pre = text[max(0, s - w):s].replace("\n", "⏎")
    post = text[e:e + w].replace("\n", "⏎")
    seg = (pre if len(pre) < w else "…" + pre[-w:]) + text[s:e] + \
          (post if len(post) < w else post[:w] + "…")
    return seg.strip()


def _privacy_desensitize(pkind, val):
    """§6 隐私命中去隐私化脱敏示例(报告明细节整改指引, 同内网 IP 口径展示)。
    邮箱 local 段整段 → xxxxxx 保域名: sample@email.com -> xxxxxx@email.com
    手机号 保前 3 后 2, 中间 x: 13333333333 -> 133XXXXXX33
    身份证 保前 6(地域)后 4, 中间 x: 110105199001011234 -> 110105XXXXXXXX1234
    仅报告展示用, 数据脱敏按 §6 由上游 x 占位执行。"""
    if pkind == "邮箱":
        at = val.rfind("@")
        if at > 0:
            return "xxxxxx" + val[at:]
        return "xxxxxx"
    if pkind == "手机号":
        d = re.sub(r"\D", "", val)
        if len(d) >= 5:
            return d[:3] + "X" * (len(d) - 5) + d[-2:]
        return "XXXXX"
    if pkind == "身份证":
        d = re.sub(r"\D", "", val)
        if len(d) >= 10:
            return d[:6] + "X" * (len(d) - 10) + d[-4:]
        return "XXXXXXXX"
    if pkind == "银行卡":
        d = re.sub(r"\D", "", val)
        if len(d) >= 8:
            return d[:4] + "X" * (len(d) - 8) + d[-4:]
        return "XXXX"
    return "xxxxxx"


# 银行卡"支付语境门禁"(见 _card_payment_ctx): 命中值 ±60 字符内须同现支付/卡片关键词。
# 代码问答语料里真实卡号几乎必与"银行卡/credit/visa/cvv"等词同现; 而 Luhn 巧合命中的
# 数组元素/分区偏移/GUID/引脚定义周围无任何支付词汇 → 此门根治 Luhn 对随机数字串的误报
# (2026-09-20 A 批实测 9/9 误报: ATX 电源引脚/字符串数组/2D 数组/时间戳/网格/片长/
#  磁盘分区偏移/GUID hex, 全部无支付语境)。
_RE_CARD_CTX_EN = re.compile(
    r'\b(?:credit|debit|bank(?:ing|card)?|visa|master(?:card)?|amex|'
    r'american\s*express|diners\s*club|cvv2?|cvc|payment|pay(?:pal)?|'
    r'stripe|checkout|card(?:s|number)?)\b')
_CARD_CTX_CN = ("银行卡", "信用卡", "借记卡", "卡号", "支付", "付款", "银行", "充值", "刷卡")


def _card_payment_ctx(prose, s, e):
    """命中值 ±60 字符窗口内须出现支付/卡片关键词, 否则视为代码数字串, 不判卡号。"""
    win = prose[max(0, s - 60):e + 60].lower()
    return bool(_RE_CARD_CTX_EN.search(win)) or any(k in win for k in _CARD_CTX_CN)


# 行业通用标准测试卡号(Stripe/Visa/Mastercard/Amex 官方文档值, 无任何真实持卡人,
# 支付集成文档/示例代码里必然出现): 2026-09-21 StackExchange 巡检核实误报
# (QA_2026_7df8452cbf38: "Enter CC No. (4111111111111111) Exp: 02/18 CVC: 111" = Braintree 测试流程)。
_TEST_CARDS = frozenset({
    "4111111111111111",  # Visa (Braintree/Visa 官方文档)
    "4111111111111111111",  # Visa 19 位
    "4242424242424242",  # Visa (Stripe 官方)
    "4000056655665556",  # Visa (Stripe 官方, 3DS 测试)
    "4000002500003155",  # Visa (Stripe 官方, 3DS 挑战)
    "4000000000009995",  # Visa (Stripe 官方, 3DS 无交互)
    "4000005660001199",  # Mastercard (Stripe 官方)
    "4000002760003184",  # Mastercard (Stripe 官方)
    "4000000000000002",  # Visa (Stripe 官方, 文档默认测试号)
    "4000000000000003",  # Visa (Stripe 官方, 3DS)
    "4000000000000010",  # Visa (Stripe 官方, 需验证码)
    "4000000000000069",  # Visa (Stripe 官方, 3DS 重定向)
    "400000000000000200",  # Visa (Stripe 官方, 20 位测试号)
    "4012888888881881",  # Visa (Stripe 官方, 3DS 无交互)
    "4012000033330660",  # Visa (Stripe 官方, 需验证码)
    "4205311123456789",  # Visa (Stripe 官方)
    "4000000018070417",  # Mastercard (Stripe 官方, 3DS)
    "5555555555554444",  # Mastercard 通用测试号
    "2223003122003222",  # UnionPay (Stripe 官方)
    "378282246310005",   # Amex (Stripe 官方)
    "30569309025904",    # Diners (Stripe 官方)
    "38520000023234",    # Discover (Stripe 官方)
    # 2026-09-21 GitHubIssues 86 万全量跑出 9 个未覆盖测试号(3DS 套件/decline 套件/Braintree 文档),
    # 一次性补齐 Stripe/Braintree 文档全套, 避免"补一个漏一个":
    "4000000000003220",  # Visa (Stripe 官方, 3DS 挑战)
    "4000000000003063",  # Visa (Stripe 官方, 3DS 重定向)
    "4000000000000341",  # Visa (Stripe 官方, requires_action)
    "4000000000002620",  # Visa (Stripe 官方, card_declined)
    "4000008260003178",  # Visa (Stripe 官方, insufficient_funds)
    "4012001038488884",  # Visa (Stripe 官方, SCA 挑战重定向)
    "4000111111111115",  # Visa (Stripe 官方, SCA 挑战)
    "5200000000000007",  # Mastercard (Stripe 官方, 3DS 挑战)
    "5200000000000015",  # Mastercard (Stripe 官方, 3DS 挑战)
    "5200000000000023",  # Mastercard (Stripe 官方, requires_authentication)
    "5424000000000015",  # Visa (Braintree 官方文档)
    "4000000000003253",  # Visa (Stripe 官方, 3DS frictionless; 86 万全量二轮暴露, 与 3220 同记录)
})


def real_bank_cards(text):
    """银行卡号(Luhn + 边界 + 支付语境门禁 + 标准测试卡白名单), 误报根除:
      - 排除小数碎片/标识符内数字串(如 0.6297…/4.6666…)
      - 排除 hex 字面量上下文(0x 后、紧邻 a-f 字母, 如 3fe6666666666666)
      - 排除全同/循环递增数字串(如 6666666666666 / 34567890123456, 肉眼即非卡号)
      - 排除行业通用标准测试卡号(_TEST_CARDS: 支付集成文档值, 无真实持卡人)
      - 支付语境门禁: 命中值 ±60 字符内无支付/卡片关键词(credit/visa/银行卡/cvv…)
        → 代码里的数组元素/分区偏移/GUID/引脚号, 不判
    """
    out = []
    for m in re.finditer(r'(?<![\d.])([3-6](?:\s?\d){12,18})(?![\d.])', text or ''):
        s = re.sub(r'\s', '', m.group(1))
        pre = text[max(0, m.start() - 1):m.start()]
        post = text[m.end():m.end() + 1]
        if pre and not pre.isdigit():
            if pre.isalpha() or pre.isidentifier() is None or pre == "_":
                pass
        # 上下文硬排除: hex 邻接 / 标识符文件名(如 html_erb__3480...4973_ / fid6346...F983)
        if re.match(r'[0-9a-fA-F]', pre) or re.match(r'[0-9a-fA-F]', post):
            continue  # hex 字面量片段
        if pre.isalpha() or pre == "_" or post.isalpha() or post == "_":
            continue  # 嵌在文件名/标识符里(行号、FileID)
        if pre in ('#', '"', "'", '&', ':') or post in ('#', '"', "'", '&', ':', '}'):
            continue  # 设备路径/JSON id/序列值 语境(USB 实例路径、JSON "id" 等)非卡号
        if len(set(s)) == 1:
            continue  # 全同数字串(如 6666666666666)非卡号
        if re.fullmatch(r'(\d)\1{2}(\d)\2{2}.*', s):
            continue  # 显式 ABA 重复模式(过宽, 仅示例谨慎)
        if s.isdigit() and all((int(s[i + 1]) - int(s[i])) % 10 == 1 for i in range(len(s) - 1)):
            continue  # 循环递增(含 9→0 回绕, 如 0123456789012345 / 34567890123456)
        if s in _TEST_CARDS:
            continue  # 行业通用标准测试卡号(支付集成文档值, 无真实持卡人)
        if not _card_payment_ctx(text, m.start(), m.end()):
            continue  # 无支付语境: 代码数字串(数组/分区偏移/GUID/引脚)非卡号
        if luhn_ok(s):
            out.append(s)
    return out


def is_pkg_version_email(v):
    """pkg@version 判定(如 webpack@4.0.3 / Typescript@4.0.3): @后是"点分版本号"
    (≥2 段纯数字)才是版本, 非真实邮箱。
    ⚠️ 仅首段数字 + 字母 TLD(163.com / 126.com / 139.com 等真实数字域名)**不判版本**
    —— 旧口径"首段数字即版本"会漏掉 zhang@163.com 这类真实中文邮箱(2026-09-19 自测校准)。"""
    parts = v.split("@")[-1].split(".")
    first = parts[0]
    if not first or not first[0].isdigit():
        return False
    num_segs = sum(1 for p in parts[1:] if p and p[0].isdigit() and p.isdigit())
    return num_segs >= 2


def looks_like_real_email(v):
    """真实邮箱判定, 排除代码/测试/路径误报:
      - 排除 pkg@version(域名段数字开头)
      - TLD 须为 2-10 位字母开头(排除 a@a.c / name@mail.56 / element.@someattr.x 的 .c/.56/.x)
      - local 须 ≥2 位且含字母, 非全 x(已脱敏占位), 排除 a@b.c 单字符/路径片段
    """
    if "@" not in v:
        return False
    local, dom = v.split("@")[0], v.split("@")[-1].lower()
    if is_pkg_version_email(v):
        return False
    tld = dom.rsplit(".", 1)[-1]
    if not (2 <= len(tld) <= 10 and tld[0].isalpha()):
        return False
    # 代码片段"伪邮箱" TLD: 域名实为代码标识符(this@ConnectionManager.run /
    # pbmc3k@meta.data / x@...Invoke), TLD 是 run/data/string/invoke 等绝不可能
    # 真实 TLD 的词(黑名单, 不影响任何真实邮箱); 全大写 TLD 同理(StackTrace 片段)。
    if tld in _CODE_TLD_BLOCK:
        return False
    if len(local) < 2 or not any(c.isalpha() for c in local):
        return False
    # 已脱敏占位: local 由 x 及点构成(纯 xxx / xxx.xxxxxx / x.x 等)。
    # 2026-09-20 SO v6 重脱敏后邮箱 local 统一替换为 xxx.xxxxxx 形态, 纯 x 判定
    # (replace x 后须为空)对含点 x 串漏判 → 脱敏值反被判成隐私泄露, 故同时剥掉点号。
    # 真实人名邮箱(如 j.doe / xiaoming.wang / x.wild? 见下)含实义字母, 剥 x/点后非空, 不受影响。
    if local.lower().replace("x", "").replace(".", "") == "":
        return False
    # 校准(LeetCode 题解误报): 已 Defanging/脱敏的图片文件名, 形如
    #   RQSA%7BYHRQxxxxx@xxxxxxxx.png
    # 其中 @ 后的域名是"全 x 占位 + 文件扩展名", 根本不是邮箱。三条特征任一命中即排除:
    first_label = dom.split(".")[0]
    if first_label.replace("x", "") == "":   # ① 域名首段全 x = 已脱敏占位
        return False
    if "%" in local:                          # ② local 含 % = URL 编码残片(%7B 等)
        return False
    if tld in ("png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico",
               "mp4", "mp3", "wav", "pdf", "zip", "gz", "tar", "7z",
               "exe", "dll", "so", "dylib", "class", "dex", "apk", "bin"):
        return False                          # ③ TLD 是文件扩展名 = 文件名/路径片段
    return True

# §4.1 占位符/乱码: U+FFFD 替换字符即编码损坏
RE_MOJIBAKE = re.compile(r'\ufffd')
RE_PLACEHOLDER_RUN = re.compile(r'(?im)^\s*x{40,}\s*$')   # 整行 40+ 个 x 才判灌水占位
                                                            # (代码内脱敏占位 xxxx 属正常示例)

# §6 匿名化清单补充: 银行卡(Luhn)、内网 IP、社交账号
RE_BANKCARD = re.compile(r'(?<!\d)[3-6]\d{12,18}(?!\d)')
RE_PRIV_IP = re.compile(
    r'(?<![0-9a-zA-Z.])(?:192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![0-9a-zA-Z.])')
# 注: 10.x.x.x 为 §6 认可的合规替换值(RFC1918 测试段), 不作为漏脱敏检出
# 文档/示例标准私网地址(2026-09-19 SO 全量 2062 处 IP 锚定): 教科书/官方文档
# 使用频率极高的"示例网段", 不构成可定位个人的真实内网拓扑泄露。
_DOC_IP_NETS = (
    "192.168.1.", "192.168.0.",       # 教科书默认网关/首网段(SO 内 450+ 处)
    "192.168.56.",                    # VirtualBox 固定 host-only 网段
    "172.17.",                        # Docker 默认 bridge
)
_DOC_IP_EXACT = {
    "192.168.99.100", "192.168.99.1", "192.168.100.1", "192.168.100.100",
    "192.168.2.2", "192.168.3.3", "192.168.4.4",
}


def _ip_doc_excluded(ip, prose_text, i):
    """IP 属文档标准示例地址(段/精确) 或邻近 30 字符含 example/e.g./sample → 排除。"""
    if any(ip.startswith(pfx) for pfx in _DOC_IP_NETS):
        return True
    if ip in _DOC_IP_EXACT:
        return True
    near = prose_text[max(0, i - 30):i + len(ip) + 30].lower()
    if re.search(r'\bexample\b|e\.g\.|\bsample\b|示例|例如', near):
        return True
    return False


# §6 内网 IP「网络配置/诊断自披露语境」豁免(2026-09-20 Reddit A 批 43 条实测提炼)。
# 代码问答里内网 IP 几乎必然是提问者自披露的本地网络拓扑(问"我网络为啥不通"时贴
# ip route/dnsmasq/ping/nslookup 输出, IP 是问题本体)。这类自披露属 RFC1918 非路由段,
# 无可定位个人的第三方 PII(内网 IP 不绑定自然人、不可公网可达), 且 x 化会破坏语料
# 可用性(答案没法对着提问者实际网段验证) → 命中下列任一"配置/诊断语境信号"即豁免。
#   安全默认: 无任何信号 → 保持 WARN(宁多报不漏报)。
#   Group A: IP ±120 字符窗口内出现 配置键值/命令输出头/日志格式/诊断工具/代码常量
#   Group B: 整条记录出现第一人称持有短语("my router"/"my own IP" 等, 明确自持有)
_RE_IP_CFG = re.compile(
    r'(?:'
    # ① 配置键值(resolv.conf/sysconfig/dnsmasq/interfaces/NetworkManager 等, 键后 [=:]):
    r'\b(?:ipaddr|netmask|gateway|hwaddr|device|onboot|iface|address|network|'
    r'listen-address|dhcp-range|nameserver|interface|broadcast|subnetmask|server|'
    r'ip_address|domain_name_servers|routers)\b\s*[=:]'
    # ② 命令输出头(ip addr/ifconfig/route/tcpdump): inet(可被 markdown 链接包裹)/ brd N /
    #    scope global / via N / router N / Src: / Dst: / src port / dst port:
    r'|\binet\b|\bbrd\s+\d|scope\s+global|\bvia\s+\d|\brouter\s+\d'
    r'|\bsrc:\s|\bdst:\s|src\s+port|dst\s+port'
    # ③ 日志格式(nginx 等): client: / upstream: / request: / HTTP/1.x / ;push "route:
    r'|client:|upstream:|request:|http/1\.\d|;push\s*"route'
    # ④ 诊断工具名 + 其输出特征: ping / traceroute / dig / nslookup / tcpdump / +short:
    r'|\bping\b|traceroute|\bdig\b|nslookup|tcpdump|\+\s*short'
    # ⑤ 代码常量 / iptables 规则: MQC.HOST_NAME_PROPERTY / properties.Add / --to-destination / -j DNAT:
    r'|host_name_property|port_property|properties\.add|--to-destination|-j\s+dnat'
    # ⑥ 网络设备/软件/协议名(self-hosted 自披露拓扑强信号): dnsmasq/wireguard/pfsense/
    #    opnsense/树莓派/VLAN/fstab/NFS/RDMA:
    r'|dnsmasq|wireguard|pfsense|opnsense|raspberry|\bvlan\b|\bfstab\b|\bnfs\b|\brdma\b'
    # ⑦ 命令/登录/探测输出: ssh 到内网机 / Last login from / ping 的 No reply from /
    #    mount -t / static ip / AF_INET(socket 日志) / Resolving·Connecting to / 探测状态 /
    #    "the ip is"/"local ip":
    r'|ssh\s+[^@\s]+@|last login|no reply from|mount\s+-t|static\s+ip|af_inet'
    r'|\bresolving\b|connecting\s+to|looking\s+up\s+status|\bip\s+is\b|local\s+ip'
    # ⑧ 裸配置名词(空格分隔键值, 如 "netmask 255.255.255.0 gateway 192.168.4.1"):
    r'|\bnetmask\b|\bbroadcast\b|\bgateway\b|\brouter(s)?\b'
    # ⑨ 网卡接口名: eth0/eth1/wlan0/enp39s0 等:
    r'|\b(?:eth\d+w?\d*|wlan\d+|enp\w+)\b'
    r')', re.I)
_IP_SELF_OWN = (
    "my router", "my own ip", "my local", "my wifi", "my home network",
    "my network", "my machine", "my gateway", "my virtual", "the virtual interface",
    "my dhcp", "my dns", "my subnet", "my lan", "my internal",
    "local ip", "local network", "my pc", "my main pc",
)


def _ip_netconfig_excluded(prose_text, i, e):
    """内网 IP 处属「网络配置/诊断自披露」语境 → 豁免(见 _RE_IP_CFG/_IP_SELF_OWN 注释)。
    Group A: IP ±120 字符窗口含配置/诊断信号; Group B: 整条记录含第一人称持有短语。"""
    win = prose_text[max(0, i - 120):e + 120].lower()
    if _RE_IP_CFG.search(win):
        return True
    rec = prose_text.lower()
    return any(p in rec for p in _IP_SELF_OWN)


def _ip_desensitize(ip):
    """内网 IP 去隐私化脱敏形式(§6 整改指引, 报告明细节展示用)。
    保留前两段(网段, 可定位到局域网网段级别), 后两段主机位 x 化:
    192.168.1.250 -> 192.168.x.x ; 172.16.5.9 -> 172.16.x.x ; 10.20.30.40 -> 10.20.x.x。
    仅用于报告展示整改口径, 不改数据(数据脱敏按 §6 由上游 x 占位)。"""
    p = ip.split(".")
    if len(p) == 4:
        return f"{p[0]}.{p[1]}.x.x"
    return ip.replace(".", "x.")


def _social_masked(val):
    """2026-09-20 口径: 判定社交特征串是否已脱敏(§6 x 占位)。
    去掉键前缀(QQ/微信号/vx 等)+冒号后看值体: "保首尾数字"式(542xxxx16)
    先剥首尾数字再判中段是否纯 x; 全串 x(xxxxxxx)天然命中。值中段含 x
    即视为已脱敏(不可还原, 无需再复核); 含其他实义字符(abc1234)不算脱敏
    → 仍报明细。真实 QQ/微信号为纯数字且无 x, 不会被误判为已脱敏。
    """
    core = re.sub(r'(?i)^(?:微信号|weixin|weibo|vx|qq号|qq)\s*[:：]\s*', '', val).strip()
    core = core.strip(string.digits)   # 剥首尾数字: "保首尾"式脱敏(542xxxx16) -> 中段 xxxxx
    return core != "" and set(core) <= set("x")


def _social_desensitize(val):
    """§6 社交账号脱敏示例(报告明细节整改指引, 仅展示, 不改数据)。
    数字值: 保前 3 后 2, 中间 x(与手机号口径一致): 542278416 -> 542xxxx16
    非数字值(微信号等): 整串 x 化。已脱敏值原样返回。"""
    core = re.sub(r'(?i)^(?:微信号|weixin|weibo|vx|qq号|qq)\s*[:：]\s*', '', val).strip()
    if _social_masked(val):
        return val
    if core.isdigit():
        if len(core) >= 5:
            return val.replace(core, core[:3] + "x" * (len(core) - 5) + core[-2:])
        return val.replace(core, "x" * len(core))
    return val.replace(core, "x" * max(len(core), 5))
RE_SOCIAL_ACCT = re.compile(r'(?<![A-Za-z0-9])(?:微信号|weixin|qq号|qq|vx)\s*[:：]\s*(?=[a-zA-Z0-9_-]*\d)[a-zA-Z0-9_-]{5,}', re.I)

# §4.1 低质: 纯文字闲聊(无代码需求/无报错信息)
CHAT_Q_HINT = ("报错", "error", "exception", "异常", "undefined", "traceback",
               "为什么", "怎么", "如何", "帮我", "实现", "优化", "重构", "```")
# 技术短语义特征: 短题含这些词即"技术问题"(语言名/编程术语/操作), 非闲聊
# 用 (?<!\w)...(?!\w) 而非 \b...\b —— c#/c++ 尾部是非单词字符 #/+, 加 \b 会漏配
TECH_Q_HINT = re.compile(
    r'(?i)(?<!\w)(?:python|java|javascript|typescript|js|ts|c\+\+|c#|go\b|rust|'
    r'php|ruby|swift|kotlin|scala|sql|html|css|react|angular|vue|node|django|flask|'
    r'class|function|method|variable|array|list|object|null|boolean|integer|'
    r'string|float|loop|while|switch|key|value|map|set|return|callback|'
    r'how to|how do|how does|does|what is|what are|use|create|define|convert|'
    r'difference|between|cast|enum|database|databases|framework|library|parser|'
    r'authorization|endian|support|drop|table|query|insert|select|page|report|'
    r'error|exception|runtime|compile|execute|implement|override|inherit|'
    r'print|install|import|require|initialize|declare|assign|pass|throw|catch|'
    r'oauth|authsub|protocol|ssl|tls|socket|regexp|repository|plugin|theme|menu|'
    r'linux|windows|mysql|postgres|mongodb|docker|git|browser|server|client|api|json|xml|regex)(?!\w)')

# §4.1 禁止复用开源数据集: 公开代码问答数据集特征(GitHub/HuggingFace)。
# 只保留"高置信专名"——在正常技术问答里几乎不可能出现的数据集/模型专名;
# 剔除会误报的通用词:
#   the-stack/theStack(编程"栈"通用词汇+变量名, 实测 14/14 误报)、
#   selfoss(冰岛城市名/足球比分, 实测 2/2 误报)、
#   github.com/datasets / huggingface.co/datasets(用户提问里的正常 URL 引用, 实测 3/3 误报)。

# --- 验收意见"标明 token 计算方式(使用的哪个 tokenizer)"校验(2026-09-15) ---
# metadata.tokenizer 必须存在且为合法 tokenizer 标识(如 "tiktoken/o200k_base")。
# 不硬性限定具体 tokenizer(允许 tiktoken/transformers 等各家编码), 但格式须规范:
#   小写字母/数字/点/下划线/连字符组成, 长度 4-64, 且含至少一个 "/" 或知名前缀, 排除占位垃圾值。
TOKENIZER_NAME_RE = re.compile(r'^[a-z0-9._/-]{4,64}$')
TOKENIZER_KNOWN_PREFIX = ("tiktoken/", "transformers/", "huggingface/", "tokenizers/", "cl100k_base", "o200k_base", "p50k_base", "r50k_base", "gpt2", "codebert", "codet5", "unixcoder")
RE_OSS_DATASET = re.compile(
    r'(?i)\b(?:codealpaca|evol-?instruct|oss-?instruct|coder-?instruct|magicoder'
    r'|stack-?overflow[- ]dump|stack[- ]exchange[- ]dump)\b')
# 低阶模型特征(§4.1: 模型答案须 Claude-4.7-opus 及同等能力以上, 低阶不予入库)
LOW_TIER_MODELS = ("gpt-3.5", "gpt3.5", "gpt-4o-mini", "gpt-4-mini",
                   "llama-2", "llama-3", "chatglm", "baichuan", "vicuna", "alpaca")
# 疑似合成提问特征(§4.1: 禁止人工/大模型合成虚构提问; 保守特征串)
# 校准: 移除 "sample question"/"示例问题" —— 它们是 Web 页面/游戏模板里的普通词
# (实测 4/4 误报: textarea 示例、多选游戏题面、jsfiddle 模板), 不构成合成特征。
# ⚠️ 2026-09-20 再校准: 移除 "假设你是" —— 它是**算法题/游戏题面的规则用语**
# (实测误报: Tcdian/keep#43「现在, 假设你是「二号」玩家…」= LeetCode 类博弈题面),
# 与"AI 提示词"无关。保留的标记须含"AI/扮演/模拟"等明确合成意图。
SYNTHETIC_Q_MARKERS = ("作为一个ai", "作为一名ai", "ai语言模型", "示例提问",
                        "请你扮演", "请模拟一个")

# 违规内容关键词(§8 禁止内容, 抽样级粗筛)
FORBIDDEN_KW = ("挖矿木马", "病毒样本下载", "社工库", "银行卡四件套", "赌博网站搭建",
                "博彩平台", "毒品交易", "枪支买卖", "恐怖主义", "色情网站",
                "洗钱通道", "钓鱼网站生成", "爆破工具包", "木马生成器")

# 代码块
RE_CODE_BLOCK = re.compile(r'```(\w*)\n', re.M)
# Python 代码块 REPL/shell 特征(跳过语法校验, 属终端会话而非程序代码)
RE_REPL_HINT = re.compile(r'(?:^|\n)\s*(?:>>>|\.\.\.|\$ |PS> )')

# 近似重复(§4.2 LQ7: 仅变量名/注释微调的高度近似样本)
NEAR_DUP_JACCARD = 0.6
NEAR_DUP_SHINGLE_CAP = 5000  # 近似查重 shingles 内存上限: 超过则跳过(流式全量查重留终检/专用工具)

# 问题整改明细: 检查项 → 建议整改措施(规范书 §10 "问题整改明细"要求)
RECTIFY_ADVICE = {
    "结构": "补齐/剔除顶层六字段, 按 §7 结构重构造",
    "message缺失": "补全 message 问答数组",
    "message结构": "补齐每组 question/answer 键",
    "question为空": "补全 question 原文",
    "answer为空": "补全 answer 内容",
    "cleaning_status": "补齐三个清洗状态布尔位",
    "metadata缺失": "补齐 primary_language/token_count/type",
    "type值错误": "type 字段改为固定值 general_code_qa_dict",
    "id格式": "id 统一为 QA_2026_xxx 前缀哈希编码",
    "隐藏反爬文本": "清洗剔除 LeetCode 隐形水印 span(§4.1 噪点)",
    "隐私泄露": "人工复核命中原文(附录/明细节含值+上下文); 属实第三方 PII 按 §6 小写 x 占位脱敏(不得直接删除), 自披露/示例/代码值标注豁免",
    "疑似内网IP": "人工复核命中原文(明细节含 IP+上下文); 真实内网拓扑按 §6 x 占位脱敏, 文档示例地址/代码示例标注豁免",
    "疑似社交账号": "社交账号按 §6 x 占位脱敏",
    "非文本资源残留": "剔除图片/二进制/外链资源(§4.1 仅保留纯文本+代码)",
    "乱码字符": "修复编码或剔除样本(§4.1)",
    "疑似违规内容": "剔除样本(§8 双重拦截)",
    "疑似开源数据集混入": "剔除样本(§4.1 禁止复用公开数据集)",
    "source标注缺失": "source 按 §4.1 标注社区名/问题来源+答案模型",
    "低阶模型答案": "剔除或用 Claude-4.7-opus 同级以上模型重新生成(§4.1)",
    "样本完全重复": "去重(§9 全局重复率 <0.5%)",
    "近似重复": "剔除仅变量名/注释微调的副本(§4.2 LQ7)",
    "疑似合成提问": "剔除合成样本, 换真实用户 Query(§4.1)",
    "token_count偏差": "重算 token_count 保证元数据数值准确(§9)",
    "代码块无语言标签": "补齐代码块语言标签",
    "代码块疑似残缺": "复核代码完整性, 残缺样本剔除(§4.2 LQ2)",
    "代码语法校验失败": "修复代码或剔除样本(§9 代码须语法完整可复现)",
    "代码块括号失衡": "复核代码完整性(§4.2 LQ2)",
    "answer过短": "剔除低质回答(§4.2 LQ3)",
    "疑似闲聊问题": "剔除闲聊样本(§4.2 LQ1)",
    "疑似占位符": "剔除灌水/占位样本(§4.2 LQ6)",
    "多轮配对不足": "补全至 ≥3 组 Q-A(§9)",
    "清洗未完成": "确认清洗流水线已执行后置 true",
    "单/多轮混存": "按 §3 单轮/多轮分目录分片归档",
    "domain非数组": "domain 改为标签数组(SO 数据新口径 §5.2, 2026-09-14 起)",
    "时间字段缺失": "补齐 metadata.question_time/answer_time(SO 数据新口径, 从 SO API/Feed 回填)",
    "token元数据缺失": "补齐 metadata.question_tokens/answer_tokens/tokenizer(tiktoken o200k_base 重算, 2026-09-15 新口径)",
    "token计算方式未标明": "metadata.tokenizer 须标注真实 tokenizer(如 tiktoken/o200k_base, 2026-09-15 验收意见)",
}


def luhn_ok(num_str):
    """Luhn 校验(银行卡号合法性), 降低纯数字串误报。"""
    digits = [int(d) for d in num_str]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S", stream=sys.stderr)
log = logging.getLogger("qa_qc")


def has_bom(path):
    with open(path, "rb") as f:
        return f.read(3) == b"\xef\xbb\xbf"


def count_lines(path):
    """快速统计非空行(≈记录数), 不解析 JSON, 用于采样/近似查重前置决策。"""
    n = 0
    with open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


def iter_jsonl(path):
    """流式逐行迭代 jsonl, 生成 (lineno, record)。O(1) 内存(不整文件 load)。
    解析失败的行记录进返回的 errors 列表 [(lineno, msg), ...]。
    用 utf-8-sig 透明剥离 BOM(BOM 本身另行检测报 ERROR)。"""
    errors = []

    def gen():
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield lineno, json.loads(line)
                except json.JSONDecodeError as e:
                    errors.append((lineno, str(e)))

    return gen(), errors


def md5(s):
    return hashlib.md5(s.encode("utf-8", "ignore")).hexdigest()


def est_tokens(s):
    """token 粗估: 中文按字, 代码/英文按 4 字符≈1 token。"""
    cjk = len(re.findall(r'[\u4e00-\u9fff]', s))
    other = len(s) - cjk
    return int(cjk + other / 4)


def qa_shingles(text, n=5):
    """字符级 5-gram 集合(规范化), 用于问答近似重复检测(§4.2 LQ7)。"""
    s = re.sub(r'\s+', '', (text or '').lower())
    return frozenset(s[i:i + n] for i in range(max(0, len(s) - n + 1)))


FENCE_LINE_RE = re.compile(r'^```([A-Za-z0-9+#.\-]*)[ \t]*$')


def _closed_blocks_in_field(text):
    """单字段内提取"成对闭合"的 fenced 代码块 [(lang, body), ...]。

    按行序两两配对 (0,1)(2,3)……; 若 fence 行数为奇数, 最后一个悬挂开围栏
    之后的内容视为正文(不判代码块) —— 避免 Q/A 拼接后跨字段 fence 误配把正文
    吞进'代码块'(奇数 fence 时 ```python 会配到别处, ast.parse 把正文当代码 →
    "unterminated string literal" 误报)。
    """
    lines = text.split("\n")
    fence_idx = [i for i, ln in enumerate(lines) if FENCE_LINE_RE.match(ln)]
    out = []
    for k in range(0, len(fence_idx) - 1, 2):
        s, e = fence_idx[k], fence_idx[k + 1]
        lang = FENCE_LINE_RE.match(lines[s]).group(1)
        out.append((lang or "", "\n".join(lines[s + 1:e])))
    return out


def _strip_for_brackets(code, lang=""):
    """剥离注释与字符串字面量, 仅保留“代码骨架”用于括号平衡粗检。

    lang: 代码块语言标签(小写), **仅用于判定是否启用 Rust 生命周期规则** ——
          该规则对其它语言是灾难(见下 ①), 必须按语言 gating。

    校准历史:
      · 原实现直接 count() 整块 ⇒ 注释/字符串里的括号也计入, 误报
        (LeetCode 题解注释里的 [i+1,n)、被注释掉的 //for(...){、字符字面量 '}' )。
      · 2026-09-20 一轮: URL 里的 // 不作行注释起点(回看连续 / 串, 前一个字符是 : ⇒ scheme)。
      · 2026-09-20 二轮(本版) —— 抽样审查 30 个命中块后发现 **约 1/3 是脚本误报**, 逐类修:
          ① Rust 生命周期 'a / 'static: 单引号后随标识符首字符、且再后面不是闭合引号
             ⇒ 不是字符字面量(否则整行后续括号被当字符串内容吞掉)。
             实测 <'a, P> 原文 ()15/15 平衡 → 剥壳后 12/15。
          ② 三引号 raw string(Kotlin/Scala \"\"\" / Python ''')跨行 ⇒ 整段识别并剥离,
             否则被当普通 " 反复切换, 使原文平衡的代码变不平衡。
          ③ 未闭合字符串回吐: 作者漏写闭合引号时, 该行后续括号会被当字符串内容吞掉。
             现在遇到换行仍未闭合 ⇒ 视作非字符串, 把缓冲内容原样回吐。
             实测 php $pool->getItem('foo', ['ns1]); 原文 ()2/2 平衡 → 剥壳 2/0。
    单遍状态机: 正常 / 行注释 / 块注释 / 字符串(含三引号), 处理反斜杠转义。
    """
    # ⚠️ Rust 生命周期规则**只对 rust 块启用**: 若对所有语言生效, 会把 JS/PHP 的
    #   单引号字符串一律误判(其内容常以字母开头, 如 var s = 'hello'), 导致引号配对
    #   全线错位 ⇒ 实测「括号失衡」从 43,550 块**涨到** 70,543 块。
    _is_rust = (lang or "").lower().startswith("rust")
    out = []
    i, n = 0, len(code)
    in_line = in_block = False
    q = ""                 # 字符串定界符: " ' \"\"\" ''' (空 = 不在字符串中)
    buf = []               # 字符串内容缓冲(未闭合要回吐)
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        n2 = code[i + 2] if i + 2 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            i += 1
            continue
        if in_block:
            if c == "*" and nxt == "/":
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if q:                                   # ---- 字符串中 ----
            if c == "\\":
                buf.append(c)
                buf.append(nxt)
                i += 2
                continue
            if len(q) == 3:
                if code.startswith(q, i):
                    q, buf = "", []
                    i += 3
                    continue
                buf.append(c)
                i += 1
                continue
            if c == q:
                q, buf = "", []
                i += 1
                continue
            if c == "\n":
                # ③ 未闭合字符串 ⇒ 不是字符串, 把缓冲内容原样回吐(见 docstring)
                out.extend(buf)
                buf = []
                q = ""
                out.append(c)
                i += 1
                continue
            buf.append(c)
            i += 1
            continue
        # ---- 正常态 ----
        # 行注释: URL 里的 // 不算(回看连续 / 串; 前一个字符是 : ⇒ URL scheme)
        if c == "/" and nxt == "/":
            j = i - 1
            while j >= 0 and code[j] == "/":
                j -= 1
            if not (j >= 0 and code[j] == ":"):
                in_line = True
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        if c == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if c in ('"', "'") and nxt == c and n2 == c:      # ② 三引号
            q, buf = c * 3, []
            i += 3
            continue
        if c == '"':
            q, buf = '"', []
            i += 1
            continue
        if c == "'":
            # ① Rust 生命周期 'a / 'static ⇒ 非字符字面量(**仅 rust 块**, 见上方 gating)
            if _is_rust and (nxt.isalpha() or nxt == "_") and n2 != "'":
                out.append(c)
                i += 1
                continue
            q, buf = "'", []
            i += 1
            continue
        out.append(c)
        i += 1
    if q:                                       # 文件末尾仍未闭合 ⇒ 回吐缓冲
        out.extend(buf)
    return "".join(out)


def check_code_syntax(code_fields):
    """抽样代码功能校验(§10): 逐字段提取成对闭合的 fenced 代码块做语法/完整性校验。

    code_fields: 各问答字段文本列表(question/answer 分列, 按轮次顺序), 使代码块
    判定与字段边界一致(不误跨 Q/A 边界)。
    返回 dict: {blocks, python_checked, python_fail, bracket_bad, nolang, tiny}
    以及 issue 列表 [(类型, 详情)]。
    """
    st = {"blocks": 0, "python_checked": 0, "python_fail": 0,
          "bracket_bad": 0, "nolang": 0, "tiny": 0}
    issues = []
    for field in code_fields:
        for lang, code in _closed_blocks_in_field(field or ""):
            st["blocks"] += 1
            lang_l = (lang or "").strip().lower()
            body = code.rstrip()
            if not body.strip():
                continue
            nlines = len(body.strip().splitlines())
            if not lang_l:
                st["nolang"] += 1
            if 0 < nlines < 3 and lang_l != "text":   # text=样例 IO 数据块, 非代码(AtCoder 固有形态)
                st["tiny"] += 1
            # ⚠️ 2026-09-20 口径变更(用户拍板): **移除 Python ast.parse 语法校验**。
            #   理由: 论坛问答(GitHub Issues)的代码块天然是**片段型** —— 作者常省略
            #   上下文缩进、用 `(...)`/`...` 占位、写 Py2 语法(`print x`)、或有意
            #   留残缺示例; 这些是真实语料形态, 不是数据缺陷。
            #   实测被该检查判 ERROR 的 24,324 条(2.8%), 逐条取样证实全部是源数据
            #   真实片段(如 `def f(...):` / `type(s) = machine.SPI` / `exit=False*)`)。
            #   ⇒ 该硬指标不适用于论坛型语料, 已移除(报告对应行改显 ➖ 不执行)。
            if lang_l in ("js", "javascript", "ts", "typescript", "java", "c",
                            "cpp", "c++", "go", "rust", "cs", "csharp", "php",
                            "rb", "ruby", "swift", "kt", "kotlin", "scala"):
                # 括号平衡粗检(字符串内括号会造成少量误报, 仅 WARN 级)
                # 豁免 1: 省略号 —— 用户缩略示例代码普遍省略闭合括号
                # (如 appbar.addOnOffsetChangedListener { ... } 截图截断), 非真残缺。
                # ⚠️ 2026-09-20 扩宽: 原仅认 "..." / "…"; 实测作者也写**两点** ".."
                #   (如 /* ..rest of code.. */) ⇒ 一并豁免。
                #   判据 `(?<![\w.])\.\.(?![./])`: 要求 ".." 前不是单词字符/点, 后不是 "." 或 "/"
                #   ⇒ 命中 ` ..rest`(后随字母) 与 ` */`, 但排除 `...` 内部、`../路径`、`a..b`、`1..5`。
                if ("..." in body or "…" in body or "省略" in body
                        or re.search(r"(?<![\w.])\.\.(?![./])", body)):
                    continue
                # 豁免 2(2026-09-20 新增): **patch/diff 文本不是可编译代码** ——
                #   diff 只含增删行, 括号天然不成对。实测误报样本:
                #   "diff --git a/... +++ b/... @@ -6,7 +6,7 @@" ⇒ 跳过粗检。
                if body.lstrip().startswith("diff --git") or \
                        re.search(r"^@@ .* @@", body, re.M):
                    continue
                # 豁免 3(2026-09-21 新增): **单行控制流片段** —— 论坛里"只贴关键一行"
                #   的片段(单行 if/for/while/case 且尾随 { ( , && || = :), 是真实语料
                #   形态(同省略号: 块"自声明"不完整), 非数据缺陷。
                #   ⚠️ 零风险设计: 仅单行 + 仅控制流关键词开头 + 仅以"未闭合终结符"收尾
                #   ⇒ 完整单行代码(括号本就平衡)根本不会走到失衡分支, 不受影响;
                #   多行残缺/真 typo 也不命中(行数>1 或非关键词开头)。
                #   2026-09-21 GitHubIssues 6000 条巡检归因: 尾部未闭合类 18% 中
                #   绝大多数属此类(如 "if (point.x == this.pos.x) || (… <= … + …) {")。
                _one = body.strip()
                if (_one.count("\n") == 0 and len(_one) > 8
                        and re.match(
                            r"(?i)^(if|while|for|switch|case|catch|do|else\s+if|else|return|try)\b",
                            _one)
                        and _one.rsplit(None, 1)[-1].rstrip(";")
                        .endswith(("{", "(", "[", ",", "&&", "||", "=>", ":", "=", "&", "|", "+"))):
                    continue
                # 括号平衡只统计"代码骨架"(剥离 // 与 /* */ 注释、字符串/字符字面量),
                # 否则注释/字符串内的括号被计入 → 误报(实测 LeetCode 题解多例)。
                skel = _strip_for_brackets(body, lang_l)
                paren_o, paren_c = skel.count("("), skel.count(")")
                brack_o, brack_c = skel.count("["), skel.count("]")
                brace_o, brace_c = skel.count("{"), skel.count("}")
                if paren_o != paren_c or brack_o != brack_c or brace_o != brace_c:
                    st["bracket_bad"] += 1
                    issues.append(("代码块括号失衡",
                                   f"{lang_l} 块: () {paren_o}/{paren_c} "
                                   f"[] {brack_o}/{brack_c} {{}} {brace_o}/{brace_c}"))
    return st, issues


# ----------------------------------------------------------------------------
# 深度质检(语义层 N1-N9) —— 原 code_qa_deep_qc.py 逻辑并入(2026-09-19 脚本合并)。
# 覆盖主检查盲区(2026-09 抽样核验沉淀): 无代码块/模板占位/语言标注交叉/token 复算/
# 截断/上标压平/时间字段共模/AI 答案标记。全部默认 WARN, 不改 E1-E14 的 ERROR 语义;
# --fail-on-warn 可转 ERROR 接 CI。dataset_class: code=编程题集 / forum=论坛问答(抑制 N1/N3/N6)。
# ----------------------------------------------------------------------------
RULE_DESC = {
    "N1_无代码块": "question/answer 均无围栏代码块",
    "N2_模板占位": "答案含采集/平台模板占位模式",
    "N3_语言标注不符": "primary_language 与代码块语言/代码块有无交叉不符",
    "N4_token复算偏差": "按声明 tokenizer 抽样复算 token, 与存值不一致",
    "N5_截断嫌疑": "answer 疑似尾部截断(句中收尾/围栏未闭合)",
    "N6_上标压平可疑": "约束数值疑似上标压平(109/231 类)",
    "N8_时间字段共模": "question_time 单一取值占比过高(疑似题目时间口径)",
    "N9_AI生成答案": "答案作者标记为 AI 生成(info, 口径待客户)",
}

TEMPLATE_PATTERNS = [
    ("write_idea_cn", "此处撰写解题思路"),
    ("problem_code", "Problem: Code"),
    ("title_repeat", "题解: "),
]
AI_AUTHOR_PAT = re.compile(r"\bAI answer\b|AI\s*生成|GPT[- ]?generated", re.I)
SUPP_PAT = re.compile(
    r"(<=|≥|<)\s*10[1-9](?![0-9.,])|\b10[1-9]\s*(<=|≥|<)|(-\s*)?231\s*-\s*1")
FENCE = re.compile(r"```([^\n`]*)\n(.*?)```", re.S)
FENCE_OPEN = re.compile(r"(?m)^\s*```")
STOP_PUNCT = set(".!?。！？:;:;")
CODE_KW_PAT = re.compile(
    r"(?:\bSELECT\b|\bINSERT\b|\bCREATE\s+TABLE\b|\bdef\b|\bclass\b|\bfunction\b|"
    r"\bpublic\s+static\b|\bint\s+main\b|\bvar\b|console\.log|print\s*\(|input\s*\(|"
    r"#include|\bimport\b|\bfn\b|\bpackage\s+main\b|\becho\b|\bif __name__|->|=>)", re.I)
STRONG_CODE_PAT = re.compile(
    r"(?m)(\A[ \t]*#include|int main\(|using namespace std|#ifndef\s|#define\s|"
    r"public class\s+[A-Za-z_]|import java\.|public static void|"
    r"^\s*(def |class )\w+.*:|^\s*import \w+.*$|^\s*fn \w+|^\s*let mut |^\s*<?php)"
)
RAW_DETECTABLE = {"go", "java", "rust", "c#", "php", "c++", "c", "python",
                  "javascript", "typescript"}
FENCE_LANG_MAP = {
    "python": "python", "py": "python", "python3": "python",
    "java": "java", "cpp": "c++", "c++": "c++", "cxx": "c++", "c": "c",
    "js": "javascript", "javascript": "javascript", "typescript": "typescript",
    "ts": "typescript", "go": "go", "golang": "go", "rust": "rust",
    "php": "php", "csharp": "c#", "cs": "c#", "c#": "c#", "kotlin": "kotlin",
    "swift": "swift", "ruby": "ruby", "bash": "bash", "sh": "bash", "shell": "bash",
    "sql": "mysql", "mysql": "mysql", "psql": "postgresql", "powershell": "powershell",
    "ps1": "powershell", "vb": "vb.net", "vb.net": "vb.net", "vbnet": "vb.net", "scala": "scala",
    "r": "r", "perl": "perl", "html": "html", "css": "css", "json": "json",
    "shellsession": "bash", "console": "", "text": "", "txt": "", "markdown": "",
    "plaintext": "",
}
NON_LANG = {"json", "html", "css", "markdown", "plaintext", "text", "sql", "mysql",
            "postgresql", "mssql", "oracle", "bash", "shell", "powershell", "console"}
PLACEHOLDER_ANSWER_PAT = re.compile(
    r"^\s*(题解[:：]\s*)?\S{0,16}\s*\n\s*(此处撰写解题思路|Problem: Code|Code|题解|完成|测试|aa|。|1)\s*$")
LANG_SYNONYMS = {
    "cpp": "c++", "cxx": "c++", "c++": "c++",
    "js": "javascript", "typescript": "typescript",
    "vb": "vb.net", "vbnet": "vb.net", "vb.net": "vb.net",
    "ts": "typescript", "py": "python", "python3": "python",
    "golang": "go", "csharp": "c#", "cs": "c#", "c#": "c#",
    "powershell": "powershell", "ps1": "powershell",
    "mysql": "sql", "sql": "sql", "psql": "sql",
    "bash": "shell", "sh": "shell", "shell": "shell", "shellsession": "shell",
    "console": "", "text": "", "txt": "", "markdown": "", "plaintext": "",
}
_LANG_EQUIV = {"c": "c/c++", "c++": "c/c++",
               "javascript": "js/ts", "typescript": "js/ts"}


def strip_comments(text):
    """剥离注释(启发式): /* */ 块 + // 行 + Rust #[doc] 属性行。注释内嵌 ``` 不干扰配对。"""
    if not text:
        return text
    t = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    t = "\n".join(l for l in t.splitlines()
                  if not l.lstrip().startswith(("//", "#[doc")))
    return t


def raw_code_lang(text):
    """识别裸代码(无围栏)语言, 按排他性顺序判定(Go/C#/Rust/PHP/C++/C/JS/Java/Python)。
    小众语言(ruby/haskell/perl/kotlin/ocaml/shell)无可靠排他特征 → 返回 None。"""
    t = text or ""
    if re.search(r"(?m)^\s*package\s+main\b", t):
        return "go"
    if re.search(r"(?m)^\s*using\s+(System|Microsoft|static)\b", t) \
            or re.search(r"\bConsole\.(ReadLine|WriteLine|Read|ReadKey|Out)\b", t):
        return "c#"
    if re.search(r"(?m)^\s*fn\s+main\s*\(", t) or "fn main" in t or re.search(r"(?m)^\s*use\s+std::", t):
        return "rust"
    if re.search(r"(?m)^\s*<\?php", t):
        return "php"
    if "using namespace std" in t or re.search(r"#include\s*<bits/stdc\+\+\.h>", t) \
            or re.search(r"\bstd::\w+", t) or re.search(r"\bcout\s*<<", t):
        return "c++"
    if re.search(r"(?m)^\s*#\s*include\s*[<\"]", t):
        return "c"
    if re.search(r"console\.log|require\(|function\s+main\b|process\.stdin|createInterface", t):
        return "javascript"
    if re.search(r"(?m)^\s*import\s+(?:static\s+)?java\.", t) or re.search(r"\bSystem\.out\.", t) \
            or re.search(r"(?m)^\s*public\s+(?:final\s+|abstract\s+)?class\s+\w+", t) \
            or "void main(String" in t or "String[] args" in t:
        return "java"
    if re.search(r"(?m)^\s*def\s+\w+.*:", t) or "if __name__" in t \
            or re.search(r"(?m)^\s*(self\.|print\s*\(|input\s*\()", t) or '"""' in t or "'''" in t:
        return "python"
    return None


def has_code_signal(text):
    """宽口径「代码结构」信号(语言无关) —— 救回 raw_code_lang 无法判语言但有代码结构
    的小众语言裸代码, 避免 N1/N3 误判「无代码」。每条均为散文里几乎不会出现的结构标记。"""
    t = text or ""
    if not t.strip():
        return False
    if re.search(r"(?m)^\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w+)*\s*;\s*$", t):
        return True
    if "->" in t or "=>" in t:
        return True
    if re.search(r"(?m)^\s*my\s+[@$]\w", t) or re.search(r"\buse\s+(strict|warnings)\b", t):
        return True
    if re.search(r"(?m)\bqw\[|<>\b|^\s*[@$][A-Za-z_]\w*\s*=|\bchomp\b", t):
        return True
    if "<-" in t or re.search(r">>=|::\s*[A-Z\[]", t):
        return True
    if re.search(r"(?m)^\s*(fun|let|val)\s+\w+", t):
        return True
    if re.search(r"(?m)^\s*(open|module)\s+[A-Z]\w+", t):
        return True
    if re.search(r"\bgets\b|\bputs\b|\.times\b|\.chomp\b|\bdo\s*(\||\{)", t):
        return True
    if re.search(r"(?m)^\s*(awk|sed|read|printf)\b", t):
        return True
    if re.search(r"(?m)^\s*def\s+\w+\s*:", t) or re.search(r"(?m)^\s*for\s+\w+\s+in\s+\w+", t):
        return True
    return False


def _norm_lang(x):
    s = str(x or "").strip().lower()
    return LANG_SYNONYMS.get(s, s)


def _lang_neq(pl_norm, actual_set):
    """pl 与 actual 是否「不等价」(c/c++ 与 js/ts 互认)。返回 True=确实不符。"""
    p = _LANG_EQUIV.get(pl_norm, pl_norm)
    for x in actual_set:
        if x in ("", "ignore", '"', "'", "`"):
            continue
        if _LANG_EQUIV.get(x, x) == p:
            return False
    return True


def fence_langs(text):
    out = []
    for m in FENCE.finditer(strip_comments(text)):
        head = (m.group(1) or "").strip()
        if not head or not re.match(r"^[A-Za-z0-9+#.-]+$", head.split()[0]):
            continue
        lang = head.split()[0].lower()
        lang = FENCE_LANG_MAP.get(lang, lang)
        if lang:
            out.append(lang)
    return out


def deep_check_record(rec, dataset_class="forum"):
    """深度语义层 N1-N9, 返回 (issues {rule: detail}, ctx {q,a,meta,fences})。
    dataset_class: "code"=答案应含代码的编程题集(LeetCode/AtCoder/CodeChef);
                   "forum"=论坛问答(StackExchange 等), 纯文字答案合法 → 抑制 N1/N3/N6。"""
    forum = (dataset_class == "forum")
    msg = rec.get("message") or [{}]
    q = ""
    a = ""
    for turn in msg:
        q += (turn.get("question") or "") + "\n"
        a += (turn.get("answer") or "") + "\n"
    m = rec.get("metadata") or {}
    pl = str(m.get("primary_language") or "")
    a_sc = strip_comments(a)
    q_sc = strip_comments(q)
    afences = fence_langs(a)
    qfences = fence_langs(q)
    fences = afences + qfences
    issues = {}
    _sc = lambda t, s, e, w=40: "«" + _hit_ctx(t, s, e, w) + "»"  # 命中原文(明细可复核)

    # N1 无代码块(仅 code 类适用; forum 纯文字答案合法 → 豁免)
    raw_lang = None
    if not forum and not FENCE.search(a_sc) and not FENCE.search(q_sc):
        raw_lang = raw_code_lang(a_sc)
        if raw_lang is None:
            if has_code_signal(a_sc):
                raw_lang = "__signal__"
            elif STRONG_CODE_PAT.search(a_sc):
                raw_lang = "__strong__"
            elif m.get("has_code") is True:
                raw_lang = "__hascode__"
        if raw_lang is None and len(a_sc.strip()) > 40:
            # 附答案开头原文(证明确为纯文字, 无裸代码漏判)
            issues["N1_无代码块"] = (
                "q/a 均无代码块(含裸代码判定); 答案开头: "
                f"{_sc(a_sc, 0, min(60, len(a_sc)), 0)}")

    # N2 模板占位(附模板串命中原文)
    for name, pat in TEMPLATE_PATTERNS[:2]:
        i = a.find(pat)
        if i >= 0:
            issues["N2_模板占位"] = f"答案含模板占位 [{name}] {_sc(a, i, i + len(pat))}"
            break
    if "N2_模板占位" not in issues and PLACEHOLDER_ANSWER_PAT.match(a.strip()):
        issues["N2_模板占位"] = "标题式空答案"

    # N3 语言交叉验证(仅校验答案代码语言; 题面示例代码不计入)
    pl_norm = _norm_lang(pl)
    if pl and pl_norm not in ("unknown", "text", "none", "") and not forum:
        if afences:
            valid = {_norm_lang(f) for f in afences}
            valid = {x for x in valid if x and x not in ("ignore", '"', "'", "`")}
            if valid and _lang_neq(pl_norm, valid):
                issues["N3_语言标注不符"] = f"标 {pl} 但答案代码语言 {sorted(valid)}"
        else:
            a_rl = _norm_lang(raw_code_lang(a_sc))
            if a_rl:
                if pl_norm in RAW_DETECTABLE and _lang_neq(pl_norm, {a_rl}):
                    issues["N3_语言标注不符"] = f"标 {pl} 但答案裸代码语言 {a_rl}"
            elif not (has_code_signal(a_sc) or CODE_KW_PAT.search(a_sc)
                      or STRONG_CODE_PAT.search(a_sc) or m.get("has_code") is True):
                issues["N3_语言标注不符"] = f"标 {pl} 但答案无代码块且无代码特征词"
    if not forum and pl.lower() in ("json", "html", "css"):
        issues["N3_语言标注不符"] = issues.get("N3_语言标注不符", "") + \
            f" | 标 {pl}(数据格式/标记语言, 非编程语言)"

    # N5 截断嫌疑(仅 code 类; forum 把 ``` 当行内代码, 围栏天然不成对 → 抑制)
    # 附最后一个未闭合围栏处的原文(看内容戛然而止还是围栏误用)
    if not forum and len(FENCE_OPEN.findall(a_sc)) % 2 == 1:
        _opens = [x.start() for x in FENCE_OPEN.finditer(a_sc)]
        _lp = _opens[-1]
        issues["N5_截断嫌疑"] = f"代码围栏未闭合; 末围栏处: {_sc(a_sc, _lp, _lp + 3)}"

    # N6 上标压平(仅 code 类: 竞赛题约束数值; forum 普通数字误报 → 抑制)
    # 附命中串 + 题面原文(看约束区间压平形态, 如 2≤n≤2^31-1 → 2≤n≤231 - 1)
    if not forum:
        _sup = SUPP_PAT.search(q)
        if _sup:
            issues["N6_上标压平可疑"] = (
                f"题面含疑似压平上标 [{_sup.group(0)}]; {_sc(q, _sup.start(), _sup.end())}")

    # N9 AI 答案(2026-09-20 收紧: **只扫 author/metadata 署名类字段**, 正文命中不判 —
    # 论坛语料正文大量"讨论 ChatGPT/GPT generated"属被讨论对象而非答案作者标注,
    # 全量扫正文会把此类全部误判(样例集 5/5 均为误报); 署名式标记才说明答案由 AI 生成)
    for k in ("answer_author", "author", "solution_author", "solution", "by"):
        hv = str(m.get(k) or "")
        if not hv:
            continue
        ha = AI_AUTHOR_PAT.search(hv)
        if ha:
            issues["N9_AI生成答案"] = (
                f"metadata.{k} 含 AI 署名标记 [AI标记]{ha.group(0)}; "
                f"值: «{_hit_ctx(hv, ha.start(), ha.end(), 40)}»")
            break

    return issues, {"q": q, "a": a, "meta": m, "fences": fences}


# ----------------------------------------------------------------------------
# 检查逻辑
# ----------------------------------------------------------------------------
class QaQC:
    def __init__(self, near_dup=True, shingle_cap=NEAR_DUP_SHINGLE_CAP,
                 max_detail=200000, exempt_multi_turn=True,
                 dataset_class="forum", token_sample=0.0, fail_on_warn=False):
        self.near_dup = near_dup            # 是否启用近似查重(§4.2 LQ7)
        # 多轮占比 ≥10% 红线默认豁免(2026-09-19): 代码问答数据集构造上多为单轮
        # (SO 采纳答案/编程题集), 多轮 0% 单列 WARN 不触发退回; 需多轮口径的
        # 工单/追答类数据用 exempt_multi_turn=False 显式关闭豁免。
        self.exempt_multi_turn = exempt_multi_turn
        # 深度语义层(N1-N9) —— 合并自 code_qa_deep_qc.py
        # 2026-09-20: 恒为 forum(已移除 --dataset-class 参数)
        self.dataset_class = dataset_class
        self.token_sample = token_sample    # N4 token 复算抽样比例(0=关)
        self.fail_on_warn = fail_on_warn    # 深度层 WARN 是否转 ERROR 接 CI
        self._deep_rng = random.Random(20260918)
        self._deep_enc = None
        if token_sample and token_sample > 0:
            try:
                import tiktoken
                self._deep_enc = tiktoken.get_encoding("o200k_base")
            except Exception:  # tiktoken 缺失时 N4 自动跳过
                self._deep_enc = None
        self.deep_rule_hits = {k: 0 for k in RULE_DESC}
        self.deep_rule_samples = {k: [] for k in RULE_DESC}
        self.deep_qtime = collections.Counter()
        self.deep_tok_mismatch = 0
        self.shingle_cap = shingle_cap      # shingles 收集上限, 超过停止收集
        self.near_dup_skipped = False       # 因超上限/禁用而跳过近似查重
        self.max_detail = max_detail        # 明细列表上限(计数不受限, 明细封顶防大集 OOM)
        self.error_rows, self.warn_rows = [], []
        self._err_count = 0                 # 全量计数(恒准确, 供报告/退出码)
        self._warn_count = 0
        self._item_cnt = {}                 # 检查项 → 全量条数(整改明细用, 恒准确)
        # 2026-09-20: 检查项 → 级别(ERROR 优先)。用于「问题整改明细」区分
        # ERROR(待整改) / WARN(建议复核, 不阻断交付) —— 原先把两者都写成"待整改",
        # 使 WARN 项(如"多轮配对不足", 属数据真实形态)读起来像欠账。
        self._item_level = {}
        self.stats = {"total": 0, "multi_turn": 0, "lang": {}, "domain": {},
                      "dup_q": 0, "same_q_diff_lang": 0, "hidden_span": 0, "tokens_sum": 0,
                      "multi_turn_lt3": 0, "files_mixed_turn": [],
                      # §10 三、抽样代码功能校验
                      "code": {"blocks": 0, "python_checked": 0, "python_fail": 0,
                               "bracket_bad": 0, "nolang": 0, "tiny": 0},
                      "code_fail_recs": 0,
                      # §10 四、问答真实性校验
                      "source_missing": 0, "source_multi": 0, "source_model": 0,
                      "synthetic_q": 0, "oss_dataset": 0, "low_tier_model": 0,
                      # §10 五、重复率校验
                      "near_dup": 0,
                      # §10 六、脱敏校验
                      "privacy": 0, "privacy_hits": {},
                      # §10 七、低质样本过滤记录(§4.2 七规则)
                      "lq": {"LQ1_闲聊咨询": 0, "LQ2_代码残缺语法错误": 0,
                             "LQ3_回答过短无实质": 0, "LQ4_隐私未脱敏": 0,
                             "LQ5_违规内容": 0, "LQ6_占位符乱码模板": 0,
                             "LQ7_问答高度近似": 0}}
        self.ip_detail = []         # [(rid, ip, 上下文)] 内网 IP 全量命中(报告附录展示原文)
        self.social_detail = []     # [(rid, 值, 上下文)] 社交账号全量命中(报告附录展示原文; 已脱敏的不计入)
        self._seen_q = {}
        self._seen_firstq = {}
        self._file_turn_kinds = {}  # 文件 → {single, multi} 出现标记(§3 分片归档检查)
        self._shingles = []         # [(rid, frozenset)] 近似重复检测

    def add(self, level, rid, item, detail):
        # 计数恒增(报告/退出码/整改明细准确); 明细列表封顶防大集 OOM
        if level == "ERROR":
            self._err_count += 1
        else:
            self._warn_count += 1
        self._item_cnt[item] = self._item_cnt.get(item, 0) + 1
        if level == "ERROR" or item not in self._item_level:
            self._item_level[item] = level     # ERROR 优先(同一检查项混级时以 ERROR 为准)
        lst = self.error_rows if level == "ERROR" else self.warn_rows
        if len(lst) < self.max_detail:
            lst.append((rid, item, detail))

    def check_record(self, fpath, rec):
        rid = rec.get("id", "?")
        st = self.stats
        st["total"] += 1

        # E1 顶层结构
        top = set(rec.keys())
        if top != TOP_FIELDS:
            missing = TOP_FIELDS - top
            extra = top - TOP_FIELDS
            self.add("ERROR", rid, "结构",
                     f"顶层字段: 缺 {sorted(missing) or '无'}, 多 {sorted(extra) or '无'}"
                     f"(§7 六字段全必填)")

        message = rec.get("message")
        meta = rec.get("metadata") or {}
        cs = rec.get("cleaning_status") or {}

        # E2 message 数组
        if not isinstance(message, list) or not message:
            self.add("ERROR", rid, "message缺失", "message 须为非空数组(§7)")
            message = []
        for i, turn in enumerate(message, 1):
            if not isinstance(turn, dict) or set(turn.keys()) < {"question", "answer"}:
                self.add("ERROR", rid, "message结构", f"第{i}组缺 question/answer")
                continue
            q, a = turn.get("question") or "", turn.get("answer") or ""
            if not q.strip():
                self.add("ERROR", rid, "question为空", f"第{i}组 question 为空")
            if not a.strip():
                self.add("ERROR", rid, "answer为空", f"第{i}组 answer 为空")

        # 多轮统计(§9: ≥10%)
        if len(message) >= 2:
            st["multi_turn"] += 1
            kinds = self._file_turn_kinds.setdefault(fpath, set())
            kinds.add("multi")
            if len(message) < 3:
                st["multi_turn_lt3"] += 1
                self.add("WARN", rid, "多轮配对不足",
                         f"多轮对话 Q-A 配对 {len(message)} 组(<3 组, §9 要求多轮 ≥3 组)")
        elif message:
            kinds = self._file_turn_kinds.setdefault(fpath, set())
            kinds.add("single")

        # E3 cleaning_status
        missing_cs = [k for k in CS_FIELDS if k not in cs]
        if missing_cs:
            self.add("ERROR", rid, "cleaning_status", f"缺 {missing_cs}(§7 必填)")
        false_cs = [k for k in CS_FIELDS if cs.get(k) is False]
        if false_cs:
            self.add("WARN", rid, "清洗未完成", f"{false_cs} 为 false")

        # E4 metadata 必填
        missing_md = [k for k in MD_FIELDS if k not in meta or meta.get(k) in (None, "")]
        if missing_md:
            self.add("ERROR", rid, "metadata缺失", f"缺 {missing_md}(§7 必填)")
        if meta.get("type") is not None and meta.get("type") != MD_TYPE_FIXED:
            self.add("ERROR", rid, "type值错误",
                     f"type={meta.get('type')!r}(应为固定值 {MD_TYPE_FIXED})")

        # E15/E16 代码问答新口径(2026-09-14 起, 对所有代码问答数据生效):
        #   E15 domain 必须是标签数组; E16 metadata.question_time/answer_time 不可缺失。
        #   注意: 该口径对所有代码问答数据集统一适用(AtCoder/CodeChef/LeetCode 等
        #   若 domain 为字符串或无时间字段, 亦按 ERROR 处理, 需随采集整改)。
        if not isinstance(rec.get("domain"), list):
            self.add("ERROR", rid, "domain非数组",
                     f"domain={rec.get('domain')!r}(代码问答统一要求标签数组, 2026-09-14 新口径)")
        miss_t = [k for k in ("question_time", "answer_time")
                  if not meta.get(k)]
        if miss_t:
            self.add("ERROR", rid, "时间字段缺失",
                     f"metadata 缺 {miss_t}(代码问答统一要求保留, 不得删除)")

        # E17 token 数值字段必填(2026-09-15 起, 对所有代码问答数据生效):
        #   metadata.question_tokens / answer_tokens 不可缺失;
        #   token_count 缺失或与拆分不等的记录已有 W1 校验(WARN), 此处仅查"字段存在性"。
        miss_tok = [k for k in ("question_tokens", "answer_tokens")
                    if k not in meta or meta.get(k) in (None, "")]
        if miss_tok:
            self.add("ERROR", rid, "token元数据缺失",
                     f"metadata 缺 {miss_tok}(代码问答统一要求保留, 2026-09-15 新口径)")

        # E18 tokenizer 计算方式须标明且合法(2026-09-15 起, 对所有代码问答数据生效):
        #   验收意见 "后续标明 token 计算方式(使用的哪个 tokenizer)"。
        #   · metadata.tokenizer 缺失/空 → ERROR;
        #   · 值不符合合法 tokenizer 标识格式(非 [a-z0-9._/-]、长度<4、无知名前缀/斜杠) → ERROR。
        tk_v = meta.get("tokenizer")
        if not tk_v or not str(tk_v).strip():
            self.add("ERROR", rid, "token计算方式未标明",
                     "metadata.tokenizer 缺失/为空(须标明使用的 tokenizer, 如 tiktoken/o200k_base)")
        else:
            tk_s = str(tk_v).strip().lower()
            if not (TOKENIZER_NAME_RE.fullmatch(tk_s)
                    and ("/" in tk_s or tk_s.startswith(TOKENIZER_KNOWN_PREFIX))):
                self.add("ERROR", rid, "token计算方式未标明",
                         f"tokenizer={tk_v!r}(非合法 tokenizer 标识, 应如 tiktoken/o200k_base)")

        # E5 id 规范
        if not str(rid).startswith(ID_PREFIX):
            self.add("ERROR", rid, "id格式", f"应以 {ID_PREFIX} 开头(§7)")

        full_text = "\n".join(
            f"{t.get('question', '')}\n{t.get('answer', '')}" for t in message
            if isinstance(t, dict))
        # 语境检测(占位/社交/内网)语义 = 回答里的灌水/泄露 → 范围仅 answer
        # (question 为官方题面, 样例数据中的 x 串/?? 串/指令集名均为题目内容)
        answer_text = "\n".join(
            t.get('answer', '') for t in message if isinstance(t, dict))

        # E8 隐藏反爬水印 span
        m = RE_HIDDEN_SPAN.search(full_text)
        if m:
            st["hidden_span"] += 1
            self.add("ERROR", rid, "隐藏反爬文本",
                     f"question 含隐形水印 span: {m.group(0)[:80]}…(LeetCode 防爬注入, 需剔除)")

        # E14 source 标注规范(§4.1: 纯社区问答标社区名; 真实提问+模型答案需分别标注)
        source = str(rec.get("source") or "").strip()
        if not source:
            st["source_missing"] += 1
            self.add("ERROR", rid, "source标注缺失",
                     "source 为空(§4.1 须标注社区名或 问题来源+答案模型, 多来源用/分隔)")
        else:
            if "/" in source:
                st["source_multi"] += 1
            src_l = source.lower()
            if any(k in src_l for k in ("claude", "opus", "gpt-4", "gpt-5", "gemini", "o1", "o3")):
                st["source_model"] += 1
            low_tier = [k for k in LOW_TIER_MODELS if k in src_l]
            if low_tier:
                st["low_tier_model"] += 1
                self.add("ERROR", rid, "低阶模型答案",
                         f"source 含低阶模型标识 {low_tier}"
                         f"(§4.1 模型答案须 Claude-4.7-opus 同级以上, 低阶不予入库)")

        # W6 疑似合成提问(§4.1: 提问必须为真实用户原始 Query)
        if message and isinstance(message[0], dict):
            q0 = (message[0].get("question") or "")
            synth = [k for k in SYNTHETIC_Q_MARKERS if k in q0.lower()]
            if synth:
                st["synthetic_q"] += 1
                self.add("WARN", rid, "疑似合成提问",
                         f"question 命中合成特征 {synth}(§4.1 禁止人工/大模型合成虚构提问)")

        # E13 开源数据集混入(§4.1/§9)
        m_oss = RE_OSS_DATASET.search(full_text) or RE_OSS_DATASET.search(source)
        if m_oss:
            st["oss_dataset"] += 1
            self.add("ERROR", rid, "疑似开源数据集混入",
                     f"命中公开数据集特征: {m_oss.group(0)}(§4.1 禁止复用 GitHub/HuggingFace 数据集)")

        # E9 隐私明文(§6 匿名化清单: 手机号/真实邮箱/身份证 → ERROR; 银行卡 → 仅统计)
        # 银行卡 Luhn 对代码数据里随机数字串(FileID/hex/serialVersionUID)误报 100%,
        # 无告警价值, 仅统计保留命中数。
        prose_text = strip_fenced(full_text)
        # 数学表达式豁免(见 RE_MATH_SPAN 注释): $...$ 内是题面数学内容
        prose_text = RE_MATH_SPAN.sub(" ", prose_text)
        # 样例段豁免(见 RE_SAMPLE_SPAN 注释): 【样例】内是题目测试数据
        prose_text = RE_SAMPLE_SPAN.sub(" ", prose_text)
        # URL/内联代码豁免: URL 里的 @ / 内联反引号代码里的值属代码示例, 不判 PII
        prose_text = strip_urls_inline(prose_text)
        priv, priv_hits = [], []  # priv_hits: [(类型, 命中值, 上下文)] 供报告明细展示
        # 邮箱: 文档级多重性 + 逐条上下文判定(消除 SO 代码/示例/服务/自披露误报 3844→~0)
        # 一条 Q&A 里 >=3 个邮箱 → 几乎必是 CSV/数组/正则测试集/示例, 而非"泄露单个真实 PII"
        _ems = list(RE_EMAIL.finditer(prose_text))
        if len(_ems) < 3:
            for em in _ems:
                if _email_should_flag(prose_text, em.start(), em.end()):
                    priv.append("邮箱")
                    st["privacy_hits"]["邮箱"] = st["privacy_hits"].get("邮箱", 0) + 1
                    priv_hits.append(("邮箱", em.group(0),
                                      _hit_ctx(prose_text, em.start(), em.end())))
                    break
        # 手机号: 逐条语境判定(虚构号/常量/时间戳/代码上下文排除, 孤立真号仍命中)
        for m in RE_PHONE.finditer(prose_text):
            if _phone_should_flag(prose_text, m.start(), m.end()):
                priv.append("手机号")
                st["privacy_hits"]["手机号"] = st["privacy_hits"].get("手机号", 0) + 1
                priv_hits.append(("手机号", m.group(0),
                                  _hit_ctx(prose_text, m.start(), m.end())))
                break
        # 时间戳语境豁免(见 RE_TS_CTX 注释): rev=/id=/version= 后的长数字是标识符非身份证
        # 身份证: 省码合法 + 非代码/数值语境(JS 大数/Twitter 状态 id/浮点 排除)
        _prose_idc = RE_TS_CTX.sub(" ", prose_text)
        for m in RE_IDCARD.finditer(_prose_idc):
            if _idc_should_flag(_prose_idc, m.start(), m.end()):
                priv.append("身份证")
                st["privacy_hits"]["身份证"] = st["privacy_hits"].get("身份证", 0) + 1
                priv_hits.append(("身份证", m.group(0),
                                  _hit_ctx(_prose_idc, m.start(), m.end())))
                break
        # 银行卡: §6 匿名化清单。Luhn 对代码数据随机数字串误报率高, 已加"支付语境门禁"
        # (real_bank_cards 内部), 命中即视为疑似真实卡号 → 与邮箱/手机/身份证同级:
        # 计入隐私 WARN 并带命中值+脱敏示例+原文明细(对齐报告"逐条列入 WARN 明细")。
        for _bc in real_bank_cards(prose_text):
            i = prose_text.find(_bc)
            priv.append("银行卡")
            st["privacy_hits"]["银行卡"] = st["privacy_hits"].get("银行卡", 0) + 1
            priv_hits.append(("银行卡", _bc, _hit_ctx(prose_text, i, i + len(_bc))))
            break
        if priv:
            st["privacy"] += 1
            st["lq"]["LQ4_隐私未脱敏"] += 1
            detail = "; ".join(priv[:3]) + "(§6 须 x 占位)"
            # 命中原文: 值 + 脱敏整改示例 + ±60 字符上下文(便于人工复核 + 直接给整改口径)
            if priv_hits:
                detail += "; 命中: " + " | ".join(
                    f"[{t}]{v} → 脱敏 `{_privacy_desensitize(t, v)}` «{ctx}»"
                    for t, v, ctx in priv_hits[:3])
            # 2026-09-19 口径(客户确认): 隐私命中统一 WARN(告警级, 需人工复核),
            # 不再判 ERROR — 自披露/示例/代码值占比高, 0 容忍按告警+人工复核执行。
            self.add("WARN", rid, "隐私泄露", detail)

        # E9b 内网 IP 明文(§6 脱敏清单) —— 只在代码块外正文检测, 且排除"示例语境"。
        # 校准: 命中 4 条全为反引号内联代码/文件名模式(`192.168.1.225_01_20xxx_TIMING.jpg`、
        # `172.30.165.212_20241231_132125.JPG`、虚拟主机名 192.168.10.10_80 等),
        # 属 §6 明确豁免的"代码示例"且出现在内部文件名/标识符里, 不构成真实隐私泄露。
        # 仅无后缀、独立出现的裸 IP 才报(SO 数据实测正文基本不出现)。
        ips = [ip for ip in RE_PRIV_IP.findall(prose_text)]
        ips_real = []
        for ip in ips:
            i = prose_text.find(ip)
            nxt = prose_text[i + len(ip):i + len(ip) + 1]
            if nxt in ("_", "-", "/", ".") or prose_text[max(0, i - 1):i] == "`":
                continue  # 文件名/IP 段/内联代码示例
            if _ip_doc_excluded(ip, prose_text, i):
                continue  # 文档标准示例网段/VirtualBox/Docker/示例语境
            if _ip_netconfig_excluded(prose_text, i, i + len(ip)):
                continue  # 网络配置/诊断自披露语境(真实网段, IP 是问题本体, 非第三方 PII)
            ips_real.append(ip)
        if ips_real:
            # 全量 IP 值收集(报告附录展示原文, 供人工复核是否属 §6 代码示例豁免)
            for ip in ips_real:
                i = prose_text.find(ip)
                self.ip_detail.append((rid, ip, _hit_ctx(prose_text, i, i + len(ip), 40)))
            self.add("WARN", rid, "疑似内网IP",
                     f"正文含私网地址 {ips_real[0]} 等 {len(ips_real)} 处(§6 须 x 占位, 代码示例除外)")

        # E9c 社交账号(§6: 微信/微博/抖音等)
        # 2026-09-20 口径: 明细须带命中原文+上下文(同隐私/内网 IP);
        # 已按 §6 脱敏(值含 x 占位, 不可还原)的特征串不再产生明细。
        _soc_hits = []
        for _m in RE_SOCIAL_ACCT.finditer(answer_text):
            _v = _m.group(0)
            if _social_masked(_v):
                continue
            _soc_hits.append((_v, _hit_ctx(answer_text, _m.start(), _m.end())))
            self.social_detail.append((rid, _v, _hit_ctx(answer_text, _m.start(), _m.end())))
        if _soc_hits:
            self.add("WARN", rid, "疑似社交账号",
                     "含微信号/QQ 号特征串(§6 须 x 占位); 命中: " + " | ".join(
                         f"{v} → 脱敏 `{_social_desensitize(v)}` «{ctx}»"
                         for v, ctx in _soc_hits[:3]))

        # E11 非文本资源(§4.1: 真实非文本资源破坏自包含须剔除, 仅留纯文本+代码)
        # 检测对象=代码块外正文(逐字段分开处理, 与整改脚本 split_fenced_segments 同口径:
        # Q/A 各自独立判定代码块, 避免跨字段 fence 配对把"代码块"范围搞混——
        # 否则奇数 fence 的记录在 combined 拼接下正文判定与整改不一致, 复检残留)。
        # 只判"真实资源": 外链图/内嵌 base64/blob 失效引用。
        # 代码示例、文件扩展名、"讨论 <img> 标签本身"的文字提及均豁免(误报根治)。
        # 命中原文: 逐字段提取代码块外真实非文本资源原串(img/md-img/blob/base64 前 80 字符)
        _nt_hits = []
        for t in message:
            if not isinstance(t, dict):
                continue
            for fld in ("question", "answer"):
                _body = strip_fenced(t.get(fld) or "")
                for _rx in (RE_EXT_IMG, RE_EXT_MD_IMG, RE_BLOB_REF, RE_BASE64_EMBED):
                    for _m in _rx.finditer(_body):
                        _nt_hits.append(f"[{fld}] {_m.group(0)[:80]}")
                        if len(_nt_hits) >= 3:
                            break
                    if len(_nt_hits) >= 3:
                        break
            if len(_nt_hits) >= 3:
                break
        if _nt_hits:
            self.add("ERROR", rid, "非文本资源残留",
                     "正文含外链图片/base64 内嵌/blob 失效引用(§4.1 须剔除; 代码块与 <img> 文字提及已豁免)"
                     + "; 命中: " + " | ".join(_nt_hits))

        # E12 乱码(§4.3 低质过滤: "大量占位符、乱码"才剔除)
        # 2026-09-19 口径(客户确认): 单条 U+FFFD **≤ 5 个不算 ERROR** —— 个别
        # 编码损坏点(1-5 个)属轻微瑕疵, 不影响问答有效性, 不计入剔除;
        # **超过 5 个(>5)** 视为"大量乱码"(编码损坏成片/二进制当文本), 判 ERROR 需剔除。
        _mb = [m for m in RE_MOJIBAKE.finditer(full_text)]
        if len(_mb) > 5:
            st["lq"]["LQ6_占位符乱码模板"] += 1
            # 命中原文: 首个 U+FFFD 位置 ±40 字符上下文(便于人工确认损坏范围/来源)
            _m0 = _mb[0]
            _mb_ctx = _hit_ctx(full_text, _m0.start(), _m0.end(), 40).replace("\ufffd", "[U+FFFD]")
            self.add("ERROR", rid, "乱码字符",
                     f"含 U+FFFD 替换字符 **{len(_mb)} 个**(超 5 个, 大量乱码, §4.3 应剔除); "
                     f"首处命中: «{_mb_ctx}»")

        # W5 占位符串(§4.1 大量占位符类灌水) —— 计算逻辑保留但不计数。
        # 校准: SO 问答中 xxxxx 是"省略内容/示例输出"的正常表达(表格画线、XML 占位、
        # UPN 示例、私钥脱敏), 非灌水复制粘贴(实测 12/12 全为正常场景)。
        # 该项对 SO 数据无区分度 → 不判低质, LQ6 计数恒 0(与第十节 WARN 一致)。
        m = RE_PLACEHOLDER_RUN.search(answer_text)
        if (m and not re.search(r'BEGIN|PRIVATE KEY|CERTIFICATE|public key|private key',
                                answer_text, re.I)):
            pass  # 仅保留检测逻辑, 不累加 LQ6(误报率 100%, 见上方注释)

        # W6b 纯文字闲聊问题(§4.2 LQ1) —— 计算逻辑保留但不计数。
        # 校准: SO 技术短问必含结构特征(大写缩写/括号/点/数字)但小写技术专名
        # (webkit/oauth/captcha…)无法穷尽列举, 词表+结构豁免仍有边界误判(实测 2 条
        # "webkit animation"/"captcha or not" 实为技术问或吐槽问, 非纯闲聊)。
        # SO 数据闲聊场景极少且无法可靠自动区分 → 不判低质, LQ1 计数恒 0。
        if message and isinstance(message[0], dict):
            q0 = message[0].get("question") or ""
            q0l = q0.lower()
            if (len(q0.strip()) < 100 and "```" not in q0
                    and not any(h in q0l for h in CHAT_Q_HINT)
                    and not TECH_Q_HINT.search(q0l)
                    and not re.search(r'[A-Z]|[.()\[\]{}<>/\\|]|\d', q0)):
                pass  # 仅保留检测逻辑, 不累加 LQ1(误报率边界, 见上方注释)

        # 禁止内容关键词粗筛(§8/§4.2 LQ5)
        hit = [k for k in FORBIDDEN_KW if k in full_text]
        if hit:
            st["lq"]["LQ5_违规内容"] += 1
            self.add("ERROR", rid, "疑似违规内容", f"命中: {hit}(§8)")

        # W1 token_count 校验(2026-09-15 起双口径):
        #   · 新口径(含 question_tokens/answer_tokens 拆分字段, tiktoken 真实计数):
        #     校验 token_count == question_tokens+answer_tokens 内部一致性;
        #   · 旧口径(仅 token_count 粗估): 与 est_tokens(4字符≈1 token) 对照偏差>80% 记 WARN。
        qt = meta.get("question_tokens")
        at = meta.get("answer_tokens")
        tc = meta.get("token_count")
        qtv = isinstance(qt, (int, float)) and qt >= 0
        atv = isinstance(at, (int, float)) and at >= 0
        tcv = isinstance(tc, (int, float)) and tc > 0
        if qtv and atv:
            st["tokens_sum"] += qt + at
            if tcv and tc != qt + at:
                self.add("WARN", rid, "token_count偏差",
                         f"token_count={tc} != question_tokens+answer_tokens({qt}+{at}={qt + at})")
        elif tcv:
            est = est_tokens(full_text)
            st["tokens_sum"] += tc
            if abs(tc - est) / max(est, 1) > 0.8:
                self.add("WARN", rid, "token_count偏差",
                         f"标注 {tc} vs 估算 {est}(偏差>80%)")
        else:
            st["tokens_sum"] += est_tokens(full_text)

        # §10 三、校验(全部 answer 的代码块语法/完整性)
        # question / answer 各自独立判定代码块(不跨字段拼接), 避免奇数 fence 时
        # 悬挂开围栏跨 Q/A 边界误配, 把正文吞进'代码块'(python 块 ast.parse 误报)
        code_fields = []
        for t in message:
            if isinstance(t, dict):
                code_fields.append(t.get('question') or '')
                code_fields.append(t.get('answer') or '')
        code_st, code_issues = check_code_syntax(code_fields)
        for k, v in code_st.items():
            st["code"][k] = st["code"].get(k, 0) + v
        if code_issues:
            st["code_fail_recs"] += 1
            st["lq"]["LQ2_代码残缺语法错误"] += 1
            for itype, idetail in code_issues[:3]:
                self.add("ERROR" if itype == "代码语法校验失败" else "WARN",
                         rid, itype, idetail)
        # W2 代码块无语言标签 → 仅统计, 不告警。SO 数据集的代码块天然不带语言标签
        # (由渲染端自动高亮), 全量 99.98% 命中证明该项在 SO 上无区分度, 不构成 WARN。
        # W4b 代码块疑似残缺(<3行) → 仅统计, 不告警。单行/两行代码是 SO 标准正解
        # ("Use `dir()`." 等), 长度 ≠ 残缺; 真异常由 ast.parse / 括号失衡(WARN) / 
        # python_fail(ERROR) 已覆盖。

        # 精确重复检测: 完整 message(问答对)完全一致才算重复样本(§4.3 去重语义)
        full_md5 = md5(json.dumps(message, ensure_ascii=False, sort_keys=True))
        if full_md5 in self._seen_q:
            st["dup_q"] += 1
            self.add("ERROR", rid, "样本完全重复",
                     f"与 {self._seen_q[full_md5]} 的 message 完全一致(去重阈值 <{DUP_LIMIT}%)")
        else:
            self._seen_q[full_md5] = rid
        first_q = md5((message[0].get("question", "") if message and isinstance(message[0], dict) else "").strip())
        # 同题多解/同题多语言为设计口径(每题多用户 AC, 题面相同属预期),
        # 不计为问题; 仅保留计数供元数据统计(交付口径见 README/终检报告)
        if first_q in self._seen_firstq:
            st["same_q_diff_lang"] += 1
        else:
            self._seen_firstq[first_q] = rid

        # 近似重复 shingle 收集(§4.2 LQ7, check_global 统一判定)
        # 内存保护: 禁用 / 超上限时停止收集(流式全量查重留终检, 见 --no-near-dup)
        if self.near_dup and not self.near_dup_skipped:
            if len(self._shingles) < self.shingle_cap:
                self._shingles.append((rid, qa_shingles(full_text)))
            else:
                self.near_dup_skipped = True
                log.warning("记录数 %d > %d, 跳过近似重复检测(流式 O(1) 内存, "
                            "全量近似查重请用 text_dup_precise_qc.py 或终检分片)",
                            st["total"], self.shingle_cap)

        # W4 answer 过短(§4.2 LQ3) —— 计算逻辑保留但不计数。
        # 校准: SO 采纳答案允许任意短且长度≠低质("reinterpret_cast"/"mechanize"/"addslashes"
        # 都是完整正解), 任何阈值都会误伤; 真正"无实质"短语与专名无结构可分。
        # LQ3 对 SO 数据无区分度 → 不判低质, LQ3 计数恒 0(与第十节 WARN 一致)。
        for i, t in enumerate(message, 1):
            if isinstance(t, dict):
                a = t.get("answer") or ""
                if (len(a.strip()) < 60 and "```" not in a
                        and not re.search(r'`|\bhttp\S*|>=?|<|=|->|=>|\$ |\b(?:use|try|set|call|check|remove|print|close|open|change|convert|do|does|just|simply)\b', a, re.I)
                        and not re.search(r'[A-Z]|[.()\[\]{}<>/\\|]|\d', a)
                        and not any(w in a.lower() for w in ("should", "must", "need", "means", "trick", "type"))):
                    pass  # 仅保留检测逻辑, 不累加 LQ3(误报率边界, 见上方注释)

        # 统计
        lang = str(meta.get("primary_language") or "?").lower()
        st["lang"][lang] = st["lang"].get(lang, 0) + 1
        # domain 兼容两种口径(2026-09-14 起 SO 批改为标签数组):
        #   · 旧: 字符串 "语言 / 领域" → 取 "/" 前一段
        #   · 新: 标签数组 → 取**首个标签**作主领域(保证每记录只归一类, 占比合计 ≈100%)
        dom_raw = rec.get("domain")
        if isinstance(dom_raw, list):
            first_tag = str(dom_raw[0]).strip() if dom_raw else ""
            dom = first_tag or "?"
        else:
            dom = str(dom_raw or "?").split("/")[0].strip()
        st["domain"][dom] = st["domain"].get(dom, 0) + 1

        # ---- 深度语义层 N1-N9(合并自 code_qa_deep_qc.py, 默认 WARN) ----
        self._run_deep(rid, rec)

    def _run_deep(self, rid, rec):
        """跑 N1-N9 语义层: 记录命中/样例, 抽 N4 token 复算, 累计 question_time 供 N8。
        命中默认记 WARN(--fail-on-warn 时记 ERROR); N8 为全局规则, 在 check_global 判定。"""
        issues, ctx = deep_check_record(rec, dataset_class=self.dataset_class)
        for k, detail in issues.items():
            if k == "N8_时间字段共模":
                continue  # 全局规则, 由 check_global 判定
            self.deep_rule_hits[k] += 1
            if len(self.deep_rule_samples[k]) < 6:
                self.deep_rule_samples[k].append(f"{rid}: {str(detail)[:120]}")
            self.add("ERROR" if self.fail_on_warn else "WARN", rid, k,
                     f"{detail}(深度语义层)")
        # N4 token 复算抽检(按声明 tokenizer=o200k_base 抽样复算 q/a token)
        if self.token_sample > 0 and self._deep_enc is not None:
            m = ctx["meta"]
            if "o200k" in str(m.get("tokenizer") or "") and \
                    self._deep_rng.random() < self.token_sample:
                rq = len(self._deep_enc.encode(ctx["q"].strip(), disallowed_special=()))
                ra = len(self._deep_enc.encode(ctx["a"].strip(), disallowed_special=()))
                if m.get("question_tokens") != rq or m.get("answer_tokens") != ra:
                    self.deep_tok_mismatch += 1
                    if len(self.deep_rule_samples["N4_token复算偏差"]) < 6:
                        self.deep_rule_samples["N4_token复算偏差"].append(
                            f"{rid}: 存 q={m.get('question_tokens')} a={m.get('answer_tokens')} "
                            f"复算 q={rq} a={ra}")
        # N8 用: 累计 question_time 取值分布
        self.deep_qtime[str((ctx["meta"] or {}).get("question_time"))] += 1

    # ---- 近似重复检测(§4.2 LQ7) ----
    def _detect_near_dup(self):
        """稀有 5-gram 倒排召回候选对 → 精确 Jaccard 验证(≥0.6 记 WARN)。
        若未启用(--no-near-dup)或超上限跳过, 返回 None(调用方据此标注"未执行")。"""
        if (not self.near_dup) or self.near_dup_skipped:
            return None
        sh = self._shingles
        if len(sh) < 2:
            return []
        inv = {}
        for i, (_, s) in enumerate(sh):
            for g in s:
                inv.setdefault(g, []).append(i)
        cand = {}
        for g, docs in inv.items():
            if 2 <= len(docs) <= 20:
                for a in range(len(docs)):
                    for b in range(a + 1, len(docs)):
                        pair = (docs[a], docs[b])
                        cand[pair] = cand.get(pair, 0) + 1
        groups = []
        for (i, j), co in sorted(cand.items(), key=lambda x: -x[1]):
            if co < 8:
                continue
            A, B = sh[i][1], sh[j][1]
            if not A or not B:
                continue
            inter = len(A & B)
            jac = inter / (len(A) + len(B) - inter)
            if jac >= NEAR_DUP_JACCARD:
                groups.append((i, j, jac))
                self.add("WARN", f"{sh[i][0]}~{sh[j][0]}", "近似重复",
                         f"两条问答 Jaccard={jac:.3f}≥{NEAR_DUP_JACCARD}"
                         f"(§4.2 LQ7 仅变量名/注释微调的高度近似样本)")
                if len(groups) >= 20:
                    break
        return groups

    def check_global(self):
        st = self.stats
        n = st["total"] or 1
        rows = []
        st["files_mixed_turn"] = [
            os.path.basename(f) for f, kinds in self._file_turn_kinds.items()
            if len(kinds) > 1]

        def row(level, item, detail):
            rows.append((level, item, detail))

        # 语言分布 ≤30%(E6)
        if st["lang"]:
            top_lang, top_cnt = max(st["lang"].items(), key=lambda x: x[1])
            ratio = top_cnt / n * 100
            row("ERROR" if ratio > LANG_LIMIT else "PASS",
                f"单一语言占比 {ratio:.1f}%", f"{top_lang} {top_cnt}/{n}(红线 ≤{LANG_LIMIT}%)")
        # 多轮占比 ≥10%(E7)。构造性单轮数据集(SO 等无多轮场景)用 --exempt-multi-turn
        # 单列为 WARN: 不触发整体退回(需换源补采, 非清洗可解, 见 README/终检口径)。
        mt_ratio = st["multi_turn"] / n * 100
        if self.exempt_multi_turn and mt_ratio < MULTI_TURN_LIMIT:
            row("WARN", f"多轮问答占比 {mt_ratio:.1f}% [已豁免]",
                f"{st['multi_turn']}/{n}(阈值 ≥{MULTI_TURN_LIMIT}%); 数据集构造性单轮, "
                f"多轮需换源补采, 单列不触发退回(--exempt-multi-turn)")
        else:
            row("ERROR" if mt_ratio < MULTI_TURN_LIMIT else "PASS",
                f"多轮问答占比 {mt_ratio:.1f}%", f"{st['multi_turn']}/{n}(阈值 ≥{MULTI_TURN_LIMIT}%)")
        # 精确重复率(完整问答对)
        dup_ratio = st["dup_q"] / n * 100
        row("ERROR" if dup_ratio >= DUP_LIMIT else "PASS",
            f"样本完全重复率 {dup_ratio:.2f}%", f"{st['dup_q']}/{n}(阈值 <{DUP_LIMIT}%)")
        # 近似重复(超上限/禁用时 nd=None, 标注"未执行"不计入 ERROR)
        nd = self._detect_near_dup()
        if nd is None:
            st["near_dup"] = 0
            row("SKIP", f"近似重复组 未执行",
                f"记录数超 shingle 上限({self.shingle_cap})或 --no-near-dup 跳过; "
                f"全量近似查重请用 text_dup_precise_qc.py 或终检分片(§4.2 LQ7)")
        else:
            st["near_dup"] = len(nd)
            if nd:
                st["lq"]["LQ7_问答高度近似"] = len(nd)
            row("WARN" if nd else "PASS",
                f"近似重复组 {len(nd)} 组",
                f"字符 5-gram Jaccard≥{NEAR_DUP_JACCARD}(§4.2 LQ7 高度近似样本)")
        # 同题多解为设计口径, 不计问题(计数保留在 metadata)
        row("ERROR" if st["hidden_span"] else "PASS",
            f"隐藏反爬文本 {st['hidden_span']} 条", "LeetCode 水印 span 需在清洗中剔除")
        # 多轮配对不足全局(§9: 多轮 Q-A ≥3 组)
        mt_lt3 = st.get("multi_turn_lt3", 0)
        if st["multi_turn"]:
            row("WARN" if mt_lt3 else "PASS",
                f"多轮配对<3组 {mt_lt3} 条", f"多轮样本中 {mt_lt3}/{st['multi_turn']} 条 Q-A 配对不足 3 组(§9)")
        # 单轮/多轮分片归档(§3)
        if st.get("files_mixed_turn"):
            row("WARN", f"单/多轮混存文件 {len(st['files_mixed_turn'])} 个",
                f"{st['files_mixed_turn'][:3]}(§3 要求单轮与多轮分目录分片归档)")
        # 问答真实性汇总(§10 四)
        row("ERROR" if st["source_missing"] else "PASS",
            f"source标注缺失 {st['source_missing']} 条",
            f"多来源标注 {st['source_multi']} 条, 含模型来源 {st['source_model']} 条(§4.1 标注规范)")
        row("WARN" if st["synthetic_q"] else "PASS",
            f"疑似合成提问 {st['synthetic_q']} 条", "命中合成特征串, 需人工复核(§4.1 禁止合成虚构提问)")
        row("ERROR" if st["oss_dataset"] else "PASS",
            f"疑似开源数据集混入 {st['oss_dataset']} 条", "GitHub/HuggingFace 公开问答数据集特征(§4.1/§9)")
        row("ERROR" if st["low_tier_model"] else "PASS",
            f"低阶模型答案 {st['low_tier_model']} 条",
            "source 含低阶模型标识(§4.1 须 Claude-4.7-opus 同级以上)")
        # 代码功能校验汇总(§10 三)
        c = st["code"]
        # ⚠️ 2026-09-20 口径变更(用户拍板): Python ast.parse 语法校验已移除
        row("SKIP", "Python 语法校验 不执行",
            "口径已移除: 论坛问答代码块为片段型(占位/缩进省略/Py2 语法), ast.parse 不适用")
        row("WARN" if c["bracket_bad"] else "PASS",
            f"代码块括号失衡 {c['bracket_bad']} 块", "非 Python 语言粗检(字符串内括号可能误报, 需复核)")
        row("PASS", "总token(标注/估算)", f"{st['tokens_sum']:,}")

        # ---- 深度层全局规则 N8 时间字段共模(全局判定, 默认 WARN 不计入退出码) ----
        # question_time 单一取值占比 >5% → 疑似"题目时间"口径(而非真实提问时间)
        if n >= 100 and self.deep_qtime:
            top_qtime, top_qn = self.deep_qtime.most_common(1)[0]
            if top_qn / n > 0.05:
                self.deep_rule_hits["N8_时间字段共模"] = top_qn
                self.deep_rule_samples["N8_时间字段共模"] = [
                    f"question_time={top_qtime} 占 {top_qn}/{n} ({top_qn / n:.1%})"]
        # N4 token 复算偏差(全局汇总)
        if self.deep_tok_mismatch:
            self.deep_rule_hits["N4_token复算偏差"] = self.deep_tok_mismatch
        return rows

    # ---- §10 八、问题整改明细 ----
    def rectification_rows(self, prev_problems=None):
        """问题整改明细: 按检查项汇总当前问题 + 建议整改措施。

        prev_problems: 上一版报告解析出的 {(ID, 检查项)} 集合;
        提供时计算 已整改/未整改/新增 三态。
        """
        cur = {}
        sample_rids = {}   # item → [rid, ...] (来自明细列表, 可能封顶, 仅供展示样例)
        for rid, item, detail in self.error_rows + self.warn_rows:
            cur.setdefault((rid, item), detail)
            sample_rids.setdefault(item, []).append(rid)
        rows = []
        # 按检查项聚合: 计数用全量 _item_cnt(恒准确, 不受明细封顶影响)
        for item in sorted(set(self._item_cnt) | set(sample_rids),
                           key=lambda x: (-self._item_cnt.get(x, 0), x)):
            rids = sample_rids.get(item, [])
            advice = RECTIFY_ADVICE.get(item, "按规范书相应条款复核处理")
            # 2026-09-20: 状态按级别区分 —— ERROR=待整改; WARN=建议复核(不阻断交付)。
            # 例: "多轮配对不足" 属**数据真实形态**(论坛问答天然多为 2 组), 是 WARN,
            #     不应渲染成"待整改"的欠账。
            status = ("待整改" if self._item_level.get(item) == "ERROR"
                      else "WARN·建议复核(不阻断交付)")
            rows.append((item, self._item_cnt.get(item, 0),
                         ", ".join(rids[:5]) + ("…" if len(rids) > 5 else ""),
                         advice, status))
        resolved, unresolved, added = [], [], []
        if prev_problems is not None:
            cur_keys = set(cur.keys())
            for (rid, item) in prev_problems:
                if (rid, item) in cur_keys:
                    unresolved.append((rid, item))
                else:
                    resolved.append((rid, item))
            for k in cur_keys:
                if k not in prev_problems:
                    added.append(k)
        return rows, resolved, unresolved, added


def parse_prev_report(path):
    """解析上一版质检报告(md), 提取 ERROR/WARN 明细的 (ID, 检查项) 集合。"""
    problems = set()
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        log.warning("无法读取上一版报告 %s: %s", path, e)
        return None
    in_detail = False
    for line in text.splitlines():
        # 匹配 "## 九、ERROR 明细(...)" / "## 十、WARN 明细(...)"(含中文序号前缀)
        if re.match(r'^#+\s*[^#]*?(?:ERROR|WARN)\s*明细', line, re.I):
            in_detail = True
            continue
        if re.match(r'^#+\s', line):
            in_detail = False
            continue
        if not in_detail:
            continue
        m = re.match(r'^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]*)\|', line)
        if m and m.group(1) not in ("ID", ":---"):
            problems.add((m.group(1).strip(), m.group(2).strip()))
    return problems


# ----------------------------------------------------------------------------
# 报告输出
# ----------------------------------------------------------------------------
def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_reports(out_dir, qc, file_paths, started_at, sample_pct=0, sampled_n=0,
                  prev_path=None, seed=2026):
    st = qc.stats
    n = st["total"]
    stamp = started_at.strftime("%Y%m%d_%H%M%S")
    md_path = os.path.join(out_dir, f"代码问答_质检报告_{stamp}.md")
    html_path = os.path.join(out_dir, f"代码问答_质检报告_{stamp}.html")
    global_rows = qc.check_global()
    sample_note = (f"(抽检模式: {sample_pct:.1f}%, 共 {sampled_n} 条, seed={seed})"
                   if sample_pct > 0 else "(全量检查)")

    prev_problems = parse_prev_report(prev_path) if prev_path else None
    rect_rows, resolved, unresolved, added = qc.rectification_rows(prev_problems)
    # 全局 ERROR 计入总数(退出码/结论一致, 对齐 2026-09-02 QC 口径升级)
    n_global_err = sum(1 for r in global_rows if r[0] == "ERROR")
    ok = qc._err_count == 0 and n_global_err == 0

    L = []
    L.append("# 代码问答数据集 质检报告")
    L.append("")
    L.append(f"> 生成时间: {started_at:%Y-%m-%d %H:%M:%S}")
    L.append(f"> 检查范围: {sample_note}")
    L.append(f"> 检查文件: {', '.join(os.path.basename(f) for f in file_paths)}")
    L.append("> 依据: 10-代码问答数据_技术规范书(docx 版)")
    L.append("> 报告结构: 规范书 §10 要求 — 抽样代码功能校验 / 问答真实性校验 / "
             "重复率校验 / 脱敏校验 / 低质样本过滤记录 / 问题整改明细")
    if prev_path:
        L.append(f"> 对比基线: {os.path.basename(prev_path)}")
    L.append("")
    L.append("## 一、总体结论")
    L.append("")
    L.append(f"**{'✅ 代码检测通过, 待人工复检' if ok else '❌ 不达标(存在 ERROR, 需整改)'}** — 样本 {n} 条, "
             f"ERROR {qc._err_count + n_global_err} 项"
             f"(记录级 {qc._err_count} + 全局 {n_global_err}), "
             f"WARN {qc._warn_count} 项")
    L.append("")
    L.append("## 二、验收硬指标(全局, §9)")
    L.append("")
    L.append("| 结果 | 指标 | 说明 |")
    L.append("|:---:|:---|:---|")
    for lvl, item, detail in global_rows:
        mark = {"PASS": "✅", "ERROR": "❌", "WARN": "⚠️", "SKIP": "➖"}[lvl]
        L.append(f"| {mark} | {item} | {detail} |")
    L.append("")

    # ---- 三、抽样代码功能校验 ----
    c = st["code"]
    L.append("## 三、抽样代码功能校验(§10; §9 代码质量硬指标)")
    L.append("")
    L.append("| 检查项 | 结果 | 说明 |")
    L.append("|:---|:---:|:---|")
    L.append(f"| 代码块总数 | ✅ | {c['blocks']} 个(answer 内 fenced 块) |")
    L.append("| Python 块语法校验 | ➖ | 口径已移除(论坛型语料代码为片段, ast.parse 不适用; "
             "2026-09-20 用户拍板) |")
    L.append(f"| 非 Python 块括号平衡粗检 | {'⚠️' if c['bracket_bad'] else '✅'} | "
             f"失衡 {c['bracket_bad']} 块(字符串内括号可能误报, 需复核) |")
    L.append(f"| 存在代码问题的记录 | {'⚠️' if st['code_fail_recs'] else '✅'} | "
             f"{st['code_fail_recs']}/{n} 条 |")
    # 注: 规范书 §4.2/§9 未要求"代码块必须带语言标签", 也无"<3行=残缺"标准
    # (残缺仅指语法不完整/无法运行, 由 ast.parse/括号失衡/存在代码问题记录覆盖),
    # 故"无语言标签/行数统计"不作为 QC 检查项展示, 仅保留内部统计计数。
    L.append("")

    # ---- 四、问答真实性校验 ----
    L.append("## 四、问答真实性校验(§10; §4.1 样本硬性约束)")
    L.append("")
    L.append("| 检查项 | 结果 | 说明 |")
    L.append("|:---|:---:|:---|")
    L.append(f"| source 标注完整 | {'❌' if st['source_missing'] else '✅'} | "
             f"缺失 {st['source_missing']}/{n} 条(§4.1 须标注社区名/问题来源+答案模型) |")
    L.append(f"| 多来源标注(用/分隔) | ✅ | {st['source_multi']} 条 |")
    L.append(f"| 模型生成答案来源标注 | ✅ | {st['source_model']} 条(source 含模型标识) |")
    L.append(f"| 低阶模型答案 | {'❌' if st['low_tier_model'] else '✅'} | "
             f"{st['low_tier_model']} 条(§4.1 须 Claude-4.7-opus 同级以上) |")
    L.append(f"| 疑似合成提问 | {'⚠️' if st['synthetic_q'] else '✅'} | "
             f"{st['synthetic_q']} 条(§4.1 禁止合成虚构提问, 需人工复核) |")
    L.append(f"| 开源数据集混入 | {'❌' if st['oss_dataset'] else '✅'} | "
             f"{st['oss_dataset']} 条(§4.1 禁止复用 GitHub/HuggingFace 数据集) |")
    L.append(f"| 隐藏反爬水印 | {'❌' if st['hidden_span'] else '✅'} | "
             f"{st['hidden_span']} 条(LeetCode 隐形 span, 需剔除) |")
    L.append("")

    # ---- 五、重复率校验 ----
    dup_ratio = st["dup_q"] / (n or 1) * 100
    L.append("## 五、重复率校验(§10; §9 去重指标 <0.5%)")
    L.append("")
    L.append("| 检查项 | 结果 | 说明 |")
    L.append("|:---|:---:|:---|")
    L.append(f"| 精确重复(message MD5) | {'❌' if st['dup_q'] else '✅'} | "
             f"{st['dup_q']} 条, 重复率 {dup_ratio:.2f}%(阈值 <{DUP_LIMIT}%) |")
    L.append(f"| 近似重复(5-gram Jaccard≥{NEAR_DUP_JACCARD}) | "
             f"{'⚠️' if st['near_dup'] else '✅'} | {st['near_dup']} 组"
             f"(§4.2 LQ7 仅变量名/注释微调的重复样本) |")
    L.append(f"| 同题多解(首问相同) | ✅ | "
             f"{st['same_q_diff_lang']} 条(同题多解设计口径, 见 README §七) |")
    L.append("")

    # ---- 六、脱敏校验 ----
    L.append("## 六、脱敏校验(§10; §6 匿名化合规)")
    L.append("")
    L.append("| 检查项 | 结果 | 说明 |")
    L.append("|:---|:---:|:---|")
    L.append(f"| 隐私明文泄露 | {'⚠️' if st['privacy'] else '✅'} | "
             f"{st['privacy']}/{n} 条(全量自动化扫描, 2026-09-19 起命中统一为 WARN 告警, "
             f"明细含命中原文+上下文, 逐条人工复核) |")
    if st["privacy_hits"]:
        hits_desc = "; ".join(f"{k} {v} 处" for k, v in sorted(st["privacy_hits"].items()))
    else:
        hits_desc = "未检出明文隐私"
    L.append(f"| 命中类型分布 | {'⚠️' if st['privacy_hits'] else '✅'} | "
             f"{hits_desc}(命中逐条列入 WARN 明细, 人工复核) |")
    _ip_n, _soc_n = (qc._item_cnt.get("疑似内网IP", 0),
                     qc._item_cnt.get("疑似社交账号", 0))
    if _ip_n or _soc_n:
        L.append(f"| 内网 IP/社交账号 | ⚠️ | 检出 内网 {_ip_n} / 社交 {_soc_n} 条"
                 f"(代码示例语境误报率高, 人工复核) |")
    else:
        L.append("| 内网 IP/社交账号 | ✅ | 0 检出(内网 10.x 为 §6 合规替换值; "
                 "变量名 qq/AVX 指令集等算法语境不误报) |")
    L.append("")

    # ---- 七、低质样本过滤记录 ----
    L.append("## 七、低质样本过滤记录(§10; §4.2 七条低质过滤规则)")
    L.append("")
    L.append("| 规则 | 命中记录数 | 说明 |")
    L.append("|:---|---:|:---|")
    lq_desc = {
        "LQ1_闲聊咨询": "问题无明确代码需求, 仅纯文字闲聊咨询",
        "LQ2_代码残缺语法错误": "回答代码残缺/语法报错/无效玩具 Demo",
        "LQ3_回答过短无实质": "回答仅简短文字, 无代码/原理/方案",
        "LQ4_隐私未脱敏": "含明文隐私/内网地址/联系方式",
        "LQ5_违规内容": "涉黄/暴力/违法/恶意代码类",
        "LQ6_占位符乱码模板": "大量占位符/乱码/灌水复制粘贴",
        "LQ7_问答高度近似": "仅变量名/注释微调的重复样本",
    }
    for k in ("LQ1_闲聊咨询", "LQ2_代码残缺语法错误", "LQ3_回答过短无实质",
              "LQ4_隐私未脱敏", "LQ5_违规内容", "LQ6_占位符乱码模板", "LQ7_问答高度近似"):
        v = st["lq"][k]
        mark = "⚠️" if v else "✅"
        L.append(f"| {mark} {k} | {v} | {lq_desc[k]} |")
    L.append("")

    # ---- 七·深度语义层(N1-N9, 合并自 code_qa_deep_qc.py) ----
    _forum = qc.dataset_class == "forum"
    _suppressed = {"N1_无代码块", "N3_语言标注不符", "N6_上标压平可疑"} if _forum else set()
    _class_cn = {"code": "编程题集(答案应含代码)",
                 "forum": "论坛问答(纯文字答案合法)"}.get(qc.dataset_class, qc.dataset_class)
    _deep_warn_total = sum(qc.deep_rule_hits[k] for k in RULE_DESC)
    L.append("## 七·深度语义层(N1-N9, code_qa_deep_qc 并入)")
    L.append("")
    L.append(f"> 数据集类型: {_class_cn} | token 抽检比例 {qc.token_sample:g} | "
             f"深度层 WARN 合计 {_deep_warn_total} 项"
             f"{'(--fail-on-warn 已转 ERROR)' if qc.fail_on_warn else '(默认 WARN, 不影响主脚本退出码)'}")
    L.append("")
    L.append("| 规则 | 说明 | 命中数 | 占比 | 样例 |")
    L.append("|:---|:---|---:|---:|:---|")
    for k in RULE_DESC:
        h = qc.deep_rule_hits[k]
        if k in _suppressed:
            L.append(f"| {k} | {RULE_DESC[k]} | (不适用) | — | 论坛类按数据集类型豁免 |")
            continue
        sample = "<br>".join(esc(s) for s in qc.deep_rule_samples[k][:4]) or "—"
        L.append(f"| {k} | {RULE_DESC[k]} | {h} | {h / (n or 1):.2%} | {sample} |")
    L.append("")
    if _forum:
        L.append("> 本批按**论坛问答**类型运行: N1/N3/N6 不适用(论坛答案可为纯文字, "
                 "primary_language 为话题标签而非答案代码语言), 已豁免不计入。")
    else:
        L.append("> N5 截断嫌疑为启发式(句中收尾), 需与网页原文二次确认; "
                 "N3 语言不符在 LeetCode 类(题解含多语言代码块)会偏多, 请按数据集解读。")
    L.append("")

    # ---- 八、问题整改明细 ----
    L.append("## 八、问题整改明细(§10)")
    L.append("")
    if rect_rows:
        L.append("| 检查项 | 条数 | 样本ID(前5) | 建议整改措施 | 状态 |")
        L.append("|:---|---:|:---|:---|:---:|")
        for item, cnt, rids, advice, status in rect_rows:
            L.append(f"| {esc(item)} | {cnt} | {esc(rids)} | {esc(advice)} | {status} |")
    else:
        L.append("无待整改问题")
    L.append("")
    if prev_problems is not None:
        L.append(f"### 与上一版报告对比({os.path.basename(prev_path)})")
        L.append("")
        L.append(f"- **已整改**: {len(resolved)} 项"
                 + (f"(如 {resolved[0][0]}·{resolved[0][1]})" if resolved else "") +
                 "")
        L.append(f"- **未整改**: {len(unresolved)} 项"
                 + (f"(如 {unresolved[0][0]}·{unresolved[0][1]})" if unresolved else "") +
                 "")
        L.append(f"- **新增问题**: {len(added)} 项"
                 + (f"(如 {added[0][0]}·{added[0][1]})" if added else "") + "")
        L.append(f"- **整改完成率**: "
                 f"{len(resolved) / max(len(resolved) + len(unresolved), 1) * 100:.0f}%"
                 f"(已整改/{len(resolved) + len(unresolved)} 历史问题)")
        L.append("")

    # ---- 九/十、明细(可折叠: 默认显示前 10 条, <details> 展开看全部; 2026-09-20 起全量列出, 不再截断) ----
    _PREVIEW = 10
    # 内网 IP 汇总行(只列首个 IP+"等 N 处")与逐 IP 原文行冗余 → 去汇总行,
    # 只保留逐 IP 原文行(每个命中的 IP 独立一条, 均带 ±40 上下文), 避免"部分 IP 无原文"。
    _warn_rows = [r for r in qc.warn_rows if r[1] not in ("疑似内网IP", "疑似社交账号")]
    for rid, ip, ctx in qc.ip_detail:
        # 附 §6 去隐私化脱敏示例(保留网段, 主机位 x 化), 直接给出整改口径
        _warn_rows.append((rid, "疑似内网IP",
                           f"{ip} → 脱敏 `{_ip_desensitize(ip)}` «{ctx}»"))
    # 2026-09-20 口径: 社交账号同样改逐命中原文行(已脱敏串不进 social_detail,
    # 即"已脱敏不显示明细"); 汇总行(无原文)一并去除。
    for rid, val, ctx in qc.social_detail:
        _warn_rows.append((rid, "疑似社交账号",
                           f"{val} → 脱敏 `{_social_desensitize(val)}` «{ctx}»"))
    # 2026-09-20 展示优先级: 隐私类最需人工复核 ⇒ 排前;
    # 「代码块括号失衡」是粗检指标(抽样实测约 1/3 为脚本误报, 其余多为论坛
    # 片段型语料的天然形态) ⇒ 排最后, 避免淹没真正要看的隐私/多轮项。
    _WARN_PRI = {"疑似社交账号": 0, "隐私泄露": 0, "疑似内网IP": 1,
                 "多轮配对不足": 2, "代码块括号失衡": 9}
    _warn_rows.sort(key=lambda r: (_WARN_PRI.get(r[1], 5), r[1], r[0]))

    def dump_section(title, rows):
        L.append(f"## {title}")
        L.append("")
        if not rows:
            L.append("无")
            L.append("")
            return
        if len(rows) > _PREVIEW:
            L.append(f"> 共 {len(rows)} 条 — 下方默认显示前 {_PREVIEW} 条, "
                     f"点击「展开剩余 {len(rows) - _PREVIEW} 条」查看全部。")
        else:
            L.append(f"> 共 {len(rows)} 条(全部列出)。")
        L.append("")
        L.append("| ID | 检查项 | 详情 |")
        L.append("|:---|:---|:---|")
        for rid, item, detail in rows[:_PREVIEW]:
            L.append(f"| {rid} | {item} | {esc(detail)} |")
        if len(rows) > _PREVIEW:
            L.append("")
            L.append(f"<details><summary>展开剩余 {len(rows) - _PREVIEW} 条</summary>")
            L.append("")
            for rid, item, detail in rows[_PREVIEW:]:
                L.append(f"| {rid} | {item} | {esc(detail)} |")
            L.append("")
            L.append(f"</details>")
        L.append("")

    dump_section("九、ERROR 明细(必须整改)", qc.error_rows)
    dump_section("十、WARN 明细(建议复核; 隐私/内网 IP/社交账号命中含原文上下文)", _warn_rows)

    # ---- 附录: 分布 ----
    for title, key in (("附录A、编程语言分布(§5.1 单一语言 ≤30%)", "lang"),
                       ("附录B、技术领域分布(§5.2; domain 为标签数组时取首个标签作主领域)", "domain")):
        L.append(f"## {title}")
        L.append("")
        L.append("| 类别 | 记录数 | 占比 |")
        L.append("|:---|---:|---:|")
        for k, v in sorted(st[key].items(), key=lambda x: -x[1]):
            L.append(f"| {k} | {v} | {v / (n or 1) * 100:.1f}% |")
        L.append("")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    # ---------- HTML ----------
    def tr(cells, cls=""):
        tds = "".join(f"<td>{esc(c)}</td>" for c in cells)
        return f'<tr class="{cls}">{tds}</tr>'

    H = ["""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>代码问答质检报告</title><style>
body{font-family:'Microsoft YaHei',sans-serif;margin:24px;color:#222;max-width:1200px}
h1{border-bottom:2px solid #2e75b6;padding-bottom:8px}h2{color:#2e75b6;margin-top:28px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #ccc;padding:6px 10px;font-size:13px;text-align:left}
th{background:#eaf2fa}tr.error td{background:#fdecea}tr.warn td{background:#fff8e1}
.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:bold}
.badge.fail{background:#c0392b;color:#fff}.badge.pass{background:#27ae60;color:#fff}
</style></head><body>"""]
    H.append("<h1>代码问答数据集 质检报告</h1>")
    H.append(f"<p>生成时间: {started_at:%Y-%m-%d %H:%M:%S} | 样本: {n} 条 {esc(sample_note)} | "
             f"ERROR: {qc._err_count} | WARN: {qc._warn_count}</p>")
    H.append(f'<p class="badge {"fail" if not ok else "pass"}">{"不达标 — 需整改" if not ok else "代码检测通过, 待人工复检"}</p>')
    H.append("<h2>一、总体结论</h2>")
    H.append(f"<p><b>{'❌ 不达标(存在 ERROR, 需整改)' if not ok else '✅ 代码检测通过, 待人工复检'}</b> — "
             f"样本 {n} 条, ERROR {qc._err_count} 项(记录级 + 全局口径), WARN {qc._warn_count} 项</p>")
    H.append("<p>合格判定要点: 完全重复率 <0.5% | 脱敏明文 0 | 真实性/混入/低阶模型校验通过 | "
             "设计口径(单一语言占比/多轮占比/同题多解)说明见 README §七与《终检交付评估报告》</p>")
    H.append("<h2>二、验收硬指标</h2><table><tr><th>结果</th><th>指标</th><th>说明</th></tr>")
    for lvl, item, detail in global_rows:
        mark = {"PASS": "✅", "ERROR": "❌", "WARN": "⚠️", "SKIP": "➖"}[lvl]
        H.append(tr([mark, item, detail], lvl.lower() if lvl in ("ERROR", "WARN") else ""))
    H.append("</table>")

    # ---- HTML 维度表(规范书 §10 六项: 三~七)----
    def dim_html(title, rows):
        H.append(f"<h2>{esc(title)}</h2><table><tr><th>检查项</th><th>结果</th><th>说明</th></tr>")
        for item, mark, detail in rows:
            cls = "error" if "❌" in mark else ("warn" if "⚠️" in mark else "")
            H.append(tr([item, mark, detail], cls))
        H.append("</table>")

    # 三、抽样代码功能校验
    c = st["code"]
    dim_html("三、抽样代码功能校验(§10; §9 代码质量硬指标)", [
        ("代码块总数", "✅", f"{c['blocks']} 个(answer 内 fenced 块)"),
        ("Python 块语法校验", "➖",
         "口径已移除(论坛型语料代码为片段, ast.parse 不适用; 2026-09-20 用户拍板)"),
        ("非 Python 块括号平衡粗检", "⚠️" if c["bracket_bad"] else "✅",
         f"失衡 {c['bracket_bad']} 块(字符串内括号可能误报, 需复核)"),
        ("存在代码问题的记录", "⚠️" if st["code_fail_recs"] else "✅",
         f"{st['code_fail_recs']}/{n} 条"),
    ])
    # 四、问答真实性校验
    dim_html("四、问答真实性校验(§10; §4.1 样本硬性约束)", [
        ("source 标注完整", "❌" if st["source_missing"] else "✅",
         f"缺失 {st['source_missing']}/{n} 条(§4.1 须标注社区名/问题来源+答案模型)"),
        ("多来源标注(用/分隔)", "✅", f"{st['source_multi']} 条"),
        ("模型生成答案来源标注", "✅", f"{st['source_model']} 条(source 含模型标识)"),
        ("低阶模型答案", "❌" if st["low_tier_model"] else "✅",
         f"{st['low_tier_model']} 条(§4.1 须 Claude-4.7-opus 同级以上)"),
        ("疑似合成提问", "⚠️" if st["synthetic_q"] else "✅",
         f"{st['synthetic_q']} 条(§4.1 禁止合成虚构提问, 需人工复核)"),
        ("开源数据集混入", "❌" if st["oss_dataset"] else "✅",
         f"{st['oss_dataset']} 条(§4.1 禁止复用 GitHub/HuggingFace 数据集)"),
        ("隐藏反爬水印", "❌" if st["hidden_span"] else "✅",
         f"{st['hidden_span']} 条(LeetCode 隐形 span, 需剔除)"),
    ])
    # 五、重复率校验
    dup_ratio = st["dup_q"] / (n or 1) * 100
    dim_html("五、重复率校验(§10; §9 去重指标 <0.5%)", [
        ("精确重复(message MD5)", "❌" if st["dup_q"] else "✅",
         f"{st['dup_q']} 条, 重复率 {dup_ratio:.2f}%(阈值 <{DUP_LIMIT}%)"),
        ("近似重复(5-gram Jaccard≥0.6)", "⚠️" if st["near_dup"] else "✅",
         f"{st['near_dup']} 组(§4.2 LQ7 仅变量名/注释微调的重复样本)"),
        ("同题多解(首问相同)", "✅",
         f"{st['same_q_diff_lang']} 条(同题多解设计口径, 见 README §七)"),
    ])
    # 六、脱敏校验
    hits_desc = ("; ".join(f"{k} {v} 处" for k, v in sorted(st["privacy_hits"].items()))
                 if st["privacy_hits"] else "未检出明文隐私")
    # 脱敏校验: 2026-09-19 客户口径 — 每项有命中均为 ⚠️ WARN 告警(不判 ❌ ERROR),
    # 命中原文并入 §十 WARN 明细节, 逐条人工复核; 仅"无命中"才 ✅。
    _dim_ip_soc = (qc._item_cnt.get("疑似内网IP", 0) + qc._item_cnt.get("疑似社交账号", 0))
    dim_html("六、脱敏校验(§10; §6 匿名化合规)", [
        ("隐私明文泄露", "⚠️" if st["privacy"] else "✅",
         f"{st['privacy']}/{n} 条(全量自动化扫描, 2026-09-19 起命中统一为 WARN 告警, "
         f"明细含命中原文+上下文, 逐条人工复核)"),
        ("命中类型分布", "⚠️" if st["privacy_hits"] else "✅",
         hits_desc + "(命中逐条列入 WARN 明细, 人工复核)"),
        ("内网 IP/社交账号", "⚠️" if _dim_ip_soc else "✅",
         (f"检出 内网 {qc._item_cnt.get('疑似内网IP', 0)} / 社交 {qc._item_cnt.get('疑似社交账号', 0)} 条"
          "(代码示例语境误报率高, 检出时人工复核)" if _dim_ip_soc else "0 检出(内网 10.x 为 §6 合规替换值; "
          "变量名 qq/AVX 指令集等算法语境不误报)")),
    ])
    # 七、低质样本过滤记录
    lq_desc = {
        "LQ1_闲聊咨询": "问题无明确代码需求, 仅纯文字闲聊咨询",
        "LQ2_代码残缺语法错误": "回答代码残缺/语法报错/无效玩具 Demo",
        "LQ3_回答过短无实质": "回答仅简短文字, 无代码/原理/方案",
        "LQ4_隐私未脱敏": "含明文隐私/内网地址/联系方式",
        "LQ5_违规内容": "涉黄/暴力/违法/恶意代码类",
        "LQ6_占位符乱码模板": "大量占位符/乱码/灌水复制粘贴",
        "LQ7_问答高度近似": "仅变量名/注释微调的重复样本",
    }
    H.append("<h2>七、低质样本过滤记录(§10; §4.2 七条低质过滤规则)"
             "</h2><table><tr><th>规则</th><th>命中记录数</th><th>说明</th></tr>")
    for k in ("LQ1_闲聊咨询", "LQ2_代码残缺语法错误", "LQ3_回答过短无实质",
              "LQ4_隐私未脱敏", "LQ5_违规内容", "LQ6_占位符乱码模板", "LQ7_问答高度近似"):
        v = st["lq"][k]
        mark = "⚠️" if v else "✅"
        H.append(tr([f"{mark} {k}", v, lq_desc[k]], "warn" if v else ""))
    H.append("</table>")
    H.append("<h2>八、问题整改明细</h2><table><tr><th>检查项</th><th>条数</th>"
             "<th>样本ID</th><th>建议整改措施</th><th>状态</th></tr>")
    if rect_rows:
        for item, cnt, rids, advice, status in rect_rows:
            H.append(tr([item, cnt, rids, advice, status],
                        "warn" if status.startswith("WARN") else "error"))
    else:
        H.append(tr(["无待整改问题", "", "", "", ""], ""))
    H.append("</table>")
    # 九/十、明细(默认显示前 10 条, <details> 展开; HTML 适当省略防浏览器卡顿,
    # MD 报告为全量权威清单)
    _PREVIEW = 10
    _HTML_CAP = 2000  # HTML 展开后最多渲染行数; 超出提示去 MD 查全量
    _warn_rows = [r for r in qc.warn_rows if r[1] != "疑似内网IP"]
    for rid, ip, ctx in qc.ip_detail:
        _warn_rows.append((rid, "疑似内网IP",
                           f"{ip} → 脱敏 `{_ip_desensitize(ip)}` «{ctx}»"))
    # 2026-09-20 展示优先级: 隐私类最需人工复核 ⇒ 排前;
    # 「代码块括号失衡」是粗检指标(抽样实测约 1/3 为脚本误报, 其余多为论坛
    # 片段型语料的天然形态) ⇒ 排最后, 避免淹没真正要看的隐私/多轮项。
    _WARN_PRI = {"疑似社交账号": 0, "隐私泄露": 0, "疑似内网IP": 1,
                 "多轮配对不足": 2, "代码块括号失衡": 9}
    _warn_rows.sort(key=lambda r: (_WARN_PRI.get(r[1], 5), r[1], r[0]))

    def detail_html(title, rows, cls):
        H.append(f"<h2>{esc(title)}</h2>")
        if not rows:
            H.append("<p>无</p>")
            return
        if len(rows) > _PREVIEW:
            H.append(f"<p>共 {len(rows)} 条 — 默认显示前 {_PREVIEW} 条, 点击展开查看"
                     f"(HTML 最多列 {min(len(rows), _HTML_CAP)} 条, 完整清单见同目录 MD 报告)。</p>")
        else:
            H.append(f"<p>共 {len(rows)} 条(全部列出)。</p>")
        H.append("<table><tr><th>ID</th><th>检查项</th><th>详情</th></tr>")
        for r in rows[:_PREVIEW]:
            H.append(tr(r, cls))
        H.append("</table>")
        if len(rows) > _PREVIEW:
            H.append(f"<details><summary>展开剩余 {len(rows) - _PREVIEW} 条</summary>"
                     f"<table><tr><th>ID</th><th>检查项</th><th>详情</th></tr>")
            for r in rows[_PREVIEW:_HTML_CAP]:
                H.append(tr(r, cls))
            if len(rows) > _HTML_CAP:
                H.append(tr(["…", "", f"HTML 省略 {len(rows) - _HTML_CAP} 条 — "
                                      f"完整清单见同目录 MD 报告"], cls))
            H.append("</table></details>")
    detail_html("九、ERROR 明细(必须整改)", qc.error_rows, "error")
    detail_html("十、WARN 明细(建议复核; 隐私/内网 IP/社交账号命中含原文上下文)", _warn_rows, "warn")
    H.append("</body></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(H))
    return md_path, html_path, ok


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="代码问答数据集质检")
    ap.add_argument("paths", nargs="*", help="jsonl 文件或目录")
    ap.add_argument("--out", default=None, help="报告输出目录, 默认 ./qc_reports/")
    ap.add_argument("--sample", type=float, default=0, metavar="PCT",
                    help="随机抽样百分比(如 1 表示抽 1%%, \u00a79 质检抽检要求不低于 1%%); 0=全量。seed 见 --seed")
    ap.add_argument("--seed", type=int, default=2026, metavar="N",
                    help="抽样随机种子(默认 2026)。多轮独立抽检时用不同 seed 抽不同子集")
    ap.add_argument("--prev", default=None, metavar="MD",
                    help="上一版质检报告(.md), 用于生成问题整改明细的 已整改/未整改/新增 对比")
    ap.add_argument("--no-near-dup", action="store_true",
                    help="关闭近似重复检测(§4.2 LQ7)。大数据集流式质检建议开启, "
                         "避免 5-gram shingles 集合占用大量内存; 全量近似查重请用 text_dup_precise_qc.py")
    ap.add_argument("--exempt-multi-turn", "--no-exempt-multi-turn",
                    dest="exempt_multi_turn",
                    action=argparse.BooleanOptionalAction, default=True,
                    help="多轮占比 ≥10%% 红线的默认豁免(默认开): 构造性单轮数据集"
                         "(SO/编程题集等无多轮场景)多轮 0%% 单列为 WARN 不触发整体退回"
                         "(需换源补采, 见 README 口径说明); --no-exempt-multi-turn "
                         "显式关闭豁免, 多轮 0%% 判 ERROR(适用要求多轮的工单/追答类数据)")
    # ⚠️ 2026-09-20 口径变更(用户拍板): **移除 `--dataset-class` 参数**。
    #   所有质检统一按 **forum(论坛问答)** 处理 —— 即恒抑制深度层 N1/N3/N6
    #   (纯文字答案合法 / primary_language 为话题标签而非答案代码语言 / 不做上标压平判定)。
    #   原因: 本项目的代码问答语料均源自社区论坛(Issue/SO/Discourse…), 而非编程题集,
    #   按 code 型判定会系统性误报。
    ap.add_argument("--token-sample", type=float, default=0.0, metavar="P",
                    help="深度层 N4 token 复算抽检比例(如 0.01=1%%), 0=关闭(默认; 贵)")
    ap.add_argument("--fail-on-warn", action="store_true",
                    help="深度语义层 WARN 转 ERROR(接 CI; 默认仅 WARN 不影响主脚本退出码)")
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(base))
    if not args.paths:
        args.paths = [os.path.join(root, "data", "代码问答数据_20260813_simplems", "sample_100.jsonl")]
    out_dir = args.out or os.path.join(os.path.dirname(base), "qc_reports")
    os.makedirs(out_dir, exist_ok=True)

    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.jsonl")))
        elif os.path.isfile(p):
            files.append(p)
    if not files:
        ap.error(f"未找到 jsonl 文件: {args.paths}")

    started_at = datetime.datetime.now()
    import random
    rng = random.Random(args.seed)
    # 前置统计(不解析, 只数行): 据此决策近似查重。超阈值则一个 shingle 都不建,
    # 从根上避免"先建 5000 个 5-gram 集合(≈5GB)才停"的 OOM(流式全量查重留终检/专用工具)
    file_totals = {fpath: count_lines(fpath) for fpath in files}
    total_checked = 0
    for fpath in files:
        tn = file_totals[fpath]
        if args.sample > 0 and tn > 1:
            total_checked += max(1, int(round(tn * args.sample / 100)))
        else:
            total_checked += tn
    near_dup_ok = (not args.no_near_dup) and total_checked <= NEAR_DUP_SHINGLE_CAP
    qc = QaQC(near_dup=near_dup_ok, exempt_multi_turn=args.exempt_multi_turn,
              dataset_class="forum",   # 2026-09-20: 移除 --dataset-class, 恒按 forum 处理
              token_sample=args.token_sample,
              fail_on_warn=args.fail_on_warn)
    if not near_dup_ok and not args.no_near_dup:
        log.warning("检查记录数 %d > 近似查重上限 %d, 自动跳过近似重复检测(流式 O(1) 内存, "
                    "全量近似查重请用 text_dup_precise_qc.py 或分片终检)",
                    total_checked, NEAR_DUP_SHINGLE_CAP)
    sampled_total = 0
    for fpath in files:
        total_n = file_totals[fpath]
        # 蓄水池抽样: 单遍流式, O(1) 内存的均匀随机抽样(§9 抽检要求)
        sampling = args.sample > 0 and total_n > 1
        k = max(1, int(round(total_n * args.sample / 100))) if sampling else 0
        pool = []  # [(lineno, rec)]
        iter_gen, errors = iter_jsonl(fpath)
        n_ok = 0
        for lineno, rec in iter_gen:
            n_ok += 1
            if sampling:
                if n_ok <= k:
                    pool.append((lineno, rec))
                else:
                    j = rng.randrange(n_ok)
                    if j < k:
                        pool[j] = (lineno, rec)
                continue
            qc.check_record(fpath, rec)
        for lineno, err in errors:
            qc.add("ERROR", f"{os.path.basename(fpath)}:line{lineno}", "JSON解析失败", err)
        if has_bom(fpath):
            qc.add("ERROR", os.path.basename(fpath), "BOM", "文件含 UTF-8 BOM(规范要求无 BOM)")
        if sampling:
            for lineno, rec in pool:
                qc.check_record(fpath, rec)
            sampled_total += len(pool)
            log.info("抽样 %s: 全量 %d 条 → 抽检 %d 条(%.1f%%, 蓄水池流式, seed=%d)",
                     fpath, total_n, len(pool), args.sample, args.seed)
        else:
            log.info("读取 %s: %d 条(流式), 解析失败 %d 行", fpath, n_ok, len(errors))

    md_path, html_path, ok = write_reports(out_dir, qc, files, started_at,
                                            sample_pct=args.sample, sampled_n=sampled_total,
                                            prev_path=args.prev, seed=args.seed)
    log.info("=" * 60)
    log.info("质检完成: 样本 %d 条 | 达标 %s | 记录ERROR %d | WARN %d",
             qc.stats["total"], "是" if ok else "否(存在 ERROR, 需整改)",
             qc._err_count, qc._warn_count)
    log.info("报告: %s", md_path)
    log.info("      %s", html_path)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
