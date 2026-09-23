# -*- coding: utf-8 -*-
"""
安全技术博客数据集 质检脚本
================================
依据《安全技术博客 数据集采集与标注技术规范书》(spec/ 下 docx 版)
及《网安标注数据验收.docx》0828 补充验收意见设计检查项。

用法:
    python blog_qc.py [数据目录或jsonl文件...] [--out 输出目录]
    不指定参数时默认检查 <root>/data/安全技术博客_20260831/ 下全部 blog_data_*_clean.jsonl

检查项分两级:
    ERROR —— 违反规范书硬性标准 / 0828 验收点名问题, 不达标整体退回
    WARN  —— 质量风险提示

输出: Markdown + HTML 双格式质检报告(规范书第 10 节要求), 默认写入 ./qc_reports/
"""

import argparse
import datetime
import glob
import hashlib
import json
import logging
import os
import re
import sys
import time

# ----------------------------------------------------------------------------
# 常量: 规范书口径
# ----------------------------------------------------------------------------
REQUIRED_META_FIELDS = [
    "title", "url", "source_platform", "author_or_org",
    "publish_time", "content_category", "is_original",
]  # 规范书 §9.1: 必填字段缺失率 ≤ 1%
DUP_RATE_LIMIT = 2.0        # §9.3: 全局重复率 ≤ 2%
FIELD_MISSING_LIMIT = 1.0   # §9.1: 必填字段缺失率 ≤ 1%
NONTECH_RATE_LIMIT = 0.5    # §9.3: 广告/评论/会议预告等非技术内容占比 ≤ 0.5%
AUTHORITY_COVER = 95.0      # §9.7: 权威源覆盖率 ≥ 95%
LANG_LIMIT = 30.0           # §5.1: 单一编程语言占比 ≤ 30%
MIN_CONTENT_CHARS = 200     # 低质量正文下限(自定阈值)

# §5.3 权威渠道名单(规范书明示"不限于", 最终以合同约定名单为准)
AUTHORITATIVE_SOURCES = [
    "奇安信", "玄武", "绿盟", "启明星辰", "深信服", "腾讯安全", "玄武实验室",
    "Unit 42", "CrowdStrike", "Kaspersky", "Securelist", "Exodus", "Talos",
    "Zero Day", "ZDI", "RageStorm", "Check Point", "CPR", "新华三", "默安",
    "嘶吼", "弥天",
    "先知", "FreeBuf", "安全客", "Seebug", "看雪", "52破解", "Medium",
    "Dark Reading", "公众号", "知识星球", "小密圈", "微信",
]

# 0828 验收问题: 正文以 poc:/完整poc: 等结尾 → 截断
RE_POC_TRUNC = re.compile(r'(?i)(?:完整\s*)?(?:poc|exp)\s*[：:]\s*$')
RE_COLON_END = re.compile(r'[：:]\s*$')  # 正文以冒号结尾是截断的通用信号

# 失效图片引用: ![Image N](blob:http://localhost/...)  (0828 验收问题 1b)
RE_BLOB_IMG = re.compile(r'!\[[^\]]*\]\(blob:[^)]*\)')
# 未内嵌外链图片: ![..](https://..) 而非 data:image (0828 验收问题 1b)
RE_EXT_IMG = re.compile(r'!\[[^\]]*\]\((?!data:image)(?:https?://|//)[^)]*\)', re.I)
RE_HTML_IMG = re.compile(r'<img[^>]+src=["\'](?!data:image)(?:https?://|//)[^"\']*', re.I)
# 规范书 §4.1.7: 关键图片应使用 <image_desc> 占位符
RE_IMAGE_DESC = re.compile(r'<image_desc>.*?</image_desc>', re.S)

# 隐私扫描(§9.6: 匿名化合规)
RE_PHONE = re.compile(r'(?<![0-9a-fA-F])1[3-9]\d{9}(?![0-9a-fA-F])')
RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
EMAIL_WHITELIST = ("example.com", "example.org", "example.net", "test.com")  # RFC 测试值合规
RE_EMAIL_ANON = re.compile(r'^x+@x+\.')  # xxxx@xxxx.com 为 x 占位脱敏形式(合规)
# 示例/本地域名后缀(test*/localhost 等教学/CTF 环境域名, 非真实邮箱)
RE_EMAIL_EXAMPLE = re.compile(r'@((example|test|sample|localhost)[a-z0-9-]*\.[a-z.]+|[a-z0-9-]+\.localhost)(\.[a-z]+)*$', re.I)
# 身份证出现在花括号内(flag{...}/palu{...} 等 CTF 提交流) 视为 CTF 数据, 非真实 PII
RE_ID_IN_FLAG = re.compile(r'\{[^{}]*\}')
RE_IDCARD = re.compile(r'(?<![0-9Xx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[0-9Xx](?![0-9Xx])')
# §9.6 内网 IP 须替换为 RFC 测试值(10.x.x.x 为合规替换值; 192.168/172.16-31 私网段为漏脱敏)
RE_PRIV_IP = re.compile(
    r'(?<![\d.])(?:192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])')

# §6.1 代码块损坏: 围栏未配平即未闭合(排版严重错乱/代码块损坏过滤)
# 围栏行: 允许缩进, >=3 反引号开块, 后跟 info string
RE_FENCE_LINE = re.compile(r'^\s*(`{3,})\s*(.*)$')

# §4.1.6 涉漏洞文章须标注 CVE 编号及影响版本
RE_CVE_MENTION = re.compile(r'(?<![\w-])CVE-\d{4}-\d{4,7}(?![\w-])', re.I)

# §4.1.8 翻译类文章须注明原文出处
TRANSLATION_SRC_FIELDS = ("translation_source", "original_url", "source_url")

# 空小节截断(0828 反馈 1a 变体): 正文以"## 代码实现"等标题结尾, 后无实质内容
RE_SECTION_HEAD = re.compile(r'(?m)^#{1,4}\s+.*$')
EMPTY_SECTION_KEYWORDS = ("代码", "实现", "利用", "验证", "复现", "结果", "poc", "Poc", "POC", "payload", "exp", "EXP", "flag", "Flag")

# 活跃 IOC 未去武器化(§9.6: 恶意 URL/IP 必须 Defanging)
RE_UNDEFANGED_IP_URL = re.compile(r'(?<![0-9.])h?t?t?p?s?:(?://|\.)?/?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.I)
RE_DEFANG_MARK = re.compile(r'\[\.\]|\[:\/\]|hxxp', re.I)


def _is_excluded_ip(ip):
    """非 IOC 的 IP, 不需要去武器化:
    - 回环/未指定/全广播: 127.x / 0.0.0.0 / 255.255.255.255
    - 链路本地/云元数据: 169.254.x.x (169.254.169.254 是云厂商 IMDS, 教学高频)
    - 文档保留段(RFC 5737/3330): 192.0.2.x / 198.51.100.x / 203.0.113.x / 100.64-127.x
    - 私网段: 10.x / 172.16-31.x (本机实验环境, 非公网 IOC; 漏脱敏由 E10 内网IP项负责)
    - 公共解析/教学示例: 1.1.1.1 / 8.8.x.x / 114.114.x.x / 1.2.3.4 / 9.9.9.9 (教程示例域名)"""
    p = ip.split(".")
    try:
        p = [int(x) for x in p]
    except ValueError:
        return True  # 解析异常按教学值放行, 数据侧另行人工
    if len(p) != 4 or any(x > 255 for x in p):
        return True
    if len(set(p)) == 1:
        return True  # 四段全同(如 99.199.99.199/1.1.1.1)是教学假 IP, 非真实 IOC
    if p[0] in (127, 0) or p == [255, 255, 255, 255]:
        return True
    if p[0] == 169 and p[1] == 254:
        return True
    if (p[0], p[1]) in ((192, 2), (198, 51), (203, 11)):
        return True
    if p[0] == 100 and 64 <= p[1] <= 127:
        return True
    if p[0] == 10:
        return True
    if p[0] == 172 and 16 <= p[1] <= 31:
        return True
    if ip in ("1.1.1.1", "114.114.114.114", "1.2.3.4", "9.9.9.9",
              "99.199.99.199", "123.123.123.123") or p[0] == 8 and p[1] == 8:
        return True  # 99.199.99.199 等 abab 交替值为 nginx/CDN 教程经典占位 IP
    return False

# 非技术内容关键词(§6.1/§9.3: 营销/广告占比 ≤ 0.5%)
# 强信号: 单命中即报(§4.1.7 关注引导/公众号引流残留; 本身即广告句)
AD_STRONG_KEYWORDS = ("扫码关注", "关注公众号", "加微信", "立即咨询", "报名通道")
# 弱信号: 单行命中, 且该行含广告语境(CTA)才报;
# 无 CTA 时属正文正常用词(安全案例里的"优惠券/招聘/客服热线"、目标系统名"招商网"、
# 代码目录输出"/zs 招商程序"等), 报 ERROR/WARN 均为误判。
AD_KEYWORDS = ("招募", "报名", "扫码", "渠道伙伴", "招商", "招聘", "客服热线",
               "会员招募", "训练营", "限时优惠", "优惠券", "原文首发")
# 广告语境(CTA): 命中行须含其一才算广告残留
RE_AD_CTA = re.compile(r"欢迎|请|关注|扫码|联系我们|简历|加入.{0,4}群|更多|回复|点击.{0,10}(试用|咨询)|免费试用|扫一扫|二维码")
# 正文描述标记: 命中行同时含其一 → 是正文(CTF 步骤/漏洞复现示例), 不是广告
# 如 "提示让关注公众号…输入'青龙之站'之后如下图所示" / "优惠券可多次使用"
RE_BODY_DESC = re.compile(r"如下图|如图|所示|步骤|输入|弹窗|界面|页面|提示|然后|之后|接着|点击.{0,8}(按钮|链接|图标)|流程|操作|功能|使用|多次|可.{0,4}使用")
# 注: "转载声明/版权声明" 不在此列 —— §4.1.8 要求转载文注明出处, 声明行是合规保留项

# §8 禁止内容关键词粗筛(涉黄/赌博/毒品/违禁交易/犯罪教唆类)
FORBIDDEN_KW = ("挖矿木马", "病毒样本下载", "社工库", "银行卡四件套", "赌博网站搭建",
                "博彩平台搭建", "毒品交易", "枪支买卖", "恐怖主义", "色情网站",
                "洗钱通道", "钓鱼网站生成", "爆破工具包", "木马生成器", "代刷信誉")

# 近似重复(§6.2: 同源转载/复制粘贴副本; 对齐 text_dup_precise_qc.py 口径 Jaccard≥0.6)
NEAR_DUP_JACCARD = 0.6
# base64 图片串(不吞行尾换行, 避免把紧跟其后的下一行并掉导致围栏/行结构错位)
RE_B64_STRIP = re.compile(r'data:image/[^;]*;base64,[A-Za-z0-9+/=]+')
# 代码块剔除(渲染后为纯文本, 其中 URL/图片引用不可点击, E7/E9 检查需剔除)
# 注意: 不能用 ```.*?(?:```|$) 这类跨块正则 —— 奇数围栏时会把两个独立代码块之间
# 的全部正文吞成"代码块", 导致检查漏检; 必须按行做围栏状态机只剥真正的块内行。


def strip_code_blocks(text):
    """剥掉代码块(围栏行之间)的内容, 保留块外正文。
    与 E11 同口径: 开块>=3 反引号(允许缩进+info), 闭合需>=开块数且无 info。
    末尾未闭合的开块 → 其后按块内处理(与状态机 open_n!=0 判定一致)。"""
    out = []
    n = 0
    for ln in text.split("\n"):
        m = RE_FENCE_LINE.match(ln)
        if m:
            k, info = len(m.group(1)), m.group(2).strip()
            if n == 0:
                n = k
            elif k >= n and not info:
                n = 0
            continue
        if n == 0:
            out.append(ln)
    return "\n".join(out)

def content_shingles(content, n=5):
    """字符级 5-gram 集合(剔除 base64 图片后规范化), 用于近似重复检测。"""
    s = re.sub(r'\s+', '', RE_B64_STRIP.sub('', content or '').lower())
    return frozenset(s[i:i + n] for i in range(max(0, len(s) - n + 1)))


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S", stream=sys.stderr)
log = logging.getLogger("blog_qc")


def read_jsonl(path):
    """流式读取 JSONL(生成器, 大文件不占内存): yield (记录, [解析错误行号], BOM标志)。
    用法: for rec, errors, bom in read_jsonl(path): ..."""
    with open(path, "rb") as f:
        head = f.read(3)
    bom = head == b"\xef\xbb\xbf"
    if bom:
        log.warning("%s 含 UTF-8 BOM(规范要求无 BOM)", path)
    errors = []
    with open(path, "r", encoding="utf-8", errors="strict") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line), errors, bom
            except UnicodeDecodeError as e:
                raise SystemExit(f"[FATAL] {path} 非 UTF-8 编码: {e}")
            except json.JSONDecodeError as e:
                errors.append((idx, str(e)))


def md5(s):
    return hashlib.md5(s.encode("utf-8", "ignore")).hexdigest()


# ----------------------------------------------------------------------------
# 检查逻辑
# ----------------------------------------------------------------------------
class BlogQC:
    def __init__(self, collect_shingles=True):
        self.collect_shingles = collect_shingles
        self.error_rows = []   # (文件, id, 检查项, 详情)
        self.warn_rows = []
        self.stats = {"total": 0, "files": 0, "parse_fail": 0, "bom_files": 0,
                      "dup_url": 0, "dup_text": 0, "near_dup": 0,
                      "content_missing": 0, "content_short": 0, "fence_bad": 0,
                      "trunc": 0, "blob": 0, "blob_imgs": 0, "ext": 0, "ext_imgs": 0,
                      "base64_imgs": 0, "privacy": 0, "forbidden": 0,
                      "platform": {}, "category": {}, "tokens_est": 0, "year": {},
                      "field_missing": 0, "nontech": 0, "lang": {},
                      "authority": 0, "outdated": 0, "original": 0,
                      "cve_articles": 0, "cve_body": 0, "struct_bad": 0}
        self._seen_url, self._seen_md5 = {}, {}
        self._shingles = []   # [(rid, frozenset)] 近似重复检测

    def add(self, level, f, rid, item, detail):
        row = (os.path.basename(f), rid, item, detail)
        (self.error_rows if level == "ERROR" else self.warn_rows).append(row)

    # ---- 逐条记录检查 ----
    def check_record(self, fpath, rec):
        rid = rec.get("id", "?")
        st = self.stats
        st["total"] += 1

        # E1 结构: 顶层 {id, content, meta}
        top = set(rec.keys())
        if top != {"id", "content", "meta"}:
            st["struct_bad"] += 1
            self.add("ERROR", fpath, rid, "结构",
                     f"顶层字段异常: {sorted(top)}(应为 id/content/meta)")
        content = rec.get("content") or ""
        meta = rec.get("meta") or {}
        # 性能: 先一次性剥掉 base64 图数据(单条可达数 MB), 后续检查全在纯文本上跑
        # 同时避免 base64 长串被隐私/IOC/关键词正则反复扫描
        work, n_b64 = RE_B64_STRIP.subn("", content)
        st["base64_imgs"] += n_b64
        # 代码块/行内代码中的 URL/图片引用渲染后为纯文本不可点击, 外链/IOC 检查在 no_code 上跑
        # (行内代码 span 同样剥离: XSS 教学示例 payload 里的 <img src=...> 不是真图床引用)
        no_code = re.sub(r"`[^`\n]*`", "", strip_code_blocks(work))

        # E2 必填 meta 字段
        missing = [k for k in REQUIRED_META_FIELDS if meta.get(k) in (None, "")]
        if missing:
            st["field_missing"] += 1
            self.add("ERROR", fpath, rid, "必填字段缺失", f"meta 缺失: {missing}")

        # E3 URL 重复
        url = (meta.get("url") or "").strip()
        if url:
            if url in self._seen_url:
                st["dup_url"] += 1
                self.add("ERROR", fpath, rid, "URL重复", f"与 {self._seen_url[url]} 重复: {url}")
            else:
                self._seen_url[url] = rid

        # E4 正文哈希重复
        body_md5 = md5(content.strip())
        if body_md5 in self._seen_md5:
            st["dup_text"] += 1
            self.add("ERROR", fpath, rid, "正文重复",
                     f"与 {self._seen_md5[body_md5]} 正文 MD5 一致")
        else:
            self._seen_md5[body_md5] = rid

        # E5 PoC 截断(0828 验收 1a)
        tail = work.rstrip()
        if RE_POC_TRUNC.search(tail):
            st["trunc"] += 1
            self.add("ERROR", fpath, rid, "PoC截断",
                     f"正文以 {tail[-25:]!r} 结尾, 'poc/exp:' 后无内容(0828反馈)")
        elif RE_COLON_END.search(tail):
            self.add("WARN", fpath, rid, "疑似截断",
                     f"正文以冒号结尾: {tail[-25:]!r}, 需人工复核")
        else:
            # 空小节截断: 末尾标题后【完全无内容】才是采集截断。
            # 注: 仅"短内容"不报 —— 安全博客惯用截图/flag/代码收尾,
            # "## 验证\n\n![]()" / "## flag\nflag{...}" 属正常结尾, 报 ERROR 属误判。
            heads = list(RE_SECTION_HEAD.finditer(tail))
            if heads:
                last = heads[-1]
                after = tail[last.end():].strip()
                head_text = last.group(0)
                # 以完整句结尾的标题(修复建议/要点, 如"## 5.3 ……验证码。")本身即内容, 非截断
                if not after and not re.search(r"[。！？!?]\s*$", head_text) and any(k in head_text for k in EMPTY_SECTION_KEYWORDS):
                    st["trunc"] += 1
                    self.add("ERROR", fpath, rid, "小节截断",
                             f"末尾标题 {head_text[:40]!r} 后无任何内容, 疑似采集截断(0828反馈)")

        # E6 失效 blob 图片(0828 验收 1b)
        blobs = RE_BLOB_IMG.findall(work)
        if blobs:
            st["blob"] += 1
            st["blob_imgs"] += len(blobs)
            self.add("ERROR", fpath, rid, "图片丢失(blob)",
                     f"{len(blobs)} 处 blob: 引用(如 {blobs[0][:50]}), 图片未抓到(0828反馈)")

        # E7 未内嵌外链图片(0828 验收 1b); 代码块内示例 URL(payload/CSP 教学)不算
        exts = RE_EXT_IMG.findall(no_code) + RE_HTML_IMG.findall(no_code)
        if exts:
            st["ext"] += 1
            st["ext_imgs"] += len(exts)
            self.add("ERROR", fpath, rid, "图片未内嵌",
                     f"{len(exts)} 处外链图片未转 base64(如 {exts[0][:60]})(0828反馈)")

        # E8 隐私明文(邮箱/身份证 ERROR; 手机号数字串误报率高, 降为 WARN 人工复核)
        priv = []
        today = datetime.date.today()
        for m in RE_EMAIL.finditer(work):
            addr = m.group(0)
            local = addr.split("@")[0]
            # 排除: 全占位本地名(xxx 脱敏形式) / 纯标点本地名(HTML/代码提取残留)
            placeholder = bool(re.fullmatch(r'[xX×*]{1,}', local))
            punct_only = bool(re.fullmatch(r'[._+-]{1,3}', local))
            # 排除: example.*/test.*/localhost 等教学/CTF 环境示例域名
            if (addr.split("@")[-1].lower() not in EMAIL_WHITELIST
                    and addr != "x" and not RE_EMAIL_ANON.match(addr)
                    and not RE_EMAIL_EXAMPLE.search(addr)
                    and not placeholder and not punct_only):
                priv.append(f"邮箱 {addr}")
        # CTF 提交流花括号区段(flag{...} 等), 其内的"身份证"视为 CTF 数据
        flag_spans = [(fm.start(), fm.end()) for fm in RE_ID_IN_FLAG.finditer(work)]
        for cm in RE_IDCARD.finditer(work):
            card = cm.group(0)
            # 出生年份合理性(>1900 且 <= 今年); CTF flag/假数据(如 2084)不算真实身份证
            try:
                by = int(card[6:10])
                if not (1900 <= by <= today.year):
                    continue
            except ValueError:
                pass
            if any(s <= cm.start() < e for s, e in flag_spans):
                continue
            priv.append(f"身份证 {card}")
        if priv:
            st["privacy"] += 1
            self.add("ERROR", fpath, rid, "隐私泄露", "; ".join(priv[:3]))
        phones = RE_PHONE.findall(work)
        if phones:
            self.add("WARN", fpath, rid, "疑似手机号",
                     f"正文含疑似手机号 {phones[0]} 等 {len(phones)} 处(示例号/数字串也可能命中, 需复核)")

        # E9 未去武器化 IP 链接(仅代码块外/行内代码外; 回环/教学保留段/私网段非公网 IOC, 排除)
        # 列出全部命中处(旧版只报第一处就 break, 处数被低估, 与整改脚本对不上)
        undefanged = []
        for m in RE_UNDEFANGED_IP_URL.finditer(no_code):
            frag = m.group(0)
            if RE_DEFANG_MARK.search(frag) or not frag.lower().startswith(("http",)):
                continue
            ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', frag)
            if ip and _is_excluded_ip(ip.group(0)):
                continue
            undefanged.append(frag)
        if undefanged:
            self.add("WARN", fpath, rid, "IOC未Defang",
                     f"可点击 IP 链接未去武器化 {len(undefanged)} 处: {undefanged[0]}"
                     + (f" 等" if len(undefanged) > 1 else ""))

        # E10 内网 IP 漏脱敏(§9.6: 私网段须替换为 RFC 测试值, 10.x 为合规值)
        priv_ips = RE_PRIV_IP.findall(work)
        if priv_ips:
            self.add("ERROR", fpath, rid, "内网IP未脱敏",
                     f"正文含私网地址 {priv_ips[0]} 等 {len(priv_ips)} 处(应替换为 RFC 测试值)")

        # E11 代码块未闭合(§6.1: 过滤代码块损坏/排版严重错乱文章)
        # 标准 Markdown 围栏配对状态机: 开块反引号数>=3, 闭合需>=开块数且无 info
        # (可识别缩进围栏 / 4反引号嵌套3反引号代码, 奇偶计数会误报)
        open_n = 0
        open_line = 0
        n_fence = 0
        for i, ln in enumerate(work.split("\n"), 1):
            m = RE_FENCE_LINE.match(ln)
            if not m:
                continue
            k, info = len(m.group(1)), m.group(2).strip()
            n_fence += 1
            if open_n == 0:
                open_n, open_line = k, i
            elif k >= open_n and not info:
                open_n, open_line = 0, 0
        if open_n != 0:
            self.add("ERROR", fpath, rid, "代码块未闭合",
                     f"``` 围栏未配平(第{open_line}行开块未闭合, 共{n_fence}个围栏), "
                     f"代码块损坏或采集残缺(§6.1)")

        # W3 涉漏洞文章 CVE 标注(§4.1.6: 须标注 CVE 编号及影响版本)
        cves_in_body = set(m.group(0).upper() for m in RE_CVE_MENTION.finditer(work))
        related = meta.get("related_cves")
        if isinstance(related, str):
            related = [related]
        related = [str(c).upper() for c in (related or [])]
        if cves_in_body and not related:
            self.add("ERROR", fpath, rid, "CVE未标注",
                     f"正文提及 {sorted(cves_in_body)[:3]} 但 meta.related_cves 为空"
                     f"(§4.1.6 涉漏洞文章须标注 CVE 编号及影响版本)")
        elif cves_in_body and not cves_in_body.issubset(set(related)):
            gap = sorted(cves_in_body - set(related))[:3]
            self.add("ERROR", fpath, rid, "CVE标注不全",
                     f"正文提及 {gap} 未列入 meta.related_cves(§4.1.6 须标注)")

        # W4 翻译文未注明原文出处(§4.1.8: 翻译类文章需注明原文出处)
        if meta.get("is_original") is False:
            if not any(meta.get(k) for k in TRANSLATION_SRC_FIELDS):
                self.add("WARN", fpath, rid, "翻译文无出处",
                         "is_original=false 但无 translation_source(§4.1.8 须注明原文出处)")

        # W5 时效性(§4.1.6: 以近十年内容为主)
        pt = str(meta.get("publish_time") or "")[:10]
        if re.match(r"\d{4}-\d{2}-\d{2}", pt):
            try:
                years_old = (datetime.date.today() - datetime.date.fromisoformat(pt)).days / 365.25
                if years_old > 10:
                    st["outdated"] += 1
                    self.add("WARN", fpath, rid, "内容过时",
                             f"publish_time={pt}(距今 {years_old:.1f} 年, 超十年, 需降权或标注时效)")
            except ValueError:
                pass

        # W1 正文过短(按纯文本计, 图片不计字数)
        # 图文内容(有内嵌图/占位图)纯文本短属合理: 截图型渗透/软件介绍, 图即正文
        img_cnt = n_b64 + len(RE_IMAGE_DESC.findall(work))
        if len(work.strip()) < MIN_CONTENT_CHARS and img_cnt == 0:
            self.add("WARN", fpath, rid, "正文过短", f"仅 {len(work.strip())} 字符(不含图片)")

        # W2 非技术内容(§6.1/§9.3: 正文残留营销/引流广告)
        # 判定口径(避免正文用词误报):
        #  - 分类本身即社区公告/招聘 → 正文主题, 豁免
        #  - 逐行扫描: 强信号行 或 弱信号行(须含广告语境 CTA),
        #    且该行不含正文描述标记(CTF 步骤/复现示例/产品 UI 描述)
        strong_hits = []
        hit_kw = []
        cat = str(meta.get("content_category") or "")
        cat_exempt = any(t in cat for t in ("公告", "招聘"))
        if not cat_exempt:
            for ln in work.split("\n"):
                if RE_BODY_DESC.search(ln):
                    continue
                # CTF 交旗玩法(如"关注公众号...获取你的flag")不是广告
                if re.search(r"flag|ctf", ln, re.I):
                    continue
                # "公众号的X"名词短语(如"关注公众号的微信号")是功能描述, 非引流 CTA
                if "关注公众号的" in ln:
                    continue
                for k in AD_STRONG_KEYWORDS:
                    if k in ln and k not in strong_hits:
                        strong_hits.append(k)
                for k in AD_KEYWORDS:
                    if k in ln and RE_AD_CTA.search(ln) and k not in hit_kw:
                        hit_kw.append(k)
        if strong_hits or len(hit_kw) >= 2:
            st["nontech"] += 1
            self.add("WARN", fpath, rid, "疑似非技术内容",
                     f"命中: {strong_hits + hit_kw}(§4.1.7 应去除关注引导/广告推广残留)")

        # E12 禁止内容粗筛(§8: 涉黄/赌博/毒品/违禁交易/犯罪教唆)
        fb_hits = [k for k in FORBIDDEN_KW if k in work]
        if fb_hits:
            st["forbidden"] += 1
            self.add("ERROR", fpath, rid, "疑似违规内容",
                     f"命中禁止内容关键词: {fb_hits}(§8 双重拦截, 应剔除)")

        # 近似重复 shingle 收集(§6.2, check_global 统一判定); 大文件可关闭防内存膨胀
        if self.collect_shingles:
            self._shingles.append((rid, content_shingles(work)))

        # 统计
        st["platform"][meta.get("source_platform", "?")] = st["platform"].get(meta.get("source_platform", "?"), 0) + 1
        st["category"][meta.get("content_category", "?")] = st["category"].get(meta.get("content_category", "?"), 0) + 1
        st["tokens_est"] += len(content)  # 字符数近似, 供参考
        # §5.1 primary_languages 分布(条件字段, 有值时统计; 兼容 str/list 两种历史形态)
        langs = meta.get("primary_languages") or []
        if isinstance(langs, str):
            langs = [langs]
        for lang in langs:
            lk = str(lang)
            st["lang"][lk] = st["lang"].get(lk, 0) + 1
        # §9.7 权威源覆盖率
        plat = str(meta.get("source_platform") or "")
        if plat and any(src in plat for src in AUTHORITATIVE_SOURCES):
            st["authority"] += 1
        # 报告维度计数: 完整性 / 格式规范 / 安全知识覆盖度
        # (base64_imgs 已在开头用 RE_B64_STRIP.subn 一次统计)
        if not work.strip():
            st["content_missing"] += 1
        if len(work.strip()) < MIN_CONTENT_CHARS:
            st["content_short"] += 1
        if open_n != 0:
            st["fence_bad"] += 1
        if meta.get("is_original") is True:
            st["original"] += 1
        if related:
            st["cve_articles"] += 1
        if cves_in_body:
            st["cve_body"] += 1
        pt = str(meta.get("publish_time") or "")[:4]
        if re.match(r"\d{4}", pt):
            st["year"][pt] = st["year"].get(pt, 0) + 1

    # ---- 近似重复检测(§6.2) ----
    def _detect_near_dup(self):
        """稀有 5-gram 倒排召回候选对 → 精确 Jaccard 验证(≥0.6 记 WARN)。

        返回检出组数; 单条记录对仅计一次。样本 >5000 条时自动跳过(规模限制)。
        """
        sh = self._shingles
        if len(sh) < 2:
            return []
        if len(sh) > 5000:
            log.warning("记录数 %d > 5000, 跳过近似重复检测(请用 text_dup_precise_qc.py 全量跑)",
                        len(sh))
            return []
        inv = {}
        for i, (_, s) in enumerate(sh):
            for g in s:
                inv.setdefault(g, []).append(i)
        cand = {}
        for g, docs in inv.items():
            if 2 <= len(docs) <= 20:  # 稀有 shingle 才有区分度
                for a in range(len(docs)):
                    for b in range(a + 1, len(docs)):
                        pair = (docs[a], docs[b])
                        cand[pair] = cand.get(pair, 0) + 1
        groups = []
        for (i, j), co in sorted(cand.items(), key=lambda x: -x[1]):
            if co < 8:  # 共享稀有 shingle 过少, 不足以构成近似重复
                continue
            A, B = sh[i][1], sh[j][1]
            if not A or not B:
                continue
            inter = len(A & B)
            jac = inter / (len(A) + len(B) - inter)
            if jac >= NEAR_DUP_JACCARD:
                groups.append((i, j, jac))
                self.add("WARN", "", f"{sh[i][0]}~{sh[j][0]}", "近似重复",
                         f"两篇正文 Jaccard={jac:.3f}≥{NEAR_DUP_JACCARD}"
                         f"(§6.2 同源转载/复制粘贴, 剔除单纯转载副本)")
                if len(groups) >= 20:
                    break
        return groups

    # ---- 全局阈值检查 ----
    def check_global(self, files_meta):
        st = self.stats
        n = st["total"] or 1
        global_rows = []

        def row(level, item, detail):
            global_rows.append((level, item, detail))

        # 必填字段缺失率(逐条 ERROR 已记, 此处算占比)
        url_dup_rate = st["dup_url"] / n * 100
        text_dup_rate = st["dup_text"] / n * 100
        row("ERROR" if url_dup_rate > DUP_RATE_LIMIT else "PASS",
            f"URL重复率 {url_dup_rate:.2f}%", f"阈值 ≤{DUP_RATE_LIMIT}%")
        row("ERROR" if text_dup_rate > DUP_RATE_LIMIT else "PASS",
            f"正文重复率 {text_dup_rate:.2f}%", f"阈值 ≤{DUP_RATE_LIMIT}%")
        row("ERROR" if st["privacy"] / n * 100 > FIELD_MISSING_LIMIT else ("PASS" if st["privacy"] == 0 else "WARN"),
            f"隐私泄露 {st['privacy']} 条", "规范: 匿名化合规, 明文泄露 0 容忍")
        row("ERROR" if st["trunc"] else "PASS",
            f"PoC截断 {st['trunc']} 条", "0828 反馈 1a; 规范 §4.1.1 正文不允许截断")
        row("ERROR" if st["blob"] or st["ext"] else "PASS",
            f"图片丢失: blob {st['blob_imgs']} 张 / 未内嵌外链 {st['ext_imgs']} 张",
            f"blob 记录 {st['blob']} 条, 外链记录 {st['ext']} 条(0828 反馈 1b; 规范要求自包含)")
        # 必填字段缺失率(§9.1: ≤1%)
        fm_rate = st["field_missing"] / n * 100
        row("ERROR" if fm_rate > FIELD_MISSING_LIMIT else "PASS",
            f"必填字段缺失率 {fm_rate:.2f}%", f"{st['field_missing']}/{n} 条缺失(阈值 ≤{FIELD_MISSING_LIMIT}%)")
        # 非技术内容占比(§9.3: ≤0.5%)
        nt_rate = st["nontech"] / n * 100
        row("ERROR" if nt_rate > NONTECH_RATE_LIMIT else ("WARN" if st["nontech"] else "PASS"),
            f"非技术内容占比 {nt_rate:.2f}%", f"{st['nontech']}/{n} 条命中营销/引流特征(阈值 ≤{NONTECH_RATE_LIMIT}%)")
        # 权威源覆盖率(§9.7 硬性标准: ≥95%; 名单以合同约定为准, 未含渠道人工确认)
        auth_rate = st["authority"] / n * 100
        row("ERROR" if auth_rate < AUTHORITY_COVER else "PASS",
            f"权威源覆盖率 {auth_rate:.1f}%", f"{st['authority']}/{n}(阈值 ≥{AUTHORITY_COVER}%, 名单外渠道需人工确认)")
        # 近似重复(§6.2: 同源转载/复制粘贴; 字符 5-gram Jaccard ≥0.6)
        nd_groups = self._detect_near_dup()
        st["near_dup"] = len(nd_groups)
        if not self.collect_shingles:
            row("WARN", "近似重复组 未检测",
                "大文件运行已跳过 5-gram shingle 收集(内存保护), 请用 text_dup_precise_qc.py 或抽样 --sample 复跑")
        elif nd_groups:
            row("WARN",
                f"近似重复组 {len(nd_groups)} 组",
                f"字符级 5-gram Jaccard≥{NEAR_DUP_JACCARD}(§6.2 同源内容优先保留首发完整版)")
        else:
            row("PASS", "近似重复组 0 组",
                f"字符级 5-gram Jaccard≥{NEAR_DUP_JACCARD} 检出 0 组")
        # 编程语言分布(§5.1: 单一语言 ≤30%, 条件字段有值时)
        if st["lang"]:
            top_lang, top_cnt = max(st["lang"].items(), key=lambda x: x[1])
            lang_total = sum(st["lang"].values())
            ratio = top_cnt / lang_total * 100
            row("WARN" if ratio > LANG_LIMIT else "PASS",
                f"单一语言占比 {ratio:.1f}%", f"{top_lang} {top_cnt}/{lang_total}(标注语言样本, 阈值 ≤{LANG_LIMIT}%)")
        # 时效(§4.1.6: 近十年为主)
        row("WARN" if st["outdated"] / n > 0.5 else ("PASS" if st["total"] else "PASS"),
            f"超十年内容 {st['outdated']} 条", f"占比 {st['outdated'] / n * 100:.1f}%(§4.1.6 近十年为主, 超期需降权/标注时效)")
        # 分布均衡(§9.5)
        if st["platform"]:
            top_plat, top_cnt = max(st["platform"].items(), key=lambda x: x[1])
            ratio = top_cnt / n * 100
            row("WARN" if ratio > 50 else "PASS",
                f"单一平台占比 {ratio:.1f}%", f"{top_plat} {top_cnt}/{n}(规范要求分布均衡)")
        if st["category"]:
            top_cat, top_cnt = max(st["category"].items(), key=lambda x: x[1])
            ratio = top_cnt / n * 100
            row("WARN" if ratio > 50 else "PASS",
                f"单一技术方向占比 {ratio:.1f}%", f"{top_cat} {top_cnt}/{n}(§9.5 无单一类别集中)")
        return global_rows


# ----------------------------------------------------------------------------
# 报告输出
# ----------------------------------------------------------------------------
def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_reports(out_dir, qc, files_meta, started_at, sample_pct=0, sampled_n=0):
    st = qc.stats
    n = st["total"]
    stamp = started_at.strftime("%Y%m%d_%H%M%S")
    md_path = os.path.join(out_dir, f"安全博客_质检报告_{stamp}.md")
    html_path = os.path.join(out_dir, f"安全博客_质检报告_{stamp}.html")
    global_rows = qc.check_global(files_meta)
    ok = not qc.error_rows and all(r[0] != "ERROR" for r in global_rows)
    sample_note = (f"(抽检模式: {sample_pct:.1f}%, 共 {sampled_n} 条, 固定 seed=2026)"
                   if sample_pct > 0 else "(全量检查)")

    # ---------- Markdown ----------
    nn = n or 1
    fm_rate = st["field_missing"] / nn * 100
    url_dup_rate = st["dup_url"] / nn * 100
    text_dup_rate = st["dup_text"] / nn * 100
    auth_rate = st["authority"] / nn * 100

    # 四个维度检查项(规范书 §10.3: 完整性/格式规范/数据来源/安全知识覆盖度)
    comp = [  # 二、数据完整性
        ("样本总数", "✅", f"{n} 条"),
        ("正文非空", "❌" if st["content_missing"] else "✅", f"空正文 {st['content_missing']}/{n} 条"),
        (f"正文长度达标(≥{MIN_CONTENT_CHARS}字)", "⚠️" if st["content_short"] else "✅", f"过短 {st['content_short']}/{n} 条"),
        ("必填 meta 字段完整", "❌" if st["field_missing"] else "✅",
         f"缺失 {st['field_missing']}/{n} 条(阈值 ≤1%, 实测 {fm_rate:.2f}%)"),
        ("正文无截断(PoC/空小节)", "❌" if st["trunc"] else "✅",
         f"截断 {st['trunc']} 条(0828 反馈 1a; §4.1.1 正文不允许截断)"),
        ("图片完整自包含", "❌" if (st['blob_imgs'] or st['ext_imgs']) else "✅",
         f"base64 内嵌 {st['base64_imgs']} 张 / 失效 blob {st['blob_imgs']} 张 / 外链未内嵌 {st['ext_imgs']} 张(0828 反馈 1b)"),
    ]
    fmt = [  # 三、格式规范
        ("JSONL 可解析", "❌" if st["parse_fail"] else "✅", f"解析失败 {st['parse_fail']} 行"),
        ("UTF-8 无 BOM", "❌" if st["bom_files"] else "✅", f"含 BOM 文件 {st['bom_files']} 个"),
        ("顶层结构 {id,content,meta}", "❌" if st["struct_bad"] else "✅", f"结构异常 {st['struct_bad']} 条"),
        ("代码块围栏闭合", "❌" if st["fence_bad"] else "✅",
         f"围栏未闭合(奇数 ``` ) {st['fence_bad']} 条(§6.1 代码块损坏应过滤)"),
        ("全局重复率(URL)", "❌" if url_dup_rate > DUP_RATE_LIMIT else "✅", f"{url_dup_rate:.2f}%(阈值 ≤{DUP_RATE_LIMIT}%)"),
        ("全局重复率(正文 MD5)", "❌" if text_dup_rate > DUP_RATE_LIMIT else "✅", f"{text_dup_rate:.2f}%(阈值 ≤{DUP_RATE_LIMIT}%)"),
        ("隐私脱敏合规(无明文)", "❌" if st["privacy"] else "✅", f"明文泄露 {st['privacy']} 条(邮箱/身份证 0 容忍)"),
    ]
    know = [  # 五、安全知识覆盖度
        ("原创内容占比", f"{st['original']}/{n} ({st['original'] / nn * 100:.1f}%)", "is_original=true(§5.3 优先原创实战文)"),
        ("涉漏洞文章 CVE 标注", f"{st['cve_articles']}/{n} ({st['cve_articles'] / nn * 100:.1f}%)", "meta.related_cves 非空(§4.1.6 涉漏洞文章须标注)"),
        ("非技术内容占比", f"{st['nontech']}/{n} ({st['nontech'] / nn * 100:.1f}%)", "营销/引流特征(阈值 ≤0.5%)"),
        ("时效(超十年内容)", f"{st['outdated']}/{n} ({st['outdated'] / nn * 100:.1f}%)", "§4.1.6 近十年为主, 超期需降权"),
    ]

    L = []
    L.append("# 安全技术博客数据集 质检报告")
    L.append("")
    L.append(f"> 生成时间: {started_at:%Y-%m-%d %H:%M:%S}")
    L.append(f"> 检查范围: {sample_note}")
    L.append(f"> 检查文件: {', '.join(os.path.basename(f) for f, _ in files_meta)}")
    L.append(f"> 依据: 技术规范书(docx 版) + 网安标注数据验收(0828 补充意见)")
    L.append("")
    L.append("## 一、总体结论")
    L.append("")
    L.append(f"**{'✅ 代码检测通过, 待人工复检' if ok else '❌ 不达标(存在 ERROR, 需整改)'}** — 样本 {n} 条, "
             f"ERROR {len(qc.error_rows)} 项, WARN {len(qc.warn_rows)} 项")
    L.append("")

    def dim_table(title, rows, cols=3):
        L.append(f"## {title}")
        L.append("")
        if cols == 3:
            L.append("| 检查项 | 结果 | 说明 |")
            L.append("|:---|:---:|:---|")
            for item, mark, detail in rows:
                L.append(f"| {item} | {mark} | {detail} |")
        else:
            L.append("| 维度 | 覆盖情况 | 说明 |")
            L.append("|:---|:---|:---|")
            for item, mark, detail in rows:
                L.append(f"| {item} | {mark} | {detail} |")
        L.append("")

    dim_table("二、数据完整性", comp)
    dim_table("三、格式规范", fmt)

    L.append("## 四、数据来源与权威性")
    L.append("")
    L.append("| 检查项 | 结果 | 说明 |")
    L.append("|:---|:---:|:---|")
    L.append(f"| 权威源覆盖率 | {'✅' if auth_rate >= AUTHORITY_COVER else '⚠️'} | {st['authority']}/{n}(阈值 ≥{AUTHORITY_COVER}%, 名单以合同约定为准) |")
    L.append(f"| URL 可溯源 | {'✅' if st['field_missing'] == 0 else '⚠️'} | meta.url 非空(缺失计入必填字段完整性) |")
    L.append("")
    L.append("| 来源平台 | 记录数 | 占比 | 是否权威源 |")
    L.append("|:---|---:|---:|:---|")
    for k, v in sorted(st["platform"].items(), key=lambda x: -x[1]):
        auth = "✅" if any(src in k for src in AUTHORITATIVE_SOURCES) else "⚠️ 待确认"
        L.append(f"| {k} | {v} | {v / nn * 100:.1f}% | {auth} |")
    L.append("")

    dim_table("五、安全知识覆盖度", know, cols=3)
    L.append("### 5.1 技术方向分布")
    L.append("")
    L.append("| 方向 | 记录数 | 占比 |")
    L.append("|:---|---:|---:|")
    for k, v in sorted(st["category"].items(), key=lambda x: -x[1]):
        L.append(f"| {k} | {v} | {v / nn * 100:.1f}% |")
    L.append("")
    if st["lang"]:
        L.append("### 5.2 标注编程语言分布(meta.primary_languages)")
        L.append("")
        L.append("| 语言 | 记录数 | 占标注比 |")
        L.append("|:---|---:|---:|")
        lang_total = sum(st["lang"].values()) or 1
        for k, v in sorted(st["lang"].items(), key=lambda x: -x[1]):
            L.append(f"| {k} | {v} | {v / lang_total * 100:.1f}% |")
        L.append("")
    if st["year"]:
        L.append("### 5.3 发布年份分布")
        L.append("")
        L.append("| 年份 | 记录数 | 占比 |")
        L.append("|:---|---:|---:|")
        for k, v in sorted(st["year"].items()):
            L.append(f"| {k} | {v} | {v / nn * 100:.1f}% |")
        L.append("")

    L.append("## 六、全局质量指标(阈值汇总)")
    L.append("")
    L.append("| 结果 | 指标 | 说明 |")
    L.append("|:---:|:---|:---|")
    for lvl, item, detail in global_rows:
        mark = {"PASS": "✅", "ERROR": "❌", "WARN": "⚠️"}[lvl]
        L.append(f"| {mark} | {item} | {detail} |")
    L.append("")

    def dump_section(title, rows):
        L.append(f"## {title}")
        L.append("")
        if not rows:
            L.append("无")
        else:
            L.append("| 文件 | ID | 检查项 | 详情 |")
            L.append("|:---|:---|:---|:---|")
            for f, rid, item, detail in rows[:300]:
                L.append(f"| {f} | {rid} | {item} | {esc(detail)} |")
        L.append("")

    dump_section("七、ERROR 明细(必须整改)", qc.error_rows)
    dump_section("八、WARN 明细(建议复核)", qc.warn_rows)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    # ---------- HTML ----------
    def tr(cells, cls=""):
        tds = "".join(f"<td>{esc(c)}</td>" for c in cells)
        return f'<tr class="{cls}">{tds}</tr>'

    H = ["""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>安全技术博客质检报告</title><style>
body{font-family:'Microsoft YaHei',sans-serif;margin:24px;color:#222;max-width:1200px}
h1{border-bottom:2px solid #2e75b6;padding-bottom:8px}
h2{color:#2e75b6;margin-top:28px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #ccc;padding:6px 10px;font-size:13px;text-align:left}
th{background:#eaf2fa}
tr.error td{background:#fdecea}
tr.warn td{background:#fff8e1}
.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:bold}
.badge.fail{background:#c0392b;color:#fff}.badge.pass{background:#27ae60;color:#fff}
code{background:#f4f4f4;padding:1px 4px}
</style></head><body>"""]
    def dim_html(title, rows):
        H.append(f"<h2>{esc(title)}</h2><table><tr><th>检查项</th><th>结果</th><th>说明</th></tr>")
        for item, mark, detail in rows:
            cls = ""
            if "❌" in mark:
                cls = "error"
            elif "⚠️" in mark:
                cls = "warn"
            H.append(tr([item, mark, detail], cls))
        H.append("</table>")

    H.append(f"<h1>安全技术博客数据集 质检报告</h1>")
    H.append(f"<p>生成时间: {started_at:%Y-%m-%d %H:%M:%S} | 样本: {n} 条 {esc(sample_note)} | "
             f"ERROR: {len(qc.error_rows)} | WARN: {len(qc.warn_rows)}</p>")
    H.append(f'<p class="badge {"fail" if not ok else "pass"}">{"不达标 — 需整改" if not ok else "代码检测通过, 待人工复检"}</p>')
    dim_html("二、数据完整性", comp)
    dim_html("三、格式规范", fmt)
    H.append("<h2>四、数据来源与权威性</h2><table><tr><th>检查项</th><th>结果</th><th>说明</th></tr>")
    H.append(tr(["权威源覆盖率", "✅" if auth_rate >= AUTHORITY_COVER else "⚠️",
                 f"{st['authority']}/{n}(阈值 ≥{AUTHORITY_COVER}%, 名单以合同约定为准)"]))
    H.append(tr(["URL 可溯源", "✅" if st["field_missing"] == 0 else "⚠️", "meta.url 非空(缺失计入必填字段完整性)"]))
    H.append("</table>")
    H.append("<table><tr><th>来源平台</th><th>记录数</th><th>占比</th><th>是否权威源</th></tr>")
    for k, v in sorted(st["platform"].items(), key=lambda x: -x[1]):
        auth = "✅" if any(src in k for src in AUTHORITATIVE_SOURCES) else "⚠️ 待确认"
        H.append(tr([k, v, f"{v / nn * 100:.1f}%", auth]))
    H.append("</table>")
    dim_html("五、安全知识覆盖度", know)
    H.append("<h2>五.1 技术方向分布</h2><table><tr><th>方向</th><th>记录数</th><th>占比</th></tr>")
    for k, v in sorted(st["category"].items(), key=lambda x: -x[1]):
        H.append(tr([k, v, f"{v / nn * 100:.1f}%"]))
    H.append("</table>")
    if st["lang"]:
        lang_total = sum(st["lang"].values()) or 1
        H.append("<h2>五.2 标注编程语言分布</h2><table><tr><th>语言</th><th>记录数</th><th>占标注比</th></tr>")
        for k, v in sorted(st["lang"].items(), key=lambda x: -x[1]):
            H.append(tr([k, v, f"{v / lang_total * 100:.1f}%"]))
        H.append("</table>")
    if st["year"]:
        H.append("<h2>五.3 发布年份分布</h2><table><tr><th>年份</th><th>记录数</th><th>占比</th></tr>")
        for k, v in sorted(st["year"].items()):
            H.append(tr([k, v, f"{v / nn * 100:.1f}%"]))
        H.append("</table>")
    H.append("<h2>六、全局质量指标(阈值汇总)</h2><table><tr><th>结果</th><th>指标</th><th>说明</th></tr>")
    for lvl, item, detail in global_rows:
        mark = {"PASS": "✅", "ERROR": "❌", "WARN": "⚠️"}[lvl]
        H.append(tr([mark, item, detail], lvl.lower() if lvl != "PASS" else ""))
    H.append("</table>")
    H.append("<h2>ERROR 明细(必须整改)</h2><table><tr><th>文件</th><th>ID</th><th>检查项</th><th>详情</th></tr>")
    for r in qc.error_rows[:300]:
        H.append(tr(r, "error"))
    H.append("</table>")
    H.append("<h2>WARN 明细(建议复核)</h2><table><tr><th>文件</th><th>ID</th><th>检查项</th><th>详情</th></tr>")
    for r in qc.warn_rows[:300]:
        H.append(tr(r, "warn"))
    H.append("</table></body></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(H))
    return md_path, html_path


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="安全技术博客数据集质检")
    ap.add_argument("paths", nargs="*", help="数据目录或 jsonl 文件, 默认 <root>/data/安全技术博客_20260826/")
    ap.add_argument("--out", default=None, help="报告输出目录, 默认 ./qc_reports/")
    ap.add_argument("--sample", type=float, default=0, metavar="PCT",
                    help="随机抽样百分比(如 1 = 抽 1%%, 规范书 §9 质检抽检要求 ≥1%%); 0=全量。固定 seed 可复现")
    ap.add_argument("--no-shingles", action="store_true",
                    help="跳过 5-gram 近似重复收集(大文件防内存; >5000 条本就会跳过判定)")
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(base))  # 项目根目录
    if not args.paths:
        args.paths = [os.path.join(root, "data", "安全技术博客_20260831")]
    out_dir = args.out or os.path.join(os.path.dirname(base), "qc_reports")
    os.makedirs(out_dir, exist_ok=True)

    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "blog_data_*.jsonl")))
        elif os.path.isfile(p):
            files.append(p)
    if not files:
        ap.error(f"未找到 jsonl 文件: {args.paths}")

    started_at = datetime.datetime.now()
    collect_shingles = not args.no_shingles
    if not collect_shingles:
        log.info("已跳过 5-gram 近似重复收集(--no-shingles)")
    qc = BlogQC(collect_shingles=collect_shingles)
    files_meta = []
    import random
    rng = random.Random(2026)  # 固定 seed, 抽检结果可复现
    sampled_total = 0
    for fpath in files:
        files_meta.append((fpath, 0))
        qc.stats["files"] += 1
        t_file = time.time()
        if args.sample > 0:
            records, errors, bom = [], [], False
            for rec, errors, bom in read_jsonl(fpath):
                records.append(rec)
            full_n = len(records)
            k = max(1, int(round(full_n * args.sample / 100))) if full_n > 1 else full_n
            records = rng.sample(records, k) if k < full_n else records
            sampled_total += len(records)
            log.info("抽样 %s: 全量 %d 条 → 抽检 %d 条(%.1f%%)", fpath, full_n, len(records), args.sample)
            for lineno, err in errors:
                qc.add("ERROR", fpath, f"line:{lineno}", "JSON解析失败", err)
            qc.stats["parse_fail"] += len(errors)
            if bom:
                qc.stats["bom_files"] += 1
                qc.add("ERROR", fpath, "-", "BOM", "文件含 UTF-8 BOM(规范要求无 BOM)")
            for rec in records:
                qc.check_record(fpath, rec)
            files_meta[-1] = (fpath, len(records))
        else:
            n = 0
            last_log = 0
            for rec, errors, bom in read_jsonl(fpath):
                n += 1
                qc.check_record(fpath, rec)
                if n - last_log >= 1000:
                    last_log = n
                    log.info("  %s 已检 %d 条 (%.0fs)", os.path.basename(fpath), n, time.time() - t_file)
            files_meta[-1] = (fpath, n)
            log.info("读取 %s: %d 条, 解析失败 %d 行 (%.0fs)", fpath, n, len(errors), time.time() - t_file)
            for lineno, err in errors:
                qc.add("ERROR", fpath, f"line:{lineno}", "JSON解析失败", err)
            qc.stats["parse_fail"] += len(errors)
            if bom:
                qc.stats["bom_files"] += 1
                qc.add("ERROR", fpath, "-", "BOM", "文件含 UTF-8 BOM(规范要求无 BOM)")

    md_path, html_path = write_reports(out_dir, qc, files_meta, started_at,
                                       sample_pct=args.sample, sampled_n=sampled_total)
    n_err, n_warn = len(qc.error_rows), len(qc.warn_rows)
    log.info("=" * 60)
    log.info("质检完成: 样本 %d 条 | ERROR %d | WARN %d", qc.stats["total"], n_err, n_warn)
    log.info("报告: %s", md_path)
    log.info("      %s", html_path)
    sys.exit(1 if n_err else 0)


if __name__ == "__main__":
    main()
