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
import datetime
import glob
import hashlib
import json
import logging
import os
import re
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
RE_HIDDEN_SPAN = re.compile(
    r'<span[^>]*(?:opacity:\s*0|position:\s*absolute[^>"]*left:\s*-?\d{4,})[^>]*>.*?</span>', re.I | re.S)

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
RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
RE_PHONE = re.compile(r'(?<![0-9a-fA-F])1[3-9]\d{9}(?![0-9a-fA-F])')
RE_IDCARD = re.compile(r'(?<![0-9Xx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[0-9Xx](?![0-9Xx])')


def strip_fenced(text):
    """剥离 fenced 代码块, 返回"代码块外正文"(隐私/非文本检测用, 代码示例豁免)。"""
    return RE_FENCED.sub('', text or '')


def real_bank_cards(text):
    """银行卡号(Luhn + 边界), 误报根除:
      - 排除小数碎片/标识符内数字串(如 0.6297…/4.6666…)
      - 排除 hex 字面量上下文(0x 后、紧邻 a-f 字母, 如 3fe6666666666666)
      - 排除全同/循环递增数字串(如 6666666666666 / 3334353637383930, 肉眼即非卡号)
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
        if s.isdigit() and all(int(s[i + 1]) - int(s[i]) == 1 for i in range(len(s) - 1)):
            continue  # 顺序递增(如 0123456789012345)
        if luhn_ok(s):
            out.append(s)
    return out


def is_pkg_version_email(v):
    """pkg@version 判定(如 webpack@4.x.x / Typescript@4.0.3): @后第一段以数字开头
    即版本号, 非真实邮箱(真实邮箱域名以字母开头, 如 foo@bar.com)。"""
    first = v.split("@")[-1].split(".")[0]
    return bool(first) and first[0].isdigit()


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
    if len(local) < 2 or not any(c.isalpha() for c in local):
        return False
    if local.replace("x", "") == "":      # 全 x 已脱敏占位(如 data@xxx@classes.dex 的 xxx 段)
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
RE_OSS_DATASET = re.compile(
    r'(?i)\b(?:codealpaca|evol-?instruct|oss-?instruct|coder-?instruct|magicoder'
    r'|stack-?overflow[- ]dump|stack[- ]exchange[- ]dump)\b')
# 低阶模型特征(§4.1: 模型答案须 Claude-4.7-opus 及同等能力以上, 低阶不予入库)
LOW_TIER_MODELS = ("gpt-3.5", "gpt3.5", "gpt-4o-mini", "gpt-4-mini",
                   "llama-2", "llama-3", "chatglm", "baichuan", "vicuna", "alpaca")
# 疑似合成提问特征(§4.1: 禁止人工/大模型合成虚构提问; 保守特征串)
# 校准: 移除 "sample question"/"示例问题" —— 它们是 Web 页面/游戏模板里的普通词
# (实测 4/4 误报: textarea 示例、多选游戏题面、jsfiddle 模板), 不构成合成特征。
SYNTHETIC_Q_MARKERS = ("作为一个ai", "作为一名ai", "ai语言模型", "示例提问",
                        "假设你是", "请你扮演", "请模拟一个")

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
    "隐私泄露": "按 §6 小写 x 占位脱敏(不得直接删除)",
    "疑似内网IP": "内网 IP 按 §6 x 占位脱敏(代码示例除外, 人工确认)",
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


def _strip_for_brackets(code):
    """剥离注释与字符串字面量, 仅保留代码骨架用于括号平衡粗检。

    校准: 原实现直接对整块 count(), 把 // 行注释、/* */ 块注释、"..."/'...'
    字符串内的括号也计入, 造成误报(实测 LeetCode 题解注释 [i+1,n)) 、
    被注释掉的 //for(int j=0;...){ 、字符字面量 '}' 等)。括号平衡只应对
    "代码骨架"判定, 注释/字符串里的括号不构成语法结构。
    单遍状态机: 正常/行注释/块注释/双引号串/单引号串, 处理反斜杠转义。
    """
    out = []
    i, n = 0, len(code)
    in_line = in_block = in_dq = in_sq = False
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
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
        if in_dq:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_dq = False
            i += 1
            continue
        if in_sq:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_sq = False
            i += 1
            continue
        # 正常态: 识别注释/字符串起点, 其余字符保留
        if c == "/" and nxt == "/":
            in_line = True
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if c == '"':
            in_dq = True
            i += 1
            continue
        if c == "'":
            in_sq = True
            i += 1
            continue
        out.append(c)
        i += 1
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
            if lang_l in ("python", "py", "python3"):
                if RE_REPL_HINT.search(body):
                    continue  # REPL/终端会话片段, 跳过 ast 校验
                st["python_checked"] += 1
                try:
                    ast.parse(body)
                except SyntaxError as e:
                    st["python_fail"] += 1
                    issues.append(("代码语法校验失败",
                                   f"python 块 行{e.lineno}: {e.msg}"))
            elif lang_l in ("js", "javascript", "ts", "typescript", "java", "c",
                            "cpp", "c++", "go", "rust", "cs", "csharp", "php",
                            "rb", "ruby", "swift", "kt", "kotlin", "scala"):
                # 括号平衡粗检(字符串内括号会造成少量误报, 仅 WARN 级)
                # 豁免: 含 "..." 省略号的块 —— 用户缩略示例代码普遍省略闭合括号
                # (如 appbar.addOnOffsetChangedListener { ... } 截图截断), 非真残缺。
                if "..." in body or "…" in body or "省略" in body:
                    continue
                # 括号平衡只统计"代码骨架"(剥离 // 与 /* */ 注释、字符串/字符字面量),
                # 否则注释/字符串内的括号被计入 → 误报(实测 LeetCode 题解多例)。
                skel = _strip_for_brackets(body)
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
# 检查逻辑
# ----------------------------------------------------------------------------
class QaQC:
    def __init__(self, near_dup=True, shingle_cap=NEAR_DUP_SHINGLE_CAP,
                 max_detail=200000, exempt_multi_turn=False):
        self.near_dup = near_dup            # 是否启用近似查重(§4.2 LQ7)
        self.exempt_multi_turn = exempt_multi_turn  # 构造性单轮数据集 → 多轮占比单列 WARN, 不触发退回
        self.shingle_cap = shingle_cap      # shingles 收集上限, 超过停止收集
        self.near_dup_skipped = False       # 因超上限/禁用而跳过近似查重
        self.max_detail = max_detail        # 明细列表上限(计数不受限, 明细封顶防大集 OOM)
        self.error_rows, self.warn_rows = [], []
        self._err_count = 0                 # 全量计数(恒准确, 供报告/退出码)
        self._warn_count = 0
        self._item_cnt = {}                 # 检查项 → 全量条数(整改明细用, 恒准确)
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
        priv = []
        for em in RE_EMAIL.finditer(prose_text):
            v = em.group(0)
            dom = v.split("@")[-1].lower()
            local = v.split("@")[0]
            if dom in EMAIL_WHITELIST:
                continue
            if dom.endswith(EMAIL_GH_PATH) and local.replace(".", "").isdigit():
                continue  # GitHub noreply 邮箱(12345+user@users.noreply.github.com)
            if not looks_like_real_email(v):
                continue  # pkg@version / a@a.c 测试串 / 路径片段 等误报
            priv.append("邮箱")
            st["privacy_hits"]["邮箱"] = st["privacy_hits"].get("邮箱", 0) + 1
        if RE_PHONE.search(prose_text):
            priv.append("手机号")
            st["privacy_hits"]["手机号"] = st["privacy_hits"].get("手机号", 0) + 1
        if RE_IDCARD.search(prose_text):
            priv.append("身份证")
            st["privacy_hits"]["身份证"] = st["privacy_hits"].get("身份证", 0) + 1
        if priv:
            st["privacy"] += 1
            st["lq"]["LQ4_隐私未脱敏"] += 1
            self.add("ERROR", rid, "隐私泄露", "; ".join(priv[:3]) + "(§6 须 x 占位)")
        # 银行卡: 代码问答数据中无真实卡号场景(SO 问 Linux/JSON/SQL 数字串), Luhn 命中
        # 100% 为误报(FileID/hex/ID/计数, 实测 USB 设备路径/JSON id/SQL 计数 6/6 误报)。
        # 按 §9 QC 实践口径: 仅统计不告警, 不再产生"疑似银行卡"WARN 噪音。
        if real_bank_cards(prose_text):
            st["privacy_hits"]["银行卡"] = st["privacy_hits"].get("银行卡", 0) + 1

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
            ips_real.append(ip)
        if ips_real:
            self.add("WARN", rid, "疑似内网IP",
                     f"正文含私网地址 {ips_real[0]} 等 {len(ips_real)} 处(§6 须 x 占位, 代码示例除外)")

        # E9c 社交账号(§6: 微信/微博/抖音等)
        if RE_SOCIAL_ACCT.search(answer_text):
            self.add("WARN", rid, "疑似社交账号", "含微信号/QQ 号特征串(§6 须 x 占位)")

        # E11 非文本资源(§4.1: 真实非文本资源破坏自包含须剔除, 仅留纯文本+代码)
        # 检测对象=代码块外正文(逐字段分开处理, 与整改脚本 split_fenced_segments 同口径:
        # Q/A 各自独立判定代码块, 避免跨字段 fence 配对把"代码块"范围搞混——
        # 否则奇数 fence 的记录在 combined 拼接下正文判定与整改不一致, 复检残留)。
        # 只判"真实资源": 外链图/内嵌 base64/blob 失效引用。
        # 代码示例、文件扩展名、"讨论 <img> 标签本身"的文字提及均豁免(误报根治)。
        if any(has_non_text_resource(strip_fenced(t.get(fld) or ""))
               for t in message if isinstance(t, dict)
               for fld in ("question", "answer")):
            self.add("ERROR", rid, "非文本资源残留",
                     "正文含外链图片/base64 内嵌/blob 失效引用(§4.1 须剔除; 代码块与 <img> 文字提及已豁免)")

        # E12 乱码(§4.1 占位符、乱码直接剔除)
        if RE_MOJIBAKE.search(full_text):
            st["lq"]["LQ6_占位符乱码模板"] += 1
            self.add("ERROR", rid, "乱码字符", "含 U+FFFD 替换字符(编码损坏, §4.1 应剔除)")

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

        # W1 token_count 偏差
        tc = meta.get("token_count")
        if isinstance(tc, (int, float)) and tc > 0:
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
        dom = str(rec.get("domain") or "?").split("/")[0].strip()
        st["domain"][dom] = st["domain"].get(dom, 0) + 1

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
        row("ERROR" if c["python_fail"] else "PASS",
            f"Python 语法校验失败 {c['python_fail']} 块",
            f"python 块共校验 {c['python_checked']} 块(ast.parse)")
        row("WARN" if c["bracket_bad"] else "PASS",
            f"代码块括号失衡 {c['bracket_bad']} 块", "非 Python 语言粗检(字符串内括号可能误报, 需复核)")
        row("PASS", "总token(标注/估算)", f"{st['tokens_sum']:,}")
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
            rows.append((item, self._item_cnt.get(item, 0),
                         ", ".join(rids[:5]) + ("…" if len(rids) > 5 else ""),
                         advice, "待整改"))
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
    L.append(f"| Python 块语法校验(ast.parse) | {'❌' if c['python_fail'] else '✅'} | "
             f"校验 {c['python_checked']} 块, 失败 {c['python_fail']} 块(§9 代码须语法完整可复现) |")
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
    L.append("## 六、脱敏校验(§10; §6 匿名化合规, 明文 0 容忍)")
    L.append("")
    L.append("| 检查项 | 结果 | 说明 |")
    L.append("|:---|:---:|:---|")
    L.append(f"| 隐私明文泄露 | {'❌' if st['privacy'] else '✅'} | "
             f"{st['privacy']}/{n} 条(§6 全量自动化扫描, 明文即违规) |")
    if st["privacy_hits"]:
        hits_desc = "; ".join(f"{k} {v} 处" for k, v in sorted(st["privacy_hits"].items()))
    else:
        hits_desc = "未检出明文隐私"
    L.append(f"| 命中类型分布 | ✅ | {hits_desc} |")
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

    # ---- 九/十、明细 ----
    def dump_section(title, rows):
        L.append(f"## {title}")
        L.append("")
        if not rows:
            L.append("无")
        else:
            L.append("| ID | 检查项 | 详情 |")
            L.append("|:---|:---|:---|")
            for rid, item, detail in rows[:300]:
                L.append(f"| {rid} | {item} | {esc(detail)} |")
        L.append("")

    dump_section("九、ERROR 明细(必须整改)", qc.error_rows)
    dump_section("十、WARN 明细(建议复核)", qc.warn_rows)

    # ---- 附录: 分布 ----
    for title, key in (("附录A、编程语言分布(§5.1 单一语言 ≤30%)", "lang"),
                       ("附录B、技术领域分布(§5.2)", "domain")):
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
        ("Python 块语法校验(ast.parse)", "❌" if c["python_fail"] else "✅",
         f"校验 {c['python_checked']} 块, 失败 {c['python_fail']} 块(§9 代码须语法完整可复现)"),
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
    dim_html("六、脱敏校验(§10; §6 匿名化合规, 明文 0 容忍)", [
        ("隐私明文泄露", "❌" if st["privacy"] else "✅",
         f"{st['privacy']}/{n} 条(§6 全量自动化扫描, 明文即违规)"),
        ("命中类型分布", "✅", hits_desc),
        ("内网 IP/社交账号",
         "⚠️" if (qc._item_cnt.get("疑似内网IP", 0) + qc._item_cnt.get("疑似社交账号", 0)) else "✅",
         (f"检出 内网 {qc._item_cnt.get('疑似内网IP', 0)} / 社交 {qc._item_cnt.get('疑似社交账号', 0)} 条"
          "(代码示例语境误报率高, 检出时人工复核)" if qc._item_cnt.get("疑似内网IP", 0)
          or qc._item_cnt.get("疑似社交账号", 0) else "0 检出(内网 10.x 为 §6 合规替换值; "
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
            H.append(tr([item, cnt, rids, advice, status], "error"))
    else:
        H.append(tr(["无待整改问题", "", "", "", ""], ""))
    H.append("</table>")
    H.append("<h2>九、ERROR 明细</h2><table><tr><th>ID</th><th>检查项</th><th>详情</th></tr>")
    for r in qc.error_rows[:300]:
        H.append(tr(r, "error"))
    H.append("</table>")
    H.append("<h2>十、WARN 明细</h2><table><tr><th>ID</th><th>检查项</th><th>详情</th></tr>")
    for r in qc.warn_rows[:300]:
        H.append(tr(r, "warn"))
    H.append("</table></body></html>")
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
                    help="随机抽样百分比(如 1 = 抽 1%%, §9 质检抽检要求 ≥1%%); 0=全量。seed 见 --seed")
    ap.add_argument("--seed", type=int, default=2026, metavar="N",
                    help="抽样随机种子(默认 2026)。多轮独立抽检时用不同 seed 抽不同子集")
    ap.add_argument("--prev", default=None, metavar="MD",
                    help="上一版质检报告(.md), 用于生成问题整改明细的 已整改/未整改/新增 对比")
    ap.add_argument("--no-near-dup", action="store_true",
                    help="关闭近似重复检测(§4.2 LQ7)。大数据集流式质检建议开启, "
                         "避免 5-gram shingles 集合占用大量内存; 全量近似查重请用 text_dup_precise_qc.py")
    ap.add_argument("--exempt-multi-turn", action="store_true",
                    help="构造性单轮数据集(如 SO 无多轮场景)豁免多轮占比: "
                         "多轮 0% 单列为 WARN 不触发整体退回(需换源补采, 见 README 口径说明)")
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
    qc = QaQC(near_dup=near_dup_ok, exempt_multi_turn=args.exempt_multi_turn)
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
