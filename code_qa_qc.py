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

# 隐私扫描(§6: 统一小写 x 占位, 明文即违规)
RE_PHONE = re.compile(r'(?<![0-9a-fA-F])1[3-9]\d{9}(?![0-9a-fA-F])')
RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
EMAIL_WHITELIST = ("example.com", "example.org", "example.net", "test.com")
RE_IDCARD = re.compile(r'(?<![0-9Xx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[0-9Xx](?![0-9Xx])')

# 隐藏反爬水印: LeetCode 题面注入的隐形 span(opacity:0 / 绝对定位移出视口)
RE_HIDDEN_SPAN = re.compile(
    r'<span[^>]*(?:opacity:\s*0|position:\s*absolute[^>"]*left:\s*-?\d{4,})[^>]*>.*?</span>', re.I | re.S)

# §4.1 过滤非文本资源: 图片/二进制/音视频全剔除, 仅留纯文本+代码
RE_IMG_MARK = re.compile(r'!\[[^\]]*\]\(|<img\b|data:image/|!\[image', re.I)
RE_BINARY_HINT = re.compile(r'(?i)\.(?:zip|tar|gz|rar|7z|exe|dll|so|dylib|mp4|mp3|pdf)\b|\bbase64,[A-Za-z0-9+/=]{50,}')

# §4.1 占位符/乱码: U+FFFD 替换字符即编码损坏
RE_MOJIBAKE = re.compile(r'\ufffd')
RE_PLACEHOLDER_RUN = re.compile(r'(?i)x{20,}')   # ? 串为题目要求输出的内容(§4.2 LQ6 排除)

# §6 匿名化清单补充: 银行卡(Luhn)、内网 IP、社交账号
RE_BANKCARD = re.compile(r'(?<!\d)[3-6]\d{12,18}(?!\d)')
RE_PRIV_IP = re.compile(
    r'(?<![\d.])(?:192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])')
# 注: 10.x.x.x 为 §6 认可的合规替换值(RFC1918 测试段), 不作为漏脱敏检出
RE_SOCIAL_ACCT = re.compile(r'(?<![A-Za-z0-9])(?:微信号|weixin|qq号|qq|vx)\s*[:：]\s*(?=[a-zA-Z0-9_-]*\d)[a-zA-Z0-9_-]{5,}', re.I)

# §4.1 低质: 纯文字闲聊(无代码需求/无报错信息)
CHAT_Q_HINT = ("报错", "error", "exception", "异常", "undefined", "traceback",
               "为什么", "怎么", "如何", "帮我", "实现", "优化", "重构", "```")

# §4.1 禁止复用开源数据集: 公开代码问答数据集特征(GitHub/HuggingFace)
RE_OSS_DATASET = re.compile(
    r'(?i)\b(?:codealpaca|evol-?instruct|oss-?instruct|self-?oss|the-?stack'
    r'|stackoverflow[- ]dump|stack[- ]exchange[- ]dump|coder[- ]instruct|magicoder'
    r'|huggingface\.co/datasets|hf\.co/datasets|github\.com/datasets)\b')
# 低阶模型特征(§4.1: 模型答案须 Claude-4.7-opus 及同等能力以上, 低阶不予入库)
LOW_TIER_MODELS = ("gpt-3.5", "gpt3.5", "gpt-4o-mini", "gpt-4-mini",
                   "llama-2", "llama-3", "chatglm", "baichuan", "vicuna", "alpaca")
# 疑似合成提问特征(§4.1: 禁止人工/大模型合成虚构提问; 保守特征串)
SYNTHETIC_Q_MARKERS = ("作为一个ai", "作为一名ai", "ai语言模型", "示例问题", "示例提问",
                        "sample question", "假设你是", "请你扮演", "请模拟一个")

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


def check_code_syntax(code_text):
    """抽样代码功能校验(§10): 提取 fenced 代码块并做语法/完整性校验。

    返回 dict: {blocks, python_checked, python_fail, bracket_bad, nolang, tiny}
    以及 issue 列表 [(类型, 详情)]。
    """
    st = {"blocks": 0, "python_checked": 0, "python_fail": 0,
          "bracket_bad": 0, "nolang": 0, "tiny": 0}
    issues = []
    blocks = re.findall(r'^```([A-Za-z0-9+#.\-]*)[ \t]*\n(.*?)^```[ \t]*$', code_text, re.S | re.M)
    for lang, code in blocks:
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
            paren_o, paren_c = body.count("("), body.count(")")
            brack_o, brack_c = body.count("["), body.count("]")
            brace_o, brace_c = body.count("{"), body.count("}")
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
                 max_detail=200000):
        self.near_dup = near_dup            # 是否启用近似查重(§4.2 LQ7)
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

        # E9 隐私明文(§6 匿名化清单: 手机号/邮箱/身份证/银行卡)
        priv = []
        for em in RE_EMAIL.finditer(full_text):
            if em.group(0).split("@")[-1].lower() not in EMAIL_WHITELIST \
                    and em.group(0).split("@")[0] != "x":
                priv.append(f"邮箱")
                st["privacy_hits"]["邮箱"] = st["privacy_hits"].get("邮箱", 0) + 1
        if RE_PHONE.search(full_text):
            priv.append("手机号")
            st["privacy_hits"]["手机号"] = st["privacy_hits"].get("手机号", 0) + 1
        if RE_IDCARD.search(full_text):
            priv.append("身份证")
            st["privacy_hits"]["身份证"] = st["privacy_hits"].get("身份证", 0) + 1
        for m in RE_BANKCARD.finditer(full_text):
            if luhn_ok(m.group(0)):
                priv.append(f"银行卡")
                st["privacy_hits"]["银行卡"] = st["privacy_hits"].get("银行卡", 0) + 1
                break
        if priv:
            st["privacy"] += 1
            st["lq"]["LQ4_隐私未脱敏"] += 1
            self.add("ERROR", rid, "隐私泄露", "; ".join(priv[:3]) + "(§6 须 x 占位)")

        # E9b 内网 IP 明文(§6 脱敏清单; 代码示例误报率高, 降 WARN 人工复核)
        ips = RE_PRIV_IP.findall(full_text)
        if ips:
            self.add("WARN", rid, "疑似内网IP",
                     f"含私网地址 {ips[0]} 等 {len(ips)} 处(§6 须 x 占位, 代码示例除外)")

        # E9c 社交账号(§6: 微信/微博/抖音等)
        if RE_SOCIAL_ACCT.search(answer_text):
            self.add("WARN", rid, "疑似社交账号", "含微信号/QQ 号特征串(§6 须 x 占位)")

        # E11 非文本资源(§4.1: 图片/二进制/音视频全剔除, 仅留纯文本+代码)
        if RE_IMG_MARK.search(full_text) or RE_BINARY_HINT.search(full_text):
            self.add("ERROR", rid, "非文本资源残留",
                     "含图片标记/二进制/base64 内容(§4.1 过滤非文本资源)")

        # E12 乱码(§4.1 占位符、乱码直接剔除)
        if RE_MOJIBAKE.search(full_text):
            st["lq"]["LQ6_占位符乱码模板"] += 1
            self.add("ERROR", rid, "乱码字符", "含 U+FFFD 替换字符(编码损坏, §4.1 应剔除)")

        # W5 占位符串(§4.1 大量占位符类灌水)
        m = RE_PLACEHOLDER_RUN.search(answer_text)
        if m:
            st["lq"]["LQ6_占位符乱码模板"] += 1
            self.add("WARN", rid, "疑似占位符", f"含 {m.group(0)[:12]}… 长串占位符(§4.1 剔除灌水样本)")

        # W6b 纯文字闲聊问题(§4.2 LQ1: 问题无明确代码需求仅闲聊 → 剔除)
        if message and isinstance(message[0], dict):
            q0 = message[0].get("question") or ""
            if (len(q0.strip()) < 100 and "```" not in q0
                    and not any(h in q0.lower() for h in CHAT_Q_HINT)):
                st["lq"]["LQ1_闲聊咨询"] += 1
                self.add("WARN", rid, "疑似闲聊问题",
                         f"question 仅 {len(q0.strip())} 字且无代码/报错特征(§4.2 LQ1 闲聊咨询应剔除)")

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

        # §10 三、抽样代码功能校验(全部 answer 的代码块语法/完整性)
        code_st, code_issues = check_code_syntax(full_text)
        for k, v in code_st.items():
            st["code"][k] = st["code"].get(k, 0) + v
        if code_issues:
            st["code_fail_recs"] += 1
            st["lq"]["LQ2_代码残缺语法错误"] += 1
            for itype, idetail in code_issues[:3]:
                self.add("ERROR" if itype == "代码语法校验失败" else "WARN",
                         rid, itype, idetail)
        # W2 代码块无语言标签 → 已并入 code_st["nolang"] 统计
        if code_st["nolang"]:
            self.add("WARN", rid, "代码块无语言标签",
                     f"answer 含 {code_st['nolang']} 个无标签代码块")
        if code_st["tiny"]:
            st["lq"]["LQ2_代码残缺语法错误"] += 1
            self.add("WARN", rid, "代码块疑似残缺",
                     f"含 {code_st['tiny']} 个 <3 行的代码块(§4.2 LQ2 代码残缺/无效 Demo)")

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

        # W4 answer 过短且无代码(§4.2 LQ3)
        for i, t in enumerate(message, 1):
            if isinstance(t, dict):
                a = t.get("answer") or ""
                if len(a.strip()) < 100 and "```" not in a:
                    st["lq"]["LQ3_回答过短无实质"] += 1
                    self.add("WARN", rid, "answer过短",
                             f"第{i}组 answer 仅 {len(a.strip())} 字符且无代码(§4.2 LQ3)")

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
        # 多轮占比 ≥10%(E7)
        mt_ratio = st["multi_turn"] / n * 100
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
                  prev_path=None):
    st = qc.stats
    n = st["total"]
    stamp = started_at.strftime("%Y%m%d_%H%M%S")
    md_path = os.path.join(out_dir, f"代码问答_质检报告_{stamp}.md")
    html_path = os.path.join(out_dir, f"代码问答_质检报告_{stamp}.html")
    global_rows = qc.check_global()
    sample_note = (f"(抽检模式: {sample_pct:.1f}%, 共 {sampled_n} 条, 固定 seed=2026)"
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
    L.append(f"**{'✅ 达标' if ok else '❌ 不达标(存在 ERROR, 需整改)'}** — 样本 {n} 条, "
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
    L.append(f"| 无语言标签代码块 | {'⚠️' if c['nolang'] else '✅'} | {c['nolang']} 个 |")
    L.append(f"| <3 行残缺代码块 | {'⚠️' if c['tiny'] else '✅'} | "
             f"{c['tiny']} 个(§4.2 LQ2 无效玩具 Demo) |")
    L.append(f"| 存在代码问题的记录 | {'⚠️' if st['code_fail_recs'] else '✅'} | "
             f"{st['code_fail_recs']}/{n} 条 |")
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
    L.append(f"| 内网 IP/社交账号 | ⚠️ | 见 WARN 明细(代码示例误报率高, 人工复核) |")
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
    H.append(f'<p class="badge {"fail" if not ok else "pass"}">{"不达标 — 需整改" if not ok else "达标"}</p>')
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
        ("无语言标签代码块", "⚠️" if c["nolang"] else "✅", f"{c['nolang']} 个"),
        ("<3 行残缺代码块", "⚠️" if c["tiny"] else "✅",
         f"{c['tiny']} 个(§4.2 LQ2 无效玩具 Demo)"),
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
        ("内网 IP/社交账号", "⚠️", "见 WARN 明细(代码示例误报率高, 人工复核)"),
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
                    help="随机抽样百分比(如 1 = 抽 1%%, §9 质检抽检要求 ≥1%%); 0=全量。固定 seed=2026")
    ap.add_argument("--prev", default=None, metavar="MD",
                    help="上一版质检报告(.md), 用于生成问题整改明细的 已整改/未整改/新增 对比")
    ap.add_argument("--no-near-dup", action="store_true",
                    help="关闭近似重复检测(§4.2 LQ7)。大数据集流式质检建议开启, "
                         "避免 5-gram shingles 集合占用大量内存; 全量近似查重请用 text_dup_precise_qc.py")
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
    rng = random.Random(2026)
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
    qc = QaQC(near_dup=near_dup_ok)
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
            log.info("抽样 %s: 全量 %d 条 → 抽检 %d 条(%.1f%%, 蓄水池流式, seed=2026)",
                     fpath, total_n, len(pool), args.sample)
        else:
            log.info("读取 %s: %d 条(流式), 解析失败 %d 行", fpath, n_ok, len(errors))

    md_path, html_path, ok = write_reports(out_dir, qc, files, started_at,
                                            sample_pct=args.sample, sampled_n=sampled_total,
                                            prev_path=args.prev)
    log.info("=" * 60)
    log.info("质检完成: 样本 %d 条 | 达标 %s | 记录ERROR %d | WARN %d",
             qc.stats["total"], "是" if ok else "否(存在 ERROR, 需整改)",
             qc._err_count, qc._warn_count)
    log.info("报告: %s", md_path)
    log.info("      %s", html_path)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
