# -*- coding: utf-8 -*-
"""
开源项目漏洞修复commit数据集 质检脚本
================================
依据《开源项目漏洞修复commit 数据集采集与标注技术规范书》(spec/ 下 docx 版)
及《网安标注数据验收.docx》0828 补充验收意见设计检查项。

用法:
    python vuln_commit_qc.py [jsonl文件或目录] [--out 输出目录] [--no-diff-verify]
    不指定参数时默认检查 <root>/data/开源项目代码修复commit_20260826/vuln_fix_commit_samples.jsonl

核心检查项(0828 验收意见 a~d):
    a. 代码字段混入 "From <sha>" 等 format-patch 头(大小写不敏感)
    b. 主文件误选文档文件(md/txt/rst), 漏掉真正被修复的代码文件
    c. vulnerable_code + unified_diff != fixed_code 自洽校验(内置 patch 算法)
    d. 新增文件场景 vulnerable_code 拼接 "(New file) xxx" 无关占位(应留空)

其他: 必填字段、complete_code_fetched 齐全性、text 字段分布合规(§7.1)、
      语言分布 ≤30%、近3年 CVE ≥30%、PII、revert/WIP commit 等。

输出: Markdown + HTML 双格式质检报告, 默认写入 ./qc_reports/
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

# ----------------------------------------------------------------------------
# 常量: 规范书口径
# ----------------------------------------------------------------------------
REQUIRED_META_FIELDS = [
    "cve_id", "project_name", "project_owner", "programming_language",
    "vulnerability_type", "cwe_classification", "severity", "cvss_score",
    "cvss_vector", "fix_commit_hash", "commit_message", "fix_pattern",
    "vulnerability_cause", "license",
]  # 概览性必填字段(§7 text 应承载的属性在 meta 中的镜像; license 为 §9.8 硬性要求 100% 覆盖)
REQUIRED_META_CODE_FIELDS = ["commit_message", "vulnerable_code", "fixed_code", "unified_diff"]
LANG_LIMIT = 30.0      # §9.5 单一语言 ≤30%
RECENT3_LIMIT = 30.0   # §9.7 近3年 CVE 占比 ≥30%
MIN_CODE_LINES = 5     # §6.1 有效代码 ≥5 行
REVERT_LIMIT = 0.5     # §9.7 Revert/无效修复样本占比 ≤0.5%
INCOMPLETE_LIMIT = 0.5 # §9.3 不完整性文本占比 ≤0.5%

# 文件类型分类(b 问题: 主文件误选)
DOC_EXTS = {".md", ".markdown", ".txt", ".rst", ".adoc", ".rmd"}
CODE_EXTS = {
    ".go", ".py", ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".js", ".ts",
    ".jsx", ".tsx", ".java", ".php", ".rb", ".rs", ".cs", ".lua", ".pl",
    ".sh", ".bash", ".m", ".mm", ".swift", ".kt", ".scala", ".groovy",
    ".vue", ".dart", ".zig", ".sql", ".r", ".jl", ".ex", ".exs",
}

# a 问题: format-patch 邮件头 / diff 结构标记混入代码字段
RE_FROM_SHA = re.compile(r'(?m)^From [0-9a-f]{7,40}(?: Mon Sep 17|\b)', re.I)  # 大小写不敏感
RE_DIFF_GIT = re.compile(r'(?m)^diff --git ', re.I)
RE_HUNK_MARK = re.compile(r'// Hunk:|^\+\+\+ |^--- ', re.M)
RE_INDEX_LINE = re.compile(r'(?m)^index [0-9a-f.]+\.\.[0-9a-f.]+')
RE_SUBJECT = re.compile(r'(?m)^(?:Subject: \[PATCH\]|Date: |From: )', re.I)

# d 问题: 新增文件占位污染
RE_NEW_FILE_MARK = re.compile(r'\((?:New file|new file)\)|\(New File\)')

# diff 解析
RE_DIFF_HEADER = re.compile(r'^diff --git a/(.+?) b/(.+?)$')
RE_HUNK_HEAD = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')

# PII(§9.6: 代码脱敏须用语法安全占位符, 明文即违规)
RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
EMAIL_WHITELIST = ("example.com", "example.org", "example.net", "test.com")
RE_EMAIL_ANON = re.compile(r'^x+@x+\.')  # x 占位脱敏形式(合规)
RE_AWS_KEY = re.compile(r'AKIA[0-9A-Z]{16}')
RE_GHPAT = re.compile(r'ghp_[A-Za-z0-9]{36}')
# §6.1 内部 IP / §9.6 严禁纯 x 覆盖(10.x.x.x 为合规 RFC 测试值)
RE_PRIV_IP = re.compile(
    r'(?<![\d.])(?:192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])')
RE_XX_MASK = re.compile(r'(?i)[xX]{10,}')

# §4.1.5 CVE 编号格式; §6.1 REJECTED/DISPUTED/RESERVED CVE 须剔除
# 注意: 仅匹配明确的 CVE 状态标注(cve_id 值/text 的 Status 标签),
# 不能对代码正文全局搜词——"All rights reserved"、业务语义 "rejected" 会大量误报
RE_CVE_FORMAT = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.I)
RE_CVE_ALL = re.compile(r'(?<![\w-])CVE-\d{4}-\d{4,7}(?![\w-])')
RE_CVE_REJECTED = re.compile(
    r'(?i)(?:^|\n)\s*(?:CVE\s*Status|Status)\s*[:：]\s*(?:REJECTED|DISPUTED|RESERVED)\b'
    r'|\b(?:REJECTED|DISPUTED|RESERVED)\s*[-:]?\s*(?:CVE|状态)', re.M)

# §6.1 revert/rollback/undo 等关键词(Commit Message 全文, 词边界)
RE_REVERT_FULLTEXT = re.compile(r'(?i)\b(?:revert|reverted|rollback|roll\s*back|undo)\b')

# §7.1.3 语言一致性(极度重要): text 标签 Key 中的中文字符
RE_ZH_CHAR = re.compile(r'[\u4e00-\u9fff]')
RE_TEXT_LABEL = re.compile(r'(?m)^([^:\n]{1,30})[:：]')

REVERT_KEYWORDS = re.compile(
    r'(?im)^\s*(?:Revert\b|\[?WIP\]?\b|\[?TODO\]?\b|fixme\b|experimental\b|test\b)')

THIS_YEAR = 2026  # 当前交付年份口径(2026-08)


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S", stream=sys.stderr)
log = logging.getLogger("vuln_qc")


def read_jsonl(path):
    records, errors = [], []
    with open(path, "rb") as f:
        raw = f.read()
    bom = raw.startswith(b"\xef\xbb\xbf")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise SystemExit(f"[FATAL] {path} 非 UTF-8 编码: {e}")
    if bom:
        log.warning("%s 含 UTF-8 BOM", path)
    for idx, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            errors.append((idx, str(e)))
    return records, errors, bom


# ----------------------------------------------------------------------------
# unified diff 解析与应用(自洽校验核心)
# ----------------------------------------------------------------------------
def parse_file_sections(diff_text):
    """把 diff 拆成 [(文件路径, 段内容行列表, 是否新增文件)]。

    兼容 git format-patch(带 From/Subject 邮件头)与纯 unified diff。
    同一文件出现多段时全部保留(合并 commit 场景), 调用方按顺序应用。
    """
    sections = []
    cur_path, cur_lines, cur_is_new = None, [], False
    for line in diff_text.split("\n"):
        m = RE_DIFF_HEADER.match(line)
        if m:
            if cur_path is not None:
                sections.append((cur_path, cur_lines, cur_is_new))
            cur_path, cur_lines, cur_is_new = m.group(2), [], False
            continue
        if cur_path is None:
            continue  # format-patch 邮件头/统计区, 跳过
        if line.startswith("new file mode"):
            cur_is_new = True
            continue
        cur_lines.append(line)
    if cur_path is not None:
        sections.append((cur_path, cur_lines, cur_is_new))
    return sections


def parse_hunks(lines):
    """段内行解析为 hunk 列表: 每个 hunk = {old_start, ops: [(tag, line)]}。

    行内容统一 rstrip, 与 _norm_lines 的规范化口径对齐
    (容忍 CRLF 残留 \r 与行尾空白, 不影响语义)。
    """
    hunks, cur = [], None
    for line in lines:
        m = RE_HUNK_HEAD.match(line)
        if m:
            cur = {"old_start": int(m.group(1)), "ops": []}
            hunks.append(cur)
            continue
        if cur is None:
            continue  # index/---/+++/mode 行
        if line.startswith("\\"):        # \ No newline at end of file
            continue
        if line.startswith((" ", "-", "+")):
            cur["ops"].append((line[0], line[1:].rstrip()))
        elif not line.strip():
            continue  # 段落间空行, 非 hunk 上下文
    return hunks


def _norm_lines(text):
    """规范化: 按行拆分, 去行尾空白, 去首尾空行。"""
    lines = [l.rstrip() for l in text.split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def apply_hunks(base_lines, hunks):
    """把 hunk 序列应用到 base 行列表, 返回新行列表; 失败返回 (None, 原因)。

    严格定位(2026-09-02): 仅按 hunk 声明的 old_start(+前序 hunk 净行数偏移) 精确匹配,
    不做 ±N 行模糊搜索 —— 对齐验收方 git apply 双向验证口径, 杜绝"凑位置"通过。
    """
    result = list(base_lines)
    offset = 0
    for hk in hunks:
        ops = hk["ops"]
        n_ctx = sum(1 for t, _ in ops if t == " ")
        n_del = sum(1 for t, _ in ops if t == "-")
        want = hk["old_start"] - 1 + offset
        expect = [l for t, l in ops if t != "+"]
        if not (0 <= want < len(result)):
            return None, f"上下文越界(hunk old_start={hk['old_start']})"
        if result[want:want + n_ctx + n_del][:len(expect)] != expect:
            return None, f"上下文不符(行 {hk['old_start']})"
        new_block, consumed = [], 0
        for t, l in ops:
            if t == " ":
                if result[want + consumed] != l:
                    return None, f"上下文行内容不符(行 {want + consumed + 1})"
                new_block.append(l)
                consumed += 1
            elif t == "-":
                if result[want + consumed] != l:
                    return None, f"删除行与原文不符(行 {want + consumed + 1})"
                consumed += 1
            elif t == "+":
                new_block.append(l)
        result[want:want + consumed] = new_block
        offset += len(new_block) - consumed
    return result, None


def verify_consistency(vuln_code, fixed_code, diff_text, primary_file):
    """自洽校验: vulnerable_code + primary_file 的 diff == fixed_code。

    返回 (通过?, 说明)。多文件 diff 只取 primary_file 对应段;
    同一文件多段(合并 commit)按顺序全部应用。
    """
    sections = parse_file_sections(diff_text)
    target = [s for s in sections if s[0] == primary_file]
    if not target:
        # 主文件不在 diff 中(路径前缀差异), 尝试后缀匹配
        target = [s for s in sections
                  if s[0].endswith("/" + primary_file) or primary_file.endswith("/" + s[0])]
    if not target:
        return False, f"diff 中找不到主文件 {primary_file}(diff 含 {[s[0] for s in sections][:5]})"

    vuln_lines = _norm_lines(vuln_code or "")
    fixed_lines = _norm_lines(fixed_code or "")

    if all(s[2] for s in target) and not vuln_lines:
        # 纯新增文件: 无修复前版本属预期
        hunks = [h for s in target for h in parse_hunks(s[1])]
        built = [l for h in hunks for t, l in h["ops"] if t == "+"]
        if built == fixed_lines:
            return True, "新增文件, vulnerable_code 留空(正确)"
        return False, "新增文件但 fixed_code 与 diff + 行不一致"

    merged, reason = vuln_lines, None
    for path, lines, _is_new in target:
        hunks = parse_hunks(lines)
        if not hunks:
            continue
        merged, reason = apply_hunks(merged, hunks)
        if merged is None:
            return False, reason
    if merged == fixed_lines:
        return True, "vulnerable_code + diff = fixed_code 精确自洽"
    return False, "应用 diff 后结果与 fixed_code 不一致"


def normalize_diff_sha(diff_text):
    """§6.2 重复管控: 标准化后的 Diff(剥离邮件头/index 行、去空白)计算 SHA-256。"""
    keep = []
    for line in diff_text.split("\n"):
        if (RE_FROM_SHA.search(line) or RE_SUBJECT.search(line)
                or RE_INDEX_LINE.search(line) or RE_DIFF_HEADER.match(line)):
            continue
        keep.append(line.strip())
    return hashlib.sha256("".join(keep).encode("utf-8", "ignore")).hexdigest()


def is_trivial_diff(diff_text):
    """§6.1: 判定无实质逻辑变更的 diff(纯注释/格式/文档变更)。

    返回 (trivial?, 原因)。修改行全为注释/空白, 或全部变更文件为文档类。
    """
    changed, files = [], set()
    for line in diff_text.split("\n"):
        m = RE_DIFF_HEADER.match(line)
        if m:
            files.add(os.path.splitext(m.group(2))[1].lower())
            continue
        if line.startswith("+") and not line.startswith("+++"):
            changed.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            changed.append(line[1:])
    if not changed and not files:
        return False, ""
    if not changed:
        return True, "diff 无任何增删行"
    if files and files <= DOC_EXTS:
        return True, f"全部变更文件均为文档类 {sorted(files)}"
    trivial_lines = [l for l in changed
                     if not l.strip() or l.strip().startswith(("//", "#", "*", "/*", "<!--", ";"))]
    if len(trivial_lines) == len(changed):
        return True, f"{len(changed)} 个修改行全部为注释/空白"
    return False, ""


# ----------------------------------------------------------------------------
# 检查逻辑
# ----------------------------------------------------------------------------
class VulnQC:
    def __init__(self, verify_diff=True):
        self.verify_diff = verify_diff
        self.error_rows, self.warn_rows = [], []
        self.stats = {"total": 0, "lang": {}, "year": {}, "severity": {},
                      "inconsist": 0, "consistent": 0, "skipped_verify": 0,
                      "field_missing": 0, "license_missing": 0,
                      "revert_like": 0, "incomplete": 0,
                      "diff_lines_sum": 0, "diff_repeated": 0,
                      "owner": {}, "vtype": {}, "cwe": {},
                      "cve_valid": 0, "cvss": 0, "github_url": 0,
                      "code4": 0, "ccf_true": 0, "struct_bad": 0,
                      "license_dist": {},
                      "cwe_incons": 0, "sev_cvss_bad": 0, "nonlogic": 0}
        self._cve_years = []
        self._seen_diff_hash = {}  # §6.2 标准化 diff SHA-256 去重

    def add(self, level, rid, item, detail):
        (self.error_rows if level == "ERROR" else self.warn_rows).append(
            (rid, item, detail))

    def check_record(self, rec):
        rid = rec.get("id", "?")
        st = self.stats
        st["total"] += 1

        # E1 结构: 顶层 {id, text, meta}
        top = set(rec.keys())
        if top != {"id", "text", "meta"}:
            self.add("ERROR", rid, "结构", f"顶层字段异常: {sorted(top)}(应为 id/text/meta)")
        meta = rec.get("meta") or {}
        text = rec.get("text") or ""

        # E2 必填字段
        missing = [k for k in REQUIRED_META_FIELDS + ["complete_code_fetched"]
                   if k not in meta or meta.get(k) in (None, "")]
        if missing:
            st["field_missing"] += 1
            self.add("ERROR", rid, "必填字段缺失", f"meta 缺失: {missing}")
        if not (meta.get("license") or "").strip():
            st["license_missing"] += 1  # §9.8: 100% 样本须 License 允许 AI 训练
        lic = str(meta.get("license") or "未标注")
        st["license_dist"][lic] = st["license_dist"].get(lic, 0) + 1
        for k in REQUIRED_META_CODE_FIELDS:
            if k not in meta:
                self.add("ERROR", rid, "必填字段缺失", f"meta 缺失 4 大文本字段之一: {k}(§7.1)")

        # E2b CVE 编号格式与状态(§4.1.5/§6.1)
        cve_id = str(meta.get("cve_id") or "")
        if cve_id and not RE_CVE_FORMAT.match(cve_id):
            self.add("ERROR", rid, "CVE格式错误", f"cve_id={cve_id!r}(应形如 CVE-2024-1234)")
        if cve_id and RE_CVE_FORMAT.match(cve_id):
            st["cve_valid"] += 1
        if RE_CVE_REJECTED.search(text) or RE_CVE_REJECTED.search(cve_id) \
                or re.search(r'(?i)^\s*(?:REJECTED|DISPUTED|RESERVED)\s*$', cve_id):
            self.add("ERROR", rid, "CVE状态无效",
                     "检测到 REJECTED/DISPUTED/RESERVED 状态标注(§6.1 应剔除)")

        # E2c cwe_id 与 cwe_classification 一致性(§4.2: 漏洞类型标签须与 CVE 描述
        # 及代码实际缺陷一致, NVD 权威口径以 classification 列表为准)
        cwe_id_v = str(meta.get("cwe_id") or "").strip().upper()
        cwe_cls_v = meta.get("cwe_classification")
        if isinstance(cwe_cls_v, str):
            cwe_cls_v = [cwe_cls_v]
        if cwe_id_v and cwe_cls_v:
            norm_cls = {str(c).strip().upper() for c in cwe_cls_v}
            if cwe_id_v not in norm_cls:
                st["cwe_incons"] += 1
                self.add("ERROR", rid, "cwe_id不一致",
                         f"cwe_id={cwe_id_v} 不在 cwe_classification={sorted(norm_cls)} 中"
                         f"(以 NVD 权威口径修正 cwe_id)")

        # E2d severity ↔ CVSS 评分一致性(§4.1.7: 严重等级标注须与 CVSS 评分对应)
        sev_v = str(meta.get("severity") or "").strip().upper()
        cvss_v = meta.get("cvss_score")
        if sev_v and isinstance(cvss_v, (int, float)) and cvss_v > 0:
            band = ("CRITICAL" if cvss_v >= 9.0 else "HIGH" if cvss_v >= 7.0
                    else "MEDIUM" if cvss_v >= 4.0 else "LOW")
            if sev_v != band:
                st["sev_cvss_bad"] += 1
                self.add("ERROR", rid, "severity与CVSS不符",
                         f"severity={sev_v} 但 cvss_score={cvss_v}(该分数对应 {band})")

        vuln = meta.get("vulnerable_code") or ""
        fixed = meta.get("fixed_code") or ""
        diff = meta.get("unified_diff") or ""
        ccf = meta.get("complete_code_fetched")
        primary_file = meta.get("primary_file", "")

        # E3 complete_code_fetched 语义(0824 反馈 b + README §4.2)
        if ccf is False and not (meta.get("code_note") or "").strip():
            st["incomplete"] += 1
            self.add("ERROR", rid, "code_note缺失", "complete_code_fetched=false 须附 code_note 说明原因")

        # E4 (0828-a) 代码字段混入 format-patch 头/diff 标记 —— 大小写不敏感
        for fld, val in (("vulnerable_code", vuln), ("fixed_code", fixed)):
            hits = []
            if RE_FROM_SHA.search(val):
                hits.append("From <sha> 头")
            if RE_DIFF_GIT.search(val):
                hits.append("diff --git")
            if RE_HUNK_MARK.search(val):
                hits.append("Hunk/+++ 标记")
            if RE_SUBJECT.search(val):
                hits.append("邮件头(Subject/Date/From:)")
            if hits:
                self.add("ERROR", rid, "代码字段拼接污染",
                         f"{fld} 混入 {hits}(0828反馈a: From 大写未过滤)")

        # E5 (0828-b) 主文件误选文档
        if primary_file:
            ext = os.path.splitext(primary_file)[1].lower()
            diff_files = [s[0] for s in parse_file_sections(diff)]
            code_files = [f for f in diff_files if os.path.splitext(f)[1].lower() in CODE_EXTS]
            if ext in DOC_EXTS and code_files:
                self.add("ERROR", rid, "主文件误选(文档)",
                         f"primary_file={primary_file} 为文档, 而 diff 中有代码文件被漏: "
                         f"{code_files[:3]}(0828反馈b)")

        # E6 (0828-d) 新增文件占位污染
        if RE_NEW_FILE_MARK.search(vuln) or RE_NEW_FILE_MARK.search(fixed):
            self.add("ERROR", rid, "新增文件占位污染",
                     f"代码字段含 '(New file) 路径' 无关拼接, 新增文件应留空(0828反馈d)")

        # E7 (0828-c) 自洽校验
        if self.verify_diff and vuln and fixed and diff and primary_file:
            if ccf is False:
                st["skipped_verify"] += 1
            else:
                ok, msg = verify_consistency(vuln, fixed, diff, primary_file)
                if ok:
                    st["consistent"] += 1
                else:
                    st["inconsist"] += 1
                    st["incomplete"] += 1
                    self.add("ERROR", rid, "diff自洽失败", msg)

        # E8 text 字段分布合规(§7.1: text 仅概览属性, 代码必须只在 meta)——计数, 全局汇总
        for kw in ("Vulnerable Code", "Fixed Code", "Diff Content"):
            if kw in text:
                st["text_with_code"] = st.get("text_with_code", 0) + 1
                break

        # E8b text 标签语言一致性(§7.1.3 极度重要: 英文项目严禁中文标签)
        project_name = str(meta.get("project_name") or "")
        proj_is_en = bool(project_name) and not RE_ZH_CHAR.search(project_name)
        if proj_is_en and text:
            zh_labels = [m.group(1).strip() for m in RE_TEXT_LABEL.finditer(text)
                         if RE_ZH_CHAR.search(m.group(1))]
            if zh_labels:
                self.add("ERROR", rid, "text标签语言混排",
                         f"英文项目 text 使用中文标签: {zh_labels[:4]}(§7.1.3 须用英文标签)")

        # E9 PII: 代码脱敏须语法安全占位符, 明文即违规
        for fld, val in (("vulnerable_code", vuln), ("fixed_code", fixed),
                         ("commit_message", meta.get("commit_message") or "")):
            for m in RE_EMAIL.finditer(val):
                addr = m.group(0)
                if (addr.split("@")[-1].lower() not in EMAIL_WHITELIST
                        and addr.split("@")[0] != "x" and not RE_EMAIL_ANON.match(addr)):
                    self.add("ERROR", rid, "PII明文(邮箱)",
                             f"{fld}: {addr}(diff From: 行已脱敏, commit_message 漏脱敏)")
                    break
            if RE_AWS_KEY.search(val):
                self.add("ERROR", rid, "PII明文(AWS Key)", f"{fld} 含 AKIA 密钥")
            if RE_GHPAT.search(val):
                self.add("ERROR", rid, "PII明文(GitHub PAT)", f"{fld} 含 ghp_ 令牌")
        for fld, val in (("vulnerable_code", vuln), ("fixed_code", fixed),
                         ("commit_message", meta.get("commit_message") or "")):
            ips = RE_PRIV_IP.findall(val)
            if ips:
                self.add("ERROR", rid, "内部IP未脱敏",
                         f"{fld} 含私网地址 {ips[0]}(§6.1 应脱敏或剔除)")
                break
        # §9.6 严禁纯 x 无差别覆盖(破坏 AST 解析)
        for fld, val in (("vulnerable_code", vuln), ("fixed_code", fixed)):
            m = RE_XX_MASK.search(val)
            if m:
                self.add("WARN", rid, "疑似纯x脱敏",
                         f"{fld} 含连续 {len(m.group(0))} 个 x(§9.6 应使用 dummy_key_123 类语法安全占位符)")
                break

        # W1 unified_diff 含 format-patch 邮件头(非纯 diff 格式)
        if RE_FROM_SHA.search(diff) or RE_SUBJECT.search(diff):
            self.add("WARN", rid, "diff含邮件头",
                     "unified_diff 以 git format-patch 邮件头开头(From <sha>/Subject), 建议剥离为纯 diff")

        # W2 代码过短(§6.1: <5 行有效代码应剔除; ccf=true 时升级 ERROR)
        for fld, val in (("vulnerable_code", vuln), ("fixed_code", fixed)):
            eff = [l for l in _norm_lines(val) if l.strip() and not l.strip().startswith(("//", "#", "*", "/*"))]
            if 0 < len(eff) < MIN_CODE_LINES:
                if ccf is True:
                    st["incomplete"] += 1
                    self.add("ERROR", rid, "代码过短",
                             f"{fld} 有效代码仅 {len(eff)} 行且 complete_code_fetched=true(§6.1 应剔除)")
                else:
                    self.add("WARN", rid, "代码过短",
                             f"{fld} 有效代码仅 {len(eff)} 行(<{MIN_CODE_LINES}, ccf 非真仅提示)")

        # W7 无实质逻辑变更(§6.1: 仅注释/格式/空白/版本号变更的 Diff 应过滤)
        if diff:
            def _strip_comment(s):
                """剥行尾注释(# 或 // 到行尾)与空白, 用于等价比对。"""
                t = re.sub(r'\s*(?:#|//).*$', '', s.rstrip())
                return t.strip()
            def _is_versionish(t):
                return (not t
                        or re.fullmatch(r'"?\d+\.\d+(\.\d+)?[a-z0-9.\-+]*"?,?', t, re.I) is not None
                        or re.fullmatch(r'(?i)(?:version|__version__|versionCode|versionName)\s*[:=].*', t) is not None
                        or re.fullmatch(r'(?i)(?:bump|chore|pin)\s*.*', t) is not None)
            raw = [(l[0], l[1:]) for l in diff.splitlines()
                   if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
            adds = sorted(_strip_comment(body) for sign, body in raw if sign == "+")
            dels = sorted(_strip_comment(body) for sign, body in raw if sign == "-")
            if adds == dels and (adds or dels):
                # +/- 行剥离注释与空白后完全等价 → 仅注释/空白/格式变更
                st["nonlogic"] += 1
                self.add("WARN", rid, "疑似无实质逻辑变更",
                         f"diff {len(raw)} 处改动剥离注释/空白后 + 与 - 侧完全一致"
                         f"(§6.1 仅格式化/注释/版本升级的 commit 应剔除)")
            elif adds and all(_is_versionish(a) for a in adds) and all(_is_versionish(d) for d in dels):
                st["nonlogic"] += 1
                self.add("WARN", rid, "疑似无实质逻辑变更",
                         f"diff 全部 {len(raw)} 处改动为注释/空白/版本号"
                         f"(§6.1 仅格式化/注释/版本升级的 commit 应剔除)")

        # W3 revert/WIP/revert_flag(§6.1/§9.7)
        cm = meta.get("commit_message") or ""
        if meta.get("revert_flag") is True:
            st["revert_like"] += 1
            self.add("ERROR", rid, "revert样本",
                     "meta.revert_flag=true(§6.1/§9.7 revert 类样本应剔除, 占比阈值 ≤0.5%)")
        elif REVERT_KEYWORDS.search(cm.split("\n")[0]):
            st["revert_like"] += 1
            self.add("WARN", rid, "疑似revert/WIP", f"commit message 首行命中: {cm.splitlines()[0][:60]}")
        m_ft = RE_REVERT_FULLTEXT.search(cm)
        if m_ft and not REVERT_KEYWORDS.search(cm.split("\n")[0]):
            st["revert_like"] += 1
            hits = sorted(set(w.lower() for w in RE_REVERT_FULLTEXT.findall(cm)))
            self.add("WARN", rid, "疑似修复失败",
                     f"commit_message 含 {hits}(§6.1 revert/rollback/undo 关键词, 需人工确认语境)")

        # E-new 纯注释/格式/文档变更(§6.1: 无实质逻辑变更的 commit 应过滤)
        if diff:
            trivial, why = is_trivial_diff(diff)
            if trivial:
                st["revert_like"] += 1
                self.add("ERROR", rid, "无实质变更",
                         f"{why}(§6.1 过滤仅注释/格式/文档变更; §9.7 无效修复 ≤0.5%)")

        # W4 diff 规范化去重(§6.2: 标准化 diff SHA-256 一致仅保留一条)
        if diff:
            dh = normalize_diff_sha(diff)
            if dh in self._seen_diff_hash:
                st["diff_repeated"] += 1
                self.add("ERROR", rid, "diff重复",
                         f"标准化 diff SHA-256 与 {self._seen_diff_hash[dh]} 一致(§6.2 仅保留一条)")
            else:
                self._seen_diff_hash[dh] = rid

        # W5 hunk 上下文行数(§4.1.6: 建议保留修改行前后各 10-20 行)
        if diff:
            min_ctx = None
            for _path, _lines, _new in parse_file_sections(diff):
                for hk in parse_hunks(_lines):
                    ctx = sum(1 for t, _l in hk["ops"] if t == " ")
                    min_ctx = ctx if min_ctx is None else min(min_ctx, ctx)
            if min_ctx is not None and min_ctx < 10:
                st["min_ctx_lt10"] = st.get("min_ctx_lt10", 0) + 1
                if st["min_ctx_lt10"] <= 30:  # 明细限流, 防刷屏
                    self.add("WARN", rid, "diff上下文不足",
                             f"最小 hunk 上下文仅 {min_ctx} 行(§4.1.6 建议修改行前后各 10-20 行)")

        # W6 text 另提多个 CVE(§6.1: 单 commit 修多 CVE 需拆分/剔除)
        cves_in_text = set(m.group(0).upper() for m in RE_CVE_ALL.finditer(text))
        cves_in_text.discard(cve_id.upper())
        if len(cves_in_text) >= 2:
            st["multi_cve"] = st.get("multi_cve", 0) + 1
            if st["multi_cve"] <= 30:
                self.add("WARN", rid, "多CVE关联",
                         f"text 另提及 {sorted(cves_in_text)[:4]} 等多个 CVE(§6.1 需确认是否拆分)")

        # 统计
        st["lang"][meta.get("programming_language", "?")] = st["lang"].get(meta.get("programming_language", "?"), 0) + 1
        st["severity"][meta.get("severity", "?")] = st["severity"].get(meta.get("severity", "?"), 0) + 1
        if diff:
            st["diff_lines_sum"] += len(diff.splitlines())
        year = None
        cve = meta.get("cve_id") or ""
        m = re.match(r"CVE-(\d{4})-", cve)
        if m:
            year = int(m.group(1))
        else:
            pd = str(meta.get("published_date") or "")
            m = re.match(r"(\d{4})-", pd)
            if m:
                year = int(m.group(1))
        if year:
            st["year"][year] = st["year"].get(year, 0) + 1
            self._cve_years.append(year)
        # 报告维度计数: 数据来源 / 安全知识覆盖度
        st["owner"][str(meta.get("project_owner") or "?")] = st["owner"].get(str(meta.get("project_owner") or "?"), 0) + 1
        vt = str(meta.get("vulnerability_type") or "未标注")
        st["vtype"][vt] = st["vtype"].get(vt, 0) + 1
        cwe = str(meta.get("cwe_classification") or "未标注")
        st["cwe"][cwe] = st["cwe"].get(cwe, 0) + 1
        if str(meta.get("cvss_score") or "").strip():
            st["cvss"] += 1
        if str(meta.get("github_url") or "").startswith("http"):
            st["github_url"] += 1
        if vuln and fixed and diff and (meta.get("commit_message") or ""):
            st["code4"] += 1
        if ccf is True:
            st["ccf_true"] += 1

    def check_global(self):
        st = self.stats
        n = st["total"] or 1
        rows = []

        def row(level, item, detail):
            rows.append((level, item, detail))

        # 语言分布 ≤30%
        if st["lang"]:
            top_lang, top_cnt = max(st["lang"].items(), key=lambda x: x[1])
            ratio = top_cnt / n * 100
            row("ERROR" if ratio > LANG_LIMIT else "PASS",
                f"单一语言占比 {ratio:.1f}%", f"{top_lang} {top_cnt}/{n}(阈值 ≤{LANG_LIMIT}%)")
        # 近 3 年占比 ≥30%
        if self._cve_years:
            recent = sum(1 for y in self._cve_years if y >= THIS_YEAR - 2)
            ratio = recent / len(self._cve_years) * 100
            row("ERROR" if ratio < RECENT3_LIMIT else "PASS",
                f"近3年CVE占比 {ratio:.1f}%", f"{recent}/{len(self._cve_years)}(阈值 ≥{RECENT3_LIMIT}%)")
            yrs = sorted(st["year"])
            row("PASS", "CVE年份跨度", f"{yrs[0]} ~ {yrs[-1]}")
        # 自洽率
        verified = st["consistent"] + st["inconsist"]
        if self.verify_diff:
            if verified:
                ratio = st["consistent"] / verified * 100
                row("ERROR" if st["inconsist"] else "PASS",
                    f"diff自洽率 {ratio:.1f}%", f"一致 {st['consistent']} / 不一致 {st['inconsist']}"
                    f"(0828反馈c; ccF=false 跳过 {st['skipped_verify']} 条)")
        # text 字段分布(§7.1)
        twc = st.get("text_with_code", 0)
        if twc:
            row("ERROR", f"text含代码键 {twc}/{n} 条",
                "text 同时含 Vulnerable Code/Fixed Code/Diff Content, 违反 §7.1(text 仅概览属性)"
                "——系统性构造问题, 需与验收方确认口径或整改")
        # License 覆盖率(§9.8: 100% 样本对应 License 允许 AI 训练)
        lic_rate = (n - st["license_missing"]) / n * 100
        row("ERROR" if st["license_missing"] else "PASS",
            f"License覆盖率 {lic_rate:.1f}%", f"缺 license {st['license_missing']}/{n} 条(§9.8 要求 100%)")
        # Revert/无效修复占比(§9.7: ≤0.5%)
        rv_rate = st["revert_like"] / n * 100
        row("ERROR" if rv_rate > REVERT_LIMIT else ("WARN" if st["revert_like"] else "PASS"),
            f"Revert/无效修复占比 {rv_rate:.1f}%", f"{st['revert_like']}/{n} 条(阈值 ≤{REVERT_LIMIT}%)")
        # 不完整性文本占比(§9.3: ≤0.5%)
        inc_rate = st["incomplete"] / n * 100
        row("ERROR" if inc_rate > INCOMPLETE_LIMIT else ("WARN" if st["incomplete"] else "PASS"),
            f"不完整性文本占比 {inc_rate:.1f}%",
            f"{st['incomplete']}/{n} 条(自洽失败/代码过短/code_note 缺失, 阈值 ≤{INCOMPLETE_LIMIT}%)")
        # 必填字段缺失率(§9.4)
        fm_rate = st["field_missing"] / n * 100
        row("ERROR" if fm_rate > 1.0 else "PASS",
            f"必填字段缺失率 {fm_rate:.1f}%", f"{st['field_missing']}/{n} 条(阈值 ≤1%)")
        # diff 重复(§6.2)
        if st["diff_repeated"]:
            row("ERROR", f"标准化diff重复 {st['diff_repeated']} 条", "§6.2 去空白后 SHA-256 一致应仅保留一条")
        # 平均 diff 行数(§4.2 统计报告要求)
        if st["diff_lines_sum"]:
            row("PASS", "平均 diff 行数",
                f"{st['diff_lines_sum'] / n:.1f} 行/条(§4.2 统计指标)")
        # diff 上下文(§4.1.6)
        mc = st.get("min_ctx_lt10", 0)
        if mc:
            row("WARN", f"hunk上下文<10行 {mc} 条",
                f"{mc}/{n}(§4.1.6 建议修改行前后各 10-20 行, '建议'级非硬性)")
        return rows


# ----------------------------------------------------------------------------
# 报告输出(结构复用博客脚本风格)
# ----------------------------------------------------------------------------
def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_reports(out_dir, qc, file_paths, started_at, sample_pct=0, sampled_n=0):
    st = qc.stats
    n = st["total"]
    stamp = started_at.strftime("%Y%m%d_%H%M%S")
    md_path = os.path.join(out_dir, f"漏洞修复commit_质检报告_{stamp}.md")
    html_path = os.path.join(out_dir, f"漏洞修复commit_质检报告_{stamp}.html")
    global_rows = qc.check_global()
    ok = not qc.error_rows and all(r[0] != "ERROR" for r in global_rows)
    sample_note = (f"(抽检模式: {sample_pct:.1f}%, 共 {sampled_n} 条, 固定 seed=2026)"
                   if sample_pct > 0 else "(全量检查)")

    def fmt_rows(rows, limit=400):
        out = []
        for rid, item, detail in rows[:limit]:
            out.append((rid, item, detail))
        return out

    nn = n or 1
    verified = st["consistent"] + st["inconsist"]
    selfok = st["consistent"] / verified * 100 if verified else 0.0
    fm_rate = st["field_missing"] / nn * 100
    text_label_err = sum(1 for r in qc.error_rows if "text标签" in r[1])
    code_pollution = sum(1 for r in qc.error_rows if "代码字段拼接污染" in r[1] or "新增文件占位" in r[1])

    # 四个维度检查项(规范书 §10.3: 完整性/格式规范/数据来源/安全知识覆盖度)
    comp = [  # 二、数据完整性
        ("样本总数", "✅", f"{n} 条"),
        ("顶层结构 {id,text,meta}", "❌" if st["struct_bad"] else "✅", f"结构异常 {st['struct_bad']} 条"),
        ("必填字段完整", "❌" if st["field_missing"] else "✅",
         f"缺失 {st['field_missing']}/{n} 条(阈值 ≤1%, 实测 {fm_rate:.2f}%)"),
        ("代码四件套完整(vuln/fixed/diff/commit_message)", "❌" if st["code4"] < n else "✅",
         f"齐全 {st['code4']}/{n} 条(§7.1 四大文本字段)"),
        ("完整原始代码(ccf=true)", f"✅ {st['ccf_true']}/{n} ({st['ccf_true'] / nn * 100:.1f}%)",
         "complete_code_fetched=true(主代码文件完整)"),
        ("CVE 编号格式有效", f"✅ {st['cve_valid']}/{n} ({st['cve_valid'] / nn * 100:.1f}%)", "CVE-YYYY-NNNN 格式(§4.1.5)"),
        ("diff 自洽(vuln+diff=fixed)", "❌" if st["inconsist"] else "✅",
         f"一致 {st['consistent']} / 不一致 {st['inconsist']}(0828 反馈 c; git apply 严格校验)"),
        ("diff 无重复", "❌" if st["diff_repeated"] else "✅", f"标准化 SHA-256 重复 {st['diff_repeated']} 条(§6.2)"),
    ]
    fmt = [  # 三、格式规范
        ("JSONL 可解析(无结构异常)", "❌" if st["struct_bad"] else "✅", f"结构/解析异常 {st['struct_bad']} 条"),
        ("text 键值对无中英混排", "❌" if text_label_err else "✅",
         f"英文项目 text 用中文标签 {text_label_err} 条(§7.1.3 须英文标签)"),
        ("代码字段无 diff 拼接/占位污染", "❌" if code_pollution else "✅",
         f"混入邮件头/From 大写/(New file) 占位 {code_pollution} 条(0828 反馈 a/d)"),
        ("diff 含上下文(建议级)", "✅", f"平均 {st['diff_lines_sum'] / nn:.1f} 行/条(§4.1.6 建议前后 10-20 行, 非硬性)"),
    ]
    know = [  # 五、安全知识覆盖度(汇总, 明细分布见 5.1-5.6)
        ("CWE 漏洞分类覆盖", f"✅ {len([k for k in st['cwe'] if k != '未标注'])} 类 ({st['total'] - st['cwe'].get('未标注', 0)}/{n} 条有标注)", "cwe_classification 非空(§4 漏洞类型标注)"),
        ("CVSS 评分覆盖", f"✅ {st['cvss']}/{n} ({st['cvss'] / nn * 100:.1f}%)", "cvss_score 非空"),
        ("漏洞类型标注", f"✅ {len([k for k in st['vtype'] if k != '未标注'])} 类", "vulnerability_type 分布(见 5.3)"),
        ("严重等级分布", f"✅ {len(st['severity'])} 档", "CRITICAL/HIGH/MEDIUM(见 5.4)"),
    ]

    L = []
    L.append("# 开源项目漏洞修复commit数据集 质检报告")
    L.append("")
    L.append(f"> 生成时间: {started_at:%Y-%m-%d %H:%M:%S}")
    L.append(f"> 检查范围: {sample_note}")
    L.append(f"> 检查文件: {', '.join(os.path.basename(f) for f in file_paths)}")
    L.append("> 依据: 漏洞修复commit技术规范书(docx 版) + 网安标注数据验收(0828 补充意见)")
    L.append("")
    L.append("## 一、总体结论")
    L.append("")
    L.append(f"**{'✅ 达标' if ok else '❌ 不达标(存在 ERROR, 需整改)'}** — 样本 {n} 条, "
             f"ERROR {len(qc.error_rows)} 项, WARN {len(qc.warn_rows)} 项")
    L.append("")

    def dim_table(title, rows):
        L.append(f"## {title}")
        L.append("")
        L.append("| 检查项 | 结果 | 说明 |")
        L.append("|:---|:---:|:---|")
        for item, mark, detail in rows:
            L.append(f"| {item} | {mark} | {detail} |")
        L.append("")

    def dist_table(title, key, sort_desc=True):
        if not st.get(key):
            return
        L.append(f"### {title}")
        L.append("")
        L.append("| 类别 | 记录数 | 占比 |")
        L.append("|:---|---:|---:|")
        items = st[key].items()
        items = sorted(items, key=lambda x: -x[1]) if sort_desc else sorted(items)
        for k, v in items:
            L.append(f"| {k} | {v} | {v / nn * 100:.1f}% |")
        L.append("")

    dim_table("二、数据完整性", comp)
    dim_table("三、格式规范", fmt)

    L.append("## 四、数据来源与合规")
    L.append("")
    L.append("| 检查项 | 结果 | 说明 |")
    L.append("|:---|:---:|:---|")
    L.append(f"| CVE 权威库关联(NVD) | ✅ {st['cve_valid']}/{n} | cve_id 格式有效(§4 采集口径须关联权威库) |")
    L.append(f"| GitHub 可溯源 | {'✅' if st['github_url'] == n else '⚠️'} {st['github_url']}/{n} | github_url 指向修复 commit |")
    lic_ok = n - st["license_missing"]
    L.append(f"| License 100% 覆盖(允许 AI 训练) | {'✅' if st['license_missing'] == 0 else '❌'} {lic_ok}/{n} | §9.8 硬性要求, 缺 {st['license_missing']} 条 |")
    L.append("")
    L.append("### 4.1 项目来源(组织)分布")
    L.append("")
    L.append("| 项目组织 | 记录数 | 占比 |")
    L.append("|:---|---:|---:|")
    for k, v in sorted(st["owner"].items(), key=lambda x: -x[1]):
        L.append(f"| {k} | {v} | {v / nn * 100:.1f}% |")
    L.append("")

    dim_table("五、安全知识覆盖度", know)
    dist_table("5.1 编程语言分布", "lang")
    dist_table("5.2 严重等级分布", "severity")
    dist_table("5.3 漏洞类型分布", "vtype")
    dist_table("5.4 CWE 分类分布", "cwe")
    dist_table("5.5 CVE 年份分布", "year", sort_desc=False)
    dist_table("5.6 License 分布", "license_dist")

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
            L.append("| ID | 检查项 | 详情 |")
            L.append("|:---|:---|:---|")
            for rid, item, detail in fmt_rows(rows):
                L.append(f"| {rid} | {item} | {esc(detail)} |")
        L.append("")

    dump_section("七、ERROR 明细(必须整改)", qc.error_rows)
    dump_section("八、WARN 明细(建议复核)", qc.warn_rows)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    def tr(cells, cls=""):
        tds = "".join(f"<td>{esc(c)}</td>" for c in cells)
        return f'<tr class="{cls}">{tds}</tr>'

    H = ["""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>漏洞修复commit质检报告</title><style>
body{font-family:'Microsoft YaHei',sans-serif;margin:24px;color:#222;max-width:1200px}
h1{border-bottom:2px solid #2e75b6;padding-bottom:8px}h2{color:#2e75b6;margin-top:28px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #ccc;padding:6px 10px;font-size:13px;text-align:left}
th{background:#eaf2fa}tr.error td{background:#fdecea}tr.warn td{background:#fff8e1}
.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:bold}
.badge.fail{background:#c0392b;color:#fff}.badge.pass{background:#27ae60;color:#fff}
</style></head><body>"""]
    H.append("<h1>开源项目漏洞修复commit数据集 质检报告</h1>")
    H.append(f"<p>生成时间: {started_at:%Y-%m-%d %H:%M:%S} | 样本: {n} 条 {esc(sample_note)} | "
             f"ERROR: {len(qc.error_rows)} | WARN: {len(qc.warn_rows)}</p>")
    H.append(f'<p class="badge {"fail" if not ok else "pass"}">{"不达标 — 需整改" if not ok else "达标"}</p>')

    def dim_html(title, rows):
        H.append(f"<h2>{esc(title)}</h2><table><tr><th>检查项</th><th>结果</th><th>说明</th></tr>")
        for item, mark, detail in rows:
            cls = "error" if "❌" in mark else ("warn" if "⚠️" in mark else "")
            H.append(tr([item, mark, detail], cls))
        H.append("</table>")

    def dist_html(title, key, sort_desc=True):
        if not st.get(key):
            return
        H.append(f"<h3>{esc(title)}</h3><table><tr><th>类别</th><th>记录数</th><th>占比</th></tr>")
        items = st[key].items()
        items = sorted(items, key=lambda x: -x[1]) if sort_desc else sorted(items)
        for k, v in items:
            H.append(tr([k, v, f"{v / nn * 100:.1f}%"]))
        H.append("</table>")

    dim_html("二、数据完整性", comp)
    dim_html("三、格式规范", fmt)
    H.append("<h2>四、数据来源与合规</h2><table><tr><th>检查项</th><th>结果</th><th>说明</th></tr>")
    H.append(tr(["CVE 权威库关联(NVD)", f"✅ {st['cve_valid']}/{n}", "cve_id 格式有效(§4 采集口径须关联权威库)"]))
    H.append(tr(["GitHub 可溯源", f"{'✅' if st['github_url'] == n else '⚠️'} {st['github_url']}/{n}", "github_url 指向修复 commit"]))
    lic_ok = n - st["license_missing"]
    H.append(tr(["License 100% 覆盖(允许 AI 训练)", f"{'✅' if st['license_missing'] == 0 else '❌'} {lic_ok}/{n}", f"§9.8 硬性要求, 缺 {st['license_missing']} 条"]))
    H.append("</table>")
    H.append("<h3>4.1 项目来源(组织)分布</h3><table><tr><th>项目组织</th><th>记录数</th><th>占比</th></tr>")
    for k, v in sorted(st["owner"].items(), key=lambda x: -x[1]):
        H.append(tr([k, v, f"{v / nn * 100:.1f}%"]))
    H.append("</table>")
    dim_html("五、安全知识覆盖度", know)
    dist_html("5.1 编程语言分布", "lang")
    dist_html("5.2 严重等级分布", "severity")
    dist_html("5.3 漏洞类型分布", "vtype")
    dist_html("5.4 CWE 分类分布", "cwe")
    dist_html("5.5 CVE 年份分布", "year", sort_desc=False)
    dist_html("5.6 License 分布", "license_dist")
    H.append("<h2>六、全局质量指标(阈值汇总)</h2><table><tr><th>结果</th><th>指标</th><th>说明</th></tr>")
    for lvl, item, detail in global_rows:
        mark = {"PASS": "✅", "ERROR": "❌", "WARN": "⚠️"}[lvl]
        H.append(tr([mark, item, detail], lvl.lower() if lvl != "PASS" else ""))
    H.append("</table>")
    H.append("<h2>ERROR 明细(必须整改)</h2><table><tr><th>ID</th><th>检查项</th><th>详情</th></tr>")
    for r in fmt_rows(qc.error_rows):
        H.append(tr(r, "error"))
    H.append("</table>")
    H.append("<h2>WARN 明细(建议复核)</h2><table><tr><th>ID</th><th>检查项</th><th>详情</th></tr>")
    for r in fmt_rows(qc.warn_rows):
        H.append(tr(r, "warn"))
    H.append("</table></body></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(H))
    return md_path, html_path


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="漏洞修复commit数据集质检")
    ap.add_argument("paths", nargs="*", help="jsonl 文件或目录")
    ap.add_argument("--out", default=None, help="报告输出目录, 默认 ./qc_reports/")
    ap.add_argument("--no-diff-verify", action="store_true",
                    help="跳过 diff 自洽校验(大数据量时提速)")
    ap.add_argument("--sample", type=float, default=0, metavar="PCT",
                    help="随机抽样百分比(如 1 = 抽 1%%); 0=全量。固定 seed=2026 可复现")
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(base))
    if not args.paths:
        args.paths = [os.path.join(root, "data", "开源项目代码修复commit_20260831",
                                   "vuln_fix_commit_samples.jsonl")]
    out_dir = args.out or os.path.join(os.path.dirname(base), "qc_reports")
    os.makedirs(out_dir, exist_ok=True)

    # 采集器的拒绝留痕/单条验证产物, 非交付数据, 扫目录时跳过
    _SKIP_JSONL = {"rejected.jsonl"}
    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(f for f in glob.glob(os.path.join(p, "*.jsonl"))
                            if os.path.basename(f) not in _SKIP_JSONL)
        elif os.path.isfile(p):
            files.append(p)
    if not files:
        ap.error(f"未找到 jsonl 文件: {args.paths}")

    started_at = datetime.datetime.now()
    qc = VulnQC(verify_diff=not args.no_diff_verify)
    import random
    rng = random.Random(2026)
    sampled_total = 0
    for fpath in files:
        records, errors, bom = read_jsonl(fpath)
        if args.sample > 0 and len(records) > 1:
            full_n = len(records)
            k = max(1, int(round(full_n * args.sample / 100)))
            records = rng.sample(records, k)
            sampled_total += k
            log.info("抽样 %s: 全量 %d 条 → 抽检 %d 条(%.1f%%)", fpath, full_n, k, args.sample)
        log.info("读取 %s: %d 条, 解析失败 %d 行", fpath, len(records), len(errors))
        for lineno, err in errors:
            qc.add("ERROR", f"{os.path.basename(fpath)}:line{lineno}", "JSON解析失败", err)
        if bom:
            qc.add("ERROR", os.path.basename(fpath), "BOM", "文件含 UTF-8 BOM")
        for rec in records:
            qc.check_record(rec)

    md_path, html_path = write_reports(out_dir, qc, files, started_at,
                                       sample_pct=args.sample, sampled_n=sampled_total)
    st = qc.stats
    # 全局指标(语言红线/License 覆盖率/近3年占比等)也是验收硬指标, 须计入退出码
    global_rows = qc.check_global()
    global_errs = [r for r in global_rows if r[0] == "ERROR"]
    ok = not qc.error_rows and not global_errs
    log.info("=" * 60)
    log.info("质检完成: 样本 %d 条 | 记录ERROR %d | 记录WARN %d | 全局ERROR %d",
             st["total"], len(qc.error_rows), len(qc.warn_rows), len(global_errs))
    if not args.no_diff_verify:
        log.info("diff 自洽: 一致 %d / 不一致 %d / 跳过(ccF=false) %d",
                 st["consistent"], st["inconsist"], st["skipped_verify"])
    for _, item, detail in global_errs:
        log.warning("全局 ERROR: %s — %s", item, detail)
    log.info("报告: %s", md_path)
    log.info("      %s", html_path)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
