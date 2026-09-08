# -*- coding: utf-8 -*-
"""
文本重复 精确检测报告 生成脚本(独立于三份主质检脚本)
================================================================
基于 text-dedup (v0.4.0, pip install text-dedup) 的组件做文本重复的
精确/近似检测, 结果单独合并为一份报告。

为什么不能直接用 text-dedup 开箱流程(实测结论, 2026-08-31):
  1. 5/6 算法模块(minhash/simhash/bloom_filter/exact_hash/ccnet)在
     Windows 下 import 即失败: 模块级 mp.set_start_method("fork") 无
     fork 上下文 → ValueError; 仅 suffix_array 可导入, 但它依赖外部
     Rust 仓库 + cargo, 本机不可用。
  2. 其 MinHash 的 n-gram 为"词级"(NON_ALPHA.split 按空白分词),
     对中文文本几乎无效(中文无空白, 区分度实测 0.000);
     本脚本改为"字符级" n-gram, 实测对中文近似对区分度 0.781、
     英文代码近似对 0.484, 均有效。
  3. 其入口强依赖 HuggingFace datasets + parquet 管道; 本项目数据为
     JSONL, 无必要走该管道。

因此本脚本: 复用 text_dedup.utils 的 xxh3_32hash / optimal_param /
UnionFind 与 text_dedup.minhash 的 SEED(纯常量/纯函数, 无 fork 依赖),
自行实现"字符级 MinHash + LSH 候选召回 + 精确 Jaccard 验证"三段式检测。

检测层级(与主质检脚本的 MD5 判重互补):
  前置  规范化: 剔除 base64 内嵌图片(博客数据 99.8% 体积为图片载荷,
        单篇最大 95.8MB, 不剔除则 n-gram 计算不可行且图片载荷不应
        参与文本相似性判定) → 小写 → 去全部空白
  L1  精确重复: 规范化后全文 MD5 相同
  L2  近似重复: 字符级 n-gram(默认 n=5) MinHash(默认 256 位) + LSH
      候选召回 → 逐对精确 Jaccard 验证 → 阈值(默认 0.6)以上入组
  L3  组级汇总: 连通分量聚类, 输出每组成员/最大 Jaccard/可省字符数

用法:
    python text_dup_precise_qc.py [blog|qa|commit | jsonl文件 | 目录 ...]
        [--out 目录] [--threshold 0.6] [--ngram 5] [--num-perm 256]
    不指定参数时检查 data/ 下全部三个数据集。

输出: MD + HTML 双格式独立报告, 默认写入 ./qc_reports/
      文件名: 文本重复_精确检测报告_<时间戳>.md/.html
退出码: 存在重复组 → 1; 否则 0
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
# 导入 text-dedup 纯函数组件(打桩 set_start_method 以避开 fork 问题)
# ----------------------------------------------------------------------------
import multiprocessing as mp
_mp_orig_set_start_method = mp.set_start_method
mp.set_start_method = lambda *a, **k: None  # 保险: 防模块级 fork 调用
try:
    from text_dedup.minhash import SEED
    from text_dedup.utils import UnionFind
    from text_dedup.utils import optimal_param
    from text_dedup.utils import xxh3_32hash
except ImportError:
    sys.exit("[FATAL] 未安装 text-dedup, 请先: "
             "py311 python -m pip install text-dedup")
finally:
    mp.set_start_method = _mp_orig_set_start_method

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S", stream=sys.stderr)
log = logging.getLogger("text_dup_precise_qc")

# ----------------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------------
NORM_RE = re.compile(r"\s+")
# base64 内嵌图片(博客数据 99.8% 体积为图片载荷, 剔除后保留占位标记,
# 否则单篇最大 95.8MB 的文档做字符级 n-gram 不可行, 且图片载荷不应
# 参与"文本"重复判定 —— 同文异图/同图异码不应改变文本相似性)
RE_B64_IMG = re.compile(r"!\[[^\]]*\]\(data:image/[a-z]+;base64,[A-Za-z0-9+/=]+\)")
MIN_DOC_CHARS = 200  # 去图后少于此长度的文档不参与判重(碎片/纯图文)

DATASETS = {
    "blog": ("安全技术博客", "data/安全技术博客_20260826"),
    "qa": ("代码问答", "data/代码问答数据_20260813_simplems"),
    "commit": ("漏洞修复commit", "data/开源项目代码修复commit_20260826"),
}


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def norm_text(s):
    """规范化: 剔除 base64 内嵌图片(保留占位标记) → 小写 → 去除全部空白。"""
    s = RE_B64_IMG.sub("![](<base64_img>)", s or "")
    return NORM_RE.sub("", s.lower())


def char_ngrams(s, n):
    """字符级 n-gram 集合(替代 text-dedup 词级方案, 适配中文)。"""
    if len(s) < n:
        return {s.encode("utf-8")} if s else set()
    return {s[i:i + n].encode("utf-8") for i in range(len(s) - n + 1)}


def read_jsonl(path):
    """读取 JSONL: 返回 (记录列表, 解析失败行数); 校验 UTF-8 无 BOM。"""
    records, errors = [], 0
    with open(path, "rb") as f:
        raw = f.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        log.warning("%s 含 UTF-8 BOM", path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise SystemExit(f"[FATAL] {path} 非 UTF-8 编码: {e}")
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            errors += 1
    return records, errors


# ----------------------------------------------------------------------------
# 文本提取(三类数据集各自的"被检测正文"口径)
# ----------------------------------------------------------------------------
def extract_blog(rec):
    return rec.get("content") or ""


def extract_qa(rec):
    msg = rec.get("message") or []
    return "\n".join(
        f"{t.get('question', '')}\n{t.get('answer', '')}"
        for t in msg if isinstance(t, dict))


def extract_commit(rec):
    meta = rec.get("meta") or {}
    return "\n".join([
        meta.get("commit_message") or "",
        meta.get("vulnerable_code") or "",
        meta.get("fixed_code") or "",
        meta.get("unified_diff") or "",
    ])


EXTRACTORS = {"blog": extract_blog, "qa": extract_qa, "commit": extract_commit}


def collect_docs(key, paths):
    """收集某数据集的全部 (记录id, 规范化正文) 对。"""
    extract = EXTRACTORS[key]
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.jsonl")))
        elif os.path.isfile(p):
            files.append(p)
    if not files:
        raise FileNotFoundError(f"未找到 jsonl 文件: {paths}")

    docs, skipped_empty, skipped_short, parse_err = [], 0, 0, 0
    for fpath in files:
        records, errors = read_jsonl(fpath)
        parse_err += errors
        log.info("读取 %s: %d 条(解析失败 %d)", fpath, len(records), errors)
        for rec in records:
            rid = str(rec.get("id", "?"))
            s = norm_text(extract(rec))
            if not s:
                skipped_empty += 1
            elif len(s) < MIN_DOC_CHARS:
                skipped_short += 1
            else:
                docs.append((rid, s))
    return docs, {"parse_err": parse_err, "skipped_empty": skipped_empty,
                  "skipped_short": skipped_short, "files": len(files)}


# ----------------------------------------------------------------------------
# 检测核心
# ----------------------------------------------------------------------------
def build_minhashes(doc_norms, num_perm, ngram):
    """字符级 n-gram → xxh3_32hash → 随机线性变换 → 逐位取 min。

    与 text-dedup minhash.py 的 embed_func 同构, 仅 n-gram 粒度不同。
    返回 (signatures: list[np.ndarray], ngram_sets: list[set])
    """
    import numpy as np
    modulo_prime = (1 << 32) - 5
    rng = np.random.RandomState(SEED)
    a = rng.randint(1, modulo_prime, size=num_perm, dtype=np.uint32)
    b = rng.randint(0, modulo_prime, size=num_perm, dtype=np.uint32)
    max_h = np.full(num_perm, (1 << 32) - 1, dtype=np.uint32)

    sigs, sets_out = [], []
    for s in doc_norms:
        tokens = char_ngrams(s, ngram)
        hv = np.array([xxh3_32hash(t) for t in tokens],
                      dtype=np.uint32).reshape(-1, 1)
        hv = (hv * a + b) % modulo_prime
        sig = np.vstack([hv, max_h]).min(axis=0)
        sigs.append(sig)
        sets_out.append(tokens)
    return sigs, sets_out


def lsh_candidates(sigs, num_perm, threshold):
    """LSH banding 召回候选对(复用 text-dedup 的 optimal_param)。"""
    b, r = optimal_param(threshold, num_perm)
    ranges = [(i * r, (i + 1) * r) for i in range(b)]
    from collections import defaultdict
    tables = [defaultdict(list) for _ in range(b)]
    for idx, sig in enumerate(sigs):
        for bi, (lo, hi) in enumerate(ranges):
            tables[bi][tuple(sig[lo:hi])].append(idx)
    cand = set()
    for tbl in tables:
        for bucket in tbl.values():
            if len(bucket) > 1:
                bk = list(bucket)
                for i in range(len(bk)):
                    for j in range(i + 1, len(bk)):
                        cand.add((min(bk[i], bk[j]), max(bk[i], bk[j])))
    return cand, b, r


def precise_jaccard(sa, sb):
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    return inter / (len(sa) + len(sb) - inter) if inter else 0.0


def dedup_dataset(key, paths, threshold, ngram, num_perm, sample_pct=0, rng=None):
    """单数据集完整检测: L1 精确 + L2 近似 + L3 聚类, 返回结果 dict。

    sample_pct > 0 时按比例随机抽样(规范书"随机抽检 ≥1%"场景, 固定 rng
    可复现); 抽样模式下近似重复检出仅代表抽中子集, 跨抽样对的重复会
    漏检, 适合作抽检信号而非全局重复率结论。
    """
    docs, meta = collect_docs(key, paths)
    sampled_n = 0
    if sample_pct > 0 and len(docs) > 1 and rng is not None:
        full_n = len(docs)
        k = max(1, int(round(full_n * sample_pct / 100)))
        docs = rng.sample(docs, k)
        sampled_n = k
        meta = dict(meta, full_n=full_n)
        log.info("抽样: 全量 %d 条 → 抽检 %d 条(%.1f%%)", full_n, k, sample_pct)
    ids = [d[0] for d in docs]
    norms = [d[1] for d in docs]
    n = len(docs)

    # L1 精确重复(规范化后 MD5)
    md5s = [hashlib.md5(s.encode("utf-8")).hexdigest() for s in norms]
    seen, exact_pairs = {}, []
    for i, h in enumerate(md5s):
        if h in seen:
            exact_pairs.append((seen[h], i))
        else:
            seen[h] = i

    # L2 MinHash + LSH 召回 → 精确 Jaccard 验证
    sigs, ngram_sets = build_minhashes(norms, num_perm, ngram)
    cand, lsh_b, lsh_r = lsh_candidates(sigs, num_perm, threshold)
    sim_pairs = []
    for i, j in sorted(cand):
        if i == j:
            continue
        score = precise_jaccard(ngram_sets[i], ngram_sets[j])
        if score >= threshold:
            sim_pairs.append((i, j, score))

    # L3 连通分量聚类(精确 ∪ 近似)
    uf = UnionFind()
    for x, y in exact_pairs:
        uf.union(x, y)
    for x, y, _ in sim_pairs:
        uf.union(x, y)
    clusters = {}
    for i in range(n):
        clusters.setdefault(uf.find(i), []).append(i)
    groups = []
    for members_idx in (sorted(v) for v in clusters.values() if len(v) > 1):
        g_pairs = [(x, y) for x in range(len(members_idx))
                   for y in range(x + 1, len(members_idx))]
        scores = [precise_jaccard(ngram_sets[members_idx[x]],
                                  ngram_sets[members_idx[y]])
                  for x, y in g_pairs]
        exact_in = sum(1 for x, y in g_pairs
                       if md5s[members_idx[x]] == md5s[members_idx[y]])
        members = [(ids[i], len(norms[i])) for i in members_idx]
        groups.append({
            "members": members,
            "max_j": max(scores) if scores else 0.0,
            "exact_in": exact_in,
            "saveable": sum(m[1] for m in members) - max(m[1] for m in members),
        })
    groups.sort(key=lambda g: (-len(g["members"]), -g["saveable"]))

    return {
        "key": key,
        "n": n,
        "meta": meta,
        "sampled_n": sampled_n,
        "norms": norms,
        "ids": ids,
        "exact_pairs": exact_pairs,
        "near_groups": [g for g in groups if g["exact_in"] == 0],
        "groups": groups,
        "n_affected": sum(len(g["members"]) for g in groups),
        "lsh_b": lsh_b, "lsh_r": lsh_r,
        "threshold": threshold, "ngram": ngram, "num_perm": num_perm,
    }


# ----------------------------------------------------------------------------
# 报告输出
# ----------------------------------------------------------------------------
def _preview(s):
    return s[:80] + ("…" if len(s) > 80 else "")


def _sample_note(results):
    """拼接各数据集抽样描述。"""
    parts = []
    for r in results:
        if r.get("sampled_n"):
            parts.append(f"{DATASETS[r['key']][0]} {r['sampled_n']}/{r['meta'].get('full_n', '?')}")
    return ", ".join(parts)


NORM_DESC = "规范化(剔除 base64 内嵌图片→小写→去全部空白)"


def _group_md(res, g, idx):
    L = []
    tag = "含精确重复" if g["exact_in"] else "近似重复"
    L.append(f"#### 组 {idx} — {len(g['members'])} 条 "
             f"({tag}, 最大精确 Jaccard {g['max_j']:.3f}, "
             f"去重可省 {g['saveable']:,} 字符)")
    L.append("")
    L.append("| # | 记录 ID | 规范化字符数 | 正文摘要(前 80 字) |")
    L.append("|:---:|:---|---:|:---|")
    for k, (rid, ln) in enumerate(g["members"], 1):
        di = res["ids"].index(rid)
        L.append(f"| {k} | {rid} | {ln:,} | {esc(_preview(res['norms'][di]))} |")
    L.append("")
    return L


def write_report(out_dir, results, started_at):
    stamp = started_at.strftime("%Y%m%d_%H%M%S")
    base = os.path.join(out_dir, f"文本重复_精确检测报告_{stamp}")
    n_groups = sum(len(r["groups"]) for r in results)
    n_exact = sum(len(r["exact_pairs"]) for r in results)
    n_near = sum(len(r["near_groups"]) for r in results)
    verdict = n_groups == 0
    r0 = results[0]
    any_sampled = any(r.get("sampled_n") for r in results)
    sample_note = (f"抽检模式(共 {_sample_note(results)})" if any_sampled else "全量检测")

    # ---------- Markdown ----------
    L = []
    L.append("# 文本重复 精确检测报告")
    L.append("")
    L.append(f"> 生成时间: {started_at:%Y-%m-%d %H:%M:%S}")
    L.append(f"> 检查范围: {sample_note}(固定 seed=2026, 可复现)")
    L.append(f"> 方法: 字符级 MinHash({r0['num_perm']} 位, n-gram={r0['ngram']}) "
             f"+ LSH 召回(b={r0['lsh_b']}, r={r0['lsh_r']}) + 精确 Jaccard 验证"
             f"(哈希/参数/并查集组件来自 text-dedup v0.4.0)")
    L.append(f"> 近似阈值: 精确 Jaccard ≥ {r0['threshold']}")
    L.append("")
    L.append("## 一、总体结论")
    L.append("")
    L.append(f"**{'✅ 未发现重复' if verdict else '❌ 发现重复(需复核/整改)'}** — "
             f"精确重复 {n_exact} 对, 重复组 {n_groups} 个(纯近似组 {n_near} 个)")
    L.append("")
    L.append("## 二、数据集汇总")
    L.append("")
    L.append("| 数据集 | 参检条数 | 跳过(空/过短) | 精确重复对 | 重复组 | 纯近似组 | 涉及记录 | 可省字符 |")
    L.append("|:---|---:|---:|---:|---:|---:|---:|---:|")
    for r in results:
        name = DATASETS[r["key"]][0]
        L.append(f"| {name} | {r['n']:,} "
                 f"| {r['meta']['skipped_empty'] + r['meta']['skipped_short']} "
                 f"| {len(r['exact_pairs'])} | {len(r['groups'])} "
                 f"| {len(r['near_groups'])} | {r['n_affected']:,} "
                 f"| {sum(g['saveable'] for g in r['groups']):,} |")
    L.append("")

    sec_names = "三四五六七八九十"
    for si, r in enumerate(results, 3):
        name = DATASETS[r["key"]][0]
        sec_tag = sec_names[si - 3] if si - 3 < len(sec_names) else str(si)
        L.append(f"## {sec_tag}、{name} 明细")
        L.append("")
        L.append(f"- 参检 {r['n']:,} 条; 跳过 "
                 f"{r['meta']['skipped_empty'] + r['meta']['skipped_short']} 条"
                 f"(去图后为空 {r['meta']['skipped_empty']}, "
                 f"去图后 <{MIN_DOC_CHARS} 字 {r['meta']['skipped_short']}); "
                 f"解析失败 {r['meta']['parse_err']} 行; 文件 {r['meta']['files']} 个")
        if not r["groups"]:
            L.append("")
            L.append("无重复。")
            L.append("")
            continue
        for gi, g in enumerate(r["groups"], 1):
            L.extend(_group_md(r, g, gi))
    L.append("## 口径说明")
    L.append("")
    L.append(f"- **规范化口径**: {NORM_DESC}。博客数据 99.8% 体积为 base64 "
             "内嵌图片(单篇最大 95.8MB), 剔除后仅对真实文本做判重, "
             "图片以 `![](<base64_img>)` 占位(图片张数仍计入正文)。")
    if any_sampled:
        L.append("- **抽检模式语义**: 检测仅在抽中子集内进行——抽样内的精确/"
                 "近似重复可直接定位整改, 但跨抽样的重复对会漏检; 结论适合作"
                 "抽检信号(规范书'随机抽检 ≥1%'), 不能外推为全局重复率。")
    L.append(f"- **精确重复**: {NORM_DESC} 后全文 MD5 相同。")
    L.append("- **近似重复**: 字符级 n-gram 精确 Jaccard ≥ 阈值; "
             "先经 LSH 候选召回再逐对验证, 无 LSH 假阳性。")
    L.append("- **与主质检脚本的关系**: 主脚本正文判重仅做 `content.strip()` "
             "MD5(保留内部空白/大小写、含 base64 图片载荷), 本脚本规范化"
             "更激进且覆盖近似层, 两者互补。")
    L.append(f"- **跳过规则**: 去图规范化后为空或 <{MIN_DOC_CHARS} 字的文档"
             "不参与判重(碎片/纯图文记录)。")
    L.append("- **commit 被检测文本** = commit_message + vulnerable_code + "
             "fixed_code + unified_diff 拼接; 同一项目的不同 CVE 修改同一文件, "
             "全文天然高度相似(如 mruby 的 codegen.c、radare2 的 io_bank), "
             "属正常现象, 命中近似组需人工确认是否构成重复交付。")
    L.append("- **代码问答同题多语言**: 同一 LeetCode 题目的不同语言版本记录, "
             "题面相同、解答语言不同, 近似 Jaccard 接近 1.0, 与主质检脚本的"
             "\"同题多语言\" WARN 对应, 是否算重复需与验收方确认口径。")
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    # ---------- HTML ----------
    H = []
    H.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    H.append(f"<title>文本重复精确检测报告 {stamp}</title>")
    H.append("<style>body{font-family:'Microsoft YaHei',sans-serif;margin:24px;}"
             "table{border-collapse:collapse;margin:8px 0;}"
             "td,th{border:1px solid #ccc;padding:6px 10px;vertical-align:top;}"
             "th{background:#f0f4f8;} h1{color:#1a3a5c;} "
             "h2{color:#2c5282;border-bottom:2px solid #2c5282;padding-bottom:4px;}"
             "h3{color:#2d3748;} .err{color:#c53030;font-weight:bold;} "
             ".pass{color:#276749;font-weight:bold;} "
             ".preview{max-width:460px;color:#4a5568;font-size:12px;}"
             ".meta{color:#4a5568;font-size:13px;}</style></head><body>")
    H.append("<h1>文本重复 精确检测报告</h1>")
    H.append(f"<p class='meta'>生成时间: {started_at:%Y-%m-%d %H:%M:%S} | "
             f"检查范围: {esc(sample_note)} | "
             f"方法: 字符级 MinHash({r0['num_perm']} 位, n-gram={r0['ngram']}) "
             f"+ LSH(b={r0['lsh_b']}, r={r0['lsh_r']}) + 精确 Jaccard 验证 | "
             f"近似阈值: Jaccard ≥ {r0['threshold']}</p>")
    H.append(f"<p class='{'pass' if verdict else 'err'}'>"
             f"{'✅ 未发现重复' if verdict else '❌ 发现重复(需复核/整改)'} — "
             f"精确重复 {n_exact} 对, 重复组 {n_groups} 个(纯近似组 {n_near} 个)</p>")
    H.append("<h2>数据集汇总</h2>")
    H.append("<table><tr><th>数据集</th><th>参检</th><th>跳过</th><th>精确重复对</th>"
             "<th>重复组</th><th>纯近似组</th><th>涉及记录</th><th>可省字符</th></tr>")
    for r in results:
        H.append(f"<tr><td>{DATASETS[r['key']][0]}</td><td>{r['n']:,}</td>"
                 f"<td>{r['meta']['skipped_empty'] + r['meta']['skipped_short']}</td>"
                 f"<td>{len(r['exact_pairs'])}</td><td>{len(r['groups'])}</td>"
                 f"<td>{len(r['near_groups'])}</td><td>{r['n_affected']:,}</td>"
                 f"<td>{sum(g['saveable'] for g in r['groups']):,}</td></tr>")
    H.append("</table>")

    for r in results:
        H.append(f"<h2>{DATASETS[r['key']][0]} 明细</h2>")
        if not r["groups"]:
            H.append("<p>无重复。</p>")
            continue
        for gi, g in enumerate(r["groups"], 1):
            cls = "err" if g["exact_in"] else ""
            tag = "含精确重复" if g["exact_in"] else "近似重复"
            H.append(f"<h3>组 {gi} — {len(g['members'])} 条 "
                     f"[<span class='{cls}'>{tag}</span> "
                     f"J={g['max_j']:.3f}, 可省 {g['saveable']:,} 字符]</h3>")
            H.append("<table><tr><th>#</th><th>记录 ID</th>"
                     "<th>规范化字符数</th><th>正文摘要(前 80 字)</th></tr>")
            for k, (rid, ln) in enumerate(g["members"], 1):
                di = r["ids"].index(rid)
                H.append(f"<tr><td>{k}</td><td>{esc(rid)}</td><td>{ln:,}</td>"
                         f"<td class='preview'>{esc(_preview(r['norms'][di]))}</td></tr>")
            H.append("</table>")
    H.append("<h2>口径说明</h2><ul>"
             f"<li><b>规范化口径</b>: {NORM_DESC}; 博客数据 99.8% 体积为 "
             "base64 内嵌图片, 剔除后仅对真实文本判重。</li>"
             f"<li><b>精确重复</b>: {NORM_DESC} 后全文 MD5 相同。</li>"
             "<li><b>近似重复</b>: 字符级 n-gram 精确 Jaccard ≥ 阈值, "
             "LSH 召回后逐对验证, 无假阳性。</li>"
             f"<li>去图规范化后为空或 &lt;{MIN_DOC_CHARS} 字的文档不参与判重。</li>"
             "<li>commit 被检测文本 = commit_message + vulnerable_code + "
             "fixed_code + unified_diff 拼接; 同一项目不同 CVE 修改同一文件"
             "天然高相似, 需人工确认。</li>"
             "<li>代码问答同题多语言: 题面相同、解答语言不同, Jaccard 接近 1.0, "
             "是否算重复需与验收方确认口径。</li>"
             "<li>与主质检脚本互补: 主脚本正文判重保留内部空白/大小写、"
             "含 base64 载荷, 本脚本更激进且含近似层。</li></ul>")
    H.append("</body></html>")
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write("\n".join(H))
    return base + ".md", base + ".html"


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="文本重复精确检测(基于 text-dedup 组件)")
    ap.add_argument("targets", nargs="*",
                    help="数据集名称(blog/qa/commit)或 jsonl 文件/目录, 默认全部三个")
    ap.add_argument("--out", default=None, help="报告输出目录, 默认 ./qc_reports/")
    ap.add_argument("--threshold", type=float, default=0.6,
                    help="近似 Jaccard 阈值(默认 0.6)")
    ap.add_argument("--ngram", type=int, default=5,
                    help="字符级 n-gram 大小(默认 5, 中文/代码通用)")
    ap.add_argument("--num-perm", type=int, default=256,
                    help="MinHash 位数(默认 256)")
    ap.add_argument("--sample", type=float, default=0, metavar="PCT",
                    help="随机抽样百分比(如 1 = 抽 1%%, 规范书随机抽检 ≥1%%); 0=全量。固定 seed=2026")
    args = ap.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(base_dir))
    out_dir = args.out or os.path.join(os.path.dirname(base_dir), "qc_reports")
    os.makedirs(out_dir, exist_ok=True)

    targets = []
    for t in (args.targets or list(DATASETS.keys())):
        if t in DATASETS:
            targets.append((t, [os.path.join(root, DATASETS[t][1])]))
        else:
            key = ("qa" if "代码问答" in t
                   else "commit" if "commit" in t.lower()
                   else "blog")
            targets.append((key, [t]))
    if len({k for k, _ in targets}) != len(targets):
        ap.error("同一数据集被重复指定")

    started_at = datetime.datetime.now()
    import random
    rng = random.Random(2026)  # 固定 seed, 抽检结果可复现
    results = []
    for key, paths in targets:
        name = DATASETS[key][0]
        log.info("=== 检测 %s ===", name)
        res = dedup_dataset(key, paths, args.threshold, args.ngram, args.num_perm,
                            sample_pct=args.sample, rng=rng)
        log.info("%s: 参检 %d | 精确重复 %d 对 | 重复组 %d (纯近似 %d) | 涉及 %d 条",
                 name, res["n"], len(res["exact_pairs"]), len(res["groups"]),
                 len(res["near_groups"]), res["n_affected"])
        results.append(res)

    md_path, html_path = write_report(out_dir, results, started_at)
    n_g = sum(len(r["groups"]) for r in results)
    n_e = sum(len(r["exact_pairs"]) for r in results)
    log.info("=" * 60)
    log.info("检测完成: 精确重复 %d 对 | 重复组 %d 个", n_e, n_g)
    log.info("报告: %s", md_path)
    log.info("      %s", html_path)
    sys.exit(1 if n_g else 0)


if __name__ == "__main__":
    main()
