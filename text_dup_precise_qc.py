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

与主质检脚本内置 near-dup 的分工(为什么两套并存):
  - code_qa_qc/blog_qc/vuln_commit_qc 内置的近似检测是 5-gram shingles
    两两对比, 需全量驻留内存 → 仅适合 ≤5000 条的小数据集/分片, 超限自动
    跳过并在报告标注"➖ 未执行"。定位: 交付质检报告里的例行体检项。
  - 本脚本用 MinHash+LSH(签名紧凑, 无 5000 上限), 可一条命令跑全量
    18 万+条, 且支持三个数据集联合检查、博客 base64 载荷剔除、L3 组级
    聚类。定位: 数据冻结后的专项深度去重(终检), 与分片方案交叉验证。

资源开销与优化(数据量大时仍建议抽检/分片, 非必要不进行):
  内存  ① 逐行流式读取, 不再整文件载入; ② 不再全量驻留每个文档的 n-gram
        集合(原为最大开销, 单文档 1 万字符 ≈ 64 万字节), 改为按需计算 +
        有界 LRU 缓存(--ngram-cache); ③ MinHash 只保留 n × num_perm 的
        uint32 签名矩阵(约 1KB/条)。
        仍在内存中的: 规范化正文(约 1~3 字节/字符, 图片载荷已剔除)。
   CPU  ① 签名不再构造 n-gram 集合(取 min 与去重无关, 结果不变);
        ② 候选对先按签名估计预筛(--prefilter-margin, 默认 0.2), 与阈值
        差距大的候选对不做精确 Jaccard, 实际漏检概率可忽略(≥6σ);
        ③ 组内两两 Jaccard 复用 L2 已算出的分数, 全同组直接判定为 1.0。
  磁盘  报告体积由"重复组数 × 成员数"决定, 已在写入时打印实际大小。

进度日志:
  各阶段(读文件/提取正文/精确判重/MinHash/LSH 分桶/候选召回/预筛/Jaccard
  验证/聚类/生成报告)均按 5%~10% 刻度向 stderr 打印进度与耗时, 终端可见。

用法:
    python text_dup_precise_qc.py [blog|qa|commit | jsonl文件 | 目录 ...]
        [--out 目录] [--threshold 0.6] [--ngram 5] [--num-perm 256]
        [--sample 1] [--ngram-cache 200] [--prefilter-margin 0.2]
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
import time
from collections import defaultdict

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
def mb(nbytes):
    """字节数转 MB 文本。"""
    return nbytes / 1024.0 / 1024.0


class Progress:
    """终端进度打印: 每完成 step_pct% 打一行, 避免逐条打印本身成为开销。

    total=0 表示总量未知(如逐行解析大文件), 退化为"每 every 条打一行"。
    每条进度带已完成量/百分比/耗时, 便于估算剩余时间与定位卡点阶段。
    """

    def __init__(self, label, total=0, step_pct=5.0, every=5000):
        self.label = label
        self.total = max(0, int(total))
        self.step = (max(1, int(self.total * step_pct / 100.0))
                     if self.total else max(1, int(every)))
        self.next_at = self.step
        self.t0 = time.time()

    def update(self, done, extra=""):
        if done < self.next_at:
            return
        elapsed = time.time() - self.t0
        tail = f" | {extra}" if extra else ""
        if self.total:
            log.info("%s: %d/%d (%.1f%%) 已用 %.1fs%s", self.label, done,
                     self.total, done * 100.0 / self.total, elapsed, tail)
        else:
            log.info("%s: %d 条 已用 %.1fs%s", self.label, done, elapsed, tail)
        self.next_at = done + self.step

    def done(self, done=None, extra=""):
        """收尾: 无论是否到刻度都打一行(空阶段不打印), 并返回该阶段耗时。"""
        done = self.total if done is None else done
        if not done:
            return time.time() - self.t0
        self.next_at = 0
        self.update(done, extra)
        return time.time() - self.t0


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def norm_text(s):
    """规范化: 剔除 base64 内嵌图片(保留占位标记) → 小写 → 去除全部空白。"""
    s = RE_B64_IMG.sub("![](<base64_img>)", s or "")
    return NORM_RE.sub("", s.lower())


def char_ngrams(s, n):
    """字符级 n-gram 集合(替代 text-dedup 词级方案, 适配中文)。

    精确 Jaccard 的判定基准, 语义不可变。集合常驻内存是本脚本最大的
    内存开销(单文档 1 万字符 ≈ 64 万字节), 故不再全量持有 —— 由
    NgramCache 按需计算并做有界 LRU 缓存。
    """
    if len(s) < n:
        return {s.encode("utf-8")} if s else set()
    return {s[i:i + n].encode("utf-8") for i in range(len(s) - n + 1)}


def iter_ngrams(s, n):
    """逐个产出字符级 n-gram(不构造集合, 省一次全量 bytes 驻留)。

    MinHash 只取哈希最小值, 而"重复值不改变最小值", 故签名阶段无需去重:
    对多重集取 min 与对集合取 min 结果完全一致。Jaccard 仍需集合语义,
    故 char_ngrams 保持原样不动。
    """
    if len(s) < n:
        if s:
            yield s.encode("utf-8")
        return
    for i in range(len(s) - n + 1):
        yield s[i:i + n].encode("utf-8")


class NgramCache:
    """按需计算 + 有界 LRU 缓存的 n-gram 集合提供器。

    max_docs 限制常驻的文档集合数(默认 200, 单文档 1 万字符 ≈ 0.6MB),
    内存上限与"参检条数"解耦; 缓存未命中时按 O(文本长度) 重算, 与
    一次集合交运算同量级, 故只是常数倍代价, 不改变复杂度。
    """

    def __init__(self, texts, ngram, max_docs):
        self.texts = texts
        self.ngram = ngram
        self.max_docs = max(1, int(max_docs))
        self._cache = {}               # dict 保序, 队尾为最近使用
        self.hits = 0
        self.misses = 0

    def get(self, i):
        s = self._cache.get(i)
        if s is not None:
            self.hits += 1
            self._cache.pop(i)         # 重新插入 → 移到队尾(O(1))
            self._cache[i] = s
            return s
        self.misses += 1
        s = char_ngrams(self.texts[i], self.ngram)
        self._cache[i] = s
        if len(self._cache) > self.max_docs:
            self._cache.pop(next(iter(self._cache)))   # 淘汰最久未用(队首)
        return s

    def stats(self):
        total = self.hits + self.misses
        rate = (self.hits * 100.0 / total) if total else 0.0
        return (f"n-gram 缓存: 命中 {self.hits:,} / 未命中 {self.misses:,}"
                f"(命中率 {rate:.1f}%, 上限 {self.max_docs} 个文档)")


def iter_jsonl(path):
    """流式逐行读取 JSONL: 逐行产出 (记录, 是否解析成功)。

    二进制模式按 b"\\n" 切分 —— 与旧实现 text.split("\\n") 口径一致
    (不用 splitlines: U+2028/U+2029 等行界符会把一条记录拆成多段),
    但不再整文件载入, 内存与文件大小解耦。
    """
    with open(path, "rb") as f:
        first = True
        for raw in f:
            if first:
                first = False
                if raw.startswith(b"\xef\xbb\xbf"):
                    log.warning("%s 含 UTF-8 BOM", path)
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise SystemExit(f"[FATAL] {path} 非 UTF-8 编码: {e}")
            if not line.strip():
                continue
            try:
                yield json.loads(line), True
            except json.JSONDecodeError:
                yield None, False


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
    for fi, fpath in enumerate(files, 1):
        log.info("[文件 %d/%d] 流式读取 %s (%.1f MB)…", fi, len(files), fpath,
                 mb(os.path.getsize(fpath)))
        t_read = time.time()
        pbar = Progress(f"  提取正文 {os.path.basename(fpath)}", every=5000)
        n_read = 0
        for rec, ok in iter_jsonl(fpath):
            if not ok:
                parse_err += 1
                continue
            n_read += 1
            rid = str(rec.get("id", "?"))
            s = norm_text(extract(rec))
            if not s:
                skipped_empty += 1
            elif len(s) < MIN_DOC_CHARS:
                skipped_short += 1
            else:
                docs.append((rid, s))
            pbar.update(n_read, extra=f"已收 {len(docs)} 条")
        pbar.done(n_read, extra=f"已收 {len(docs)} 条")
        log.info("  %s: 读入 %d 条, 耗时 %.1fs",
                 os.path.basename(fpath), n_read, time.time() - t_read)
    log.info("参检文档合计 %d 条(跳过: 空 %d / 过短 %d), 正文合计 %.1f MB",
             len(docs), skipped_empty, skipped_short,
             mb(sum(len(d[1]) for d in docs)))
    return docs, {"parse_err": parse_err, "skipped_empty": skipped_empty,
                  "skipped_short": skipped_short, "files": len(files)}


# ----------------------------------------------------------------------------
# 检测核心
# ----------------------------------------------------------------------------
def build_minhashes(doc_norms, num_perm, ngram):
    """字符级 n-gram → xxh3_32hash → 随机线性变换 → 逐位取 min。

    与 text-dedup minhash.py 的 embed_func 同构, 仅 n-gram 粒度不同。
    返回签名矩阵 (n × num_perm, uint32, 约 1KB/条); n-gram 集合不在此驻留,
    改由 NgramCache 按需计算 —— 这是本函数最大的内存优化。
    """
    import numpy as np
    modulo_prime = (1 << 32) - 5
    rng = np.random.RandomState(SEED)
    a = rng.randint(1, modulo_prime, size=num_perm, dtype=np.uint32)
    b = rng.randint(0, modulo_prime, size=num_perm, dtype=np.uint32)
    max_h = np.full(num_perm, (1 << 32) - 1, dtype=np.uint32)

    n = len(doc_norms)
    sig_mat = np.empty((n, num_perm), dtype=np.uint32)
    total_ngrams = 0
    pbar = Progress("MinHash 签名", n, step_pct=5.0)
    for k, s in enumerate(doc_norms, 1):
        cnt = (len(s) - ngram + 1) if len(s) >= ngram else (1 if s else 0)
        if cnt <= 0:
            sig_mat[k - 1] = max_h
            continue
        total_ngrams += cnt
        # 逐 n-gram 边产出边哈希, 不构造集合(取 min 与是否去重无关, 结果一致)
        hv = np.fromiter((xxh3_32hash(t) for t in iter_ngrams(s, ngram)),
                         dtype=np.uint32, count=cnt).reshape(-1, 1)
        hv = (hv * a + b) % modulo_prime
        sig_mat[k - 1] = np.minimum(hv.min(axis=0), max_h)
        pbar.update(k, extra=f"累计 n-gram {total_ngrams:,}")
    pbar.done(n, extra=f"累计 n-gram {total_ngrams:,}")
    return sig_mat


def lsh_candidates(sig_mat, num_perm, threshold):
    """LSH banding 召回候选对(复用 text-dedup 的 optimal_param)。

    索引统一 0-based。旧实现用 enumerate(sigs, 1) 生成桶索引, 导致第 0 条
    永不参与比较、末条索引越界(IndexError) —— 已修正为 0-based。
    """
    b, r = optimal_param(threshold, num_perm)
    ranges = [(i * r, (i + 1) * r) for i in range(b)]
    n = sig_mat.shape[0]
    log.info("LSH 参数: b=%d 段 × r=%d 行 (阈值 %.2f, %d 位签名)",
             b, r, threshold, num_perm)
    tables = [defaultdict(list) for _ in range(b)]
    pbar = Progress("LSH 分桶", n, step_pct=5.0)
    for idx in range(n):
        for bi, (lo, hi) in enumerate(ranges):
            tables[bi][tuple(sig_mat[idx, lo:hi])].append(idx)
        pbar.update(idx + 1)
    pbar.done(n)

    cand = set()
    max_bucket = 0
    pbar2 = Progress("LSH 候选对召回", b, step_pct=10.0)
    for ti, tbl in enumerate(tables, 1):
        for bucket in tbl.values():
            if len(bucket) > 1:
                max_bucket = max(max_bucket, len(bucket))
                bk = list(bucket)
                for i in range(len(bk)):
                    for j in range(i + 1, len(bk)):
                        cand.add((min(bk[i], bk[j]), max(bk[i], bk[j])))
        pbar2.update(ti, extra=f"候选对 {len(cand):,}")
    pbar2.done(b, extra=f"候选对 {len(cand):,}")
    if max_bucket >= 1000:
        log.warning("最大 LSH 桶 %d 条: 桶内两两枚举与后续验证随桶大小平方"
                    "增长; 若为大量完全相同的文档, 建议先做精确去重", max_bucket)
    return cand, b, r


def precise_jaccard(sa, sb):
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    return inter / (len(sa) + len(sb) - inter) if inter else 0.0


def dedup_dataset(key, paths, threshold, ngram, num_perm, sample_pct=0, rng=None,
                  ngram_cache_docs=200, prefilter_margin=0.2):
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
    id_index = {}                      # 报告取摘要用: id → 下标(取首次出现)
    for i, rid in enumerate(ids):
        id_index.setdefault(rid, i)
    log.info("参检 %d 条, 规范化后合计 %d 字符", n, sum(len(s) for s in norms))

    # L1 精确重复(规范化后 MD5)
    pbar = Progress("L1 精确判重(MD5)", n, step_pct=10.0)
    md5s = []
    for k, s in enumerate(norms, 1):
        md5s.append(hashlib.md5(s.encode("utf-8")).hexdigest())
        pbar.update(k)
    pbar.done(n)
    seen, exact_pairs = {}, []
    for i, h in enumerate(md5s):
        if h in seen:
            exact_pairs.append((seen[h], i))
        else:
            seen[h] = i
    log.info("L1 完成: 精确重复 %d 对", len(exact_pairs))

    # L2 MinHash + LSH 召回 → 精确 Jaccard 验证
    sig_mat = build_minhashes(norms, num_perm, ngram)
    cand, lsh_b, lsh_r = lsh_candidates(sig_mat, num_perm, threshold)
    cand_list = sorted(cand)           # 列表仅存引用(元组共享), 且有序 → 缓存局部性好
    prefilter_skip = 0
    if prefilter_margin > 0 and cand_list:
        import numpy as np
        floor = threshold - prefilter_margin
        kept = []
        for i, j in cand_list:
            if (np.count_nonzero(sig_mat[i] == sig_mat[j]) / num_perm) >= floor:
                kept.append((i, j))
        prefilter_skip = len(cand_list) - len(kept)
        log.info("候选对预筛(签名估计 ≥ %.3f): %d → %d 对, 跳过 %d 对",
                 floor, len(cand_list), len(kept), prefilter_skip)
        cand_list = kept
    log.info("L2 候选对 %d 对, 开始逐对精确 Jaccard 验证(此步 CPU 最重)…",
             len(cand_list))
    cache = NgramCache(norms, ngram, ngram_cache_docs)
    sim_pairs = []
    pbar = Progress("L2 Jaccard 验证", len(cand_list), step_pct=5.0)
    for k, (i, j) in enumerate(cand_list, 1):
        score = precise_jaccard(cache.get(i), cache.get(j))
        if score >= threshold:
            sim_pairs.append((i, j, score))
        pbar.update(k, extra=f"命中 {len(sim_pairs)}")
    pbar.done(len(cand_list), extra=f"命中 {len(sim_pairs)}")
    log.info("L2 完成: 近似重复 %d 对(阈值 %.2f) | %s",
             len(sim_pairs), threshold, cache.stats())

    # L3 连通分量聚类(精确 ∪ 近似)
    uf = UnionFind()
    for x, y in exact_pairs:
        uf.union(x, y)
    for x, y, _ in sim_pairs:
        uf.union(x, y)
    clusters = {}
    pbar = Progress("L3 并查集聚类", n, step_pct=10.0)
    for i in range(n):
        clusters.setdefault(uf.find(i), []).append(i)
        pbar.update(i + 1)
    pbar.done(n)
    multi = [sorted(v) for v in clusters.values() if len(v) > 1]
    log.info("L3 重复组 %d 个, 最大组 %d 条; 计算组内两两 Jaccard(随组大小平方增长)…",
             len(multi), max((len(v) for v in multi), default=0))
    # 已知分数复用: L2 已验证的对 + 精确重复对(Jaccard 恒为 1.0), 免去重复计算
    known = {(x, y): sc for x, y, sc in sim_pairs}
    for x, y in exact_pairs:
        known[(x, y)] = 1.0
    groups = []
    pbar = Progress("L3 组内两两 Jaccard", len(multi), step_pct=10.0)
    for gi, members_idx in enumerate(multi, 1):
        if len(members_idx) >= 200:
            log.info("  组 %d 成员 %d 条 → 组内需比较 %d 对(耗时平方增长)",
                     gi, len(members_idx),
                     len(members_idx) * (len(members_idx) - 1) // 2)
        g_pairs = [(x, y) for x in range(len(members_idx))
                   for y in range(x + 1, len(members_idx))]
        scores, exact_in = [], 0
        for x, y in g_pairs:
            ia, ib = members_idx[x], members_idx[y]
            if md5s[ia] == md5s[ib]:       # 规范化后全文一致 → Jaccard 恒为 1.0
                scores.append(1.0)
                exact_in += 1
                continue
            sc = known.get((ia, ib))
            scores.append(sc if sc is not None
                          else precise_jaccard(cache.get(ia), cache.get(ib)))
        members = [(ids[i], len(norms[i])) for i in members_idx]
        groups.append({
            "members": members,
            "max_j": max(scores) if scores else 0.0,
            "exact_in": exact_in,
            "saveable": sum(m[1] for m in members) - max(m[1] for m in members),
        })
        pbar.update(gi, extra=f"当前组 {len(members_idx)} 条")
    pbar.done(len(multi))
    groups.sort(key=lambda g: (-len(g["members"]), -g["saveable"]))
    log.info("L3 完成 | %s", cache.stats())

    return {
        "key": key,
        "n": n,
        "meta": meta,
        "sampled_n": sampled_n,
        "norms": norms,
        "ids": ids,
        "id_index": id_index,
        "prefilter_skip": prefilter_skip,
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
        di = res["id_index"][rid]      # 字典查表, 替代 O(n) 的 list.index()
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
    log.info("生成报告: 重复组 %d 个(逐组展开全部成员, 组多时报告文件会很大)…",
             n_groups)
    pbar = Progress("写入 Markdown 明细", n_groups, step_pct=10.0)
    n_written = 0

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
            n_written += 1
            pbar.update(n_written, extra=f"{name} 组 {gi}/{len(r['groups'])}")
    pbar.done(n_written)
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
    if sum(r.get("prefilter_skip", 0) for r in results):
        L.append("- **候选对预筛(性能优化)**: LSH 候选对先按签名估计 Jaccard 预筛, "
                 "估计 < 阈值−margin 的对不做精确验证 —— 被跳过的对与阈值差距大"
                 "(≥6σ, 漏检概率可忽略), 可用 `--prefilter-margin 0` 关闭。")
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
    log.info("Markdown 报告已写入(%.1f MB)", mb(os.path.getsize(base + ".md")))

    # ---------- HTML ----------
    pbar = Progress("写入 HTML 明细", n_groups, step_pct=10.0)
    n_written = 0
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
                di = r["id_index"][rid]    # 字典查表, 替代 O(n) 的 list.index()
                H.append(f"<tr><td>{k}</td><td>{esc(rid)}</td><td>{ln:,}</td>"
                         f"<td class='preview'>{esc(_preview(r['norms'][di]))}</td></tr>")
            H.append("</table>")
            n_written += 1
            pbar.update(n_written,
                        extra=f"{DATASETS[r['key']][0]} 组 {gi}/{len(r['groups'])}")
    pbar.done(n_written)
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
    log.info("HTML 报告已写入(%.1f MB)", mb(os.path.getsize(base + ".html")))
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
    ap.add_argument("--ngram-cache", type=int, default=200, metavar="N",
                    help="常驻缓存的文档 n-gram 集合数上限(默认 200)。"
                         "调大可减少重算、提高 CPU 效率但更占内存; 调小则相反")
    ap.add_argument("--prefilter-margin", type=float, default=0.2, metavar="M",
                    help="候选对预筛余量(默认 0.2): 签名估计 Jaccard < 阈值−M 的候选对"
                         "跳过精确验证(≥6σ 差距, 漏检概率可忽略); 0=关闭, 全部精确验证")
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
    log.info("检测目标: %s | 阈值 %.2f | n-gram %d | 签名 %d 位 | %s",
             ", ".join(DATASETS[k][0] for k, _ in targets), args.threshold,
             args.ngram, args.num_perm,
             f"抽样 {args.sample}%" if args.sample > 0 else "全量")
    log.info("性能参数: n-gram 缓存 %d 个文档 | 候选对预筛 margin %.2f",
             args.ngram_cache, args.prefilter_margin)
    log.info("提示: 正文需全量驻留内存, 数据量大时请用 --sample 抽检或先分片; "
             "非必要不进行, 可随时 Ctrl-C 中断")
    results = []
    for ti, (key, paths) in enumerate(targets, 1):
        name = DATASETS[key][0]
        log.info("=== [%d/%d] 检测 %s ===", ti, len(targets), name)
        t_ds = time.time()
        res = dedup_dataset(key, paths, args.threshold, args.ngram, args.num_perm,
                            sample_pct=args.sample, rng=rng,
                            ngram_cache_docs=args.ngram_cache,
                            prefilter_margin=args.prefilter_margin)
        log.info("%s: 参检 %d | 精确重复 %d 对 | 重复组 %d (纯近似 %d) | 涉及 %d 条"
                 " | 耗时 %.1fs",
                 name, res["n"], len(res["exact_pairs"]), len(res["groups"]),
                 len(res["near_groups"]), res["n_affected"], time.time() - t_ds)
        results.append(res)

    md_path, html_path = write_report(out_dir, results, started_at)
    n_g = sum(len(r["groups"]) for r in results)
    n_e = sum(len(r["exact_pairs"]) for r in results)
    log.info("=" * 60)
    log.info("检测完成: 精确重复 %d 对 | 重复组 %d 个 | 总耗时 %.1fs",
             n_e, n_g, time.time() - started_at.timestamp())
    log.info("报告: %s", md_path)
    log.info("      %s", html_path)
    sys.exit(1 if n_g else 0)


if __name__ == "__main__":
    main()
