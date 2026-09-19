# data-quality-control

网络安全领域训练数据集（代码问答 / 安全技术博客 / 漏洞修复 commit）的质量控制工具箱。

针对大规模 JSONL 语料的全量质检场景设计，核心特色是 **流式 O(1) 内存架构**——单进程即可处理数十万乃至百万条样本，无需担心近似查重的内存爆炸。

## ⚠️ 重要声明：检测结果仅供参考

本仓库的所有质检脚本用于**统一数据验收口径**，输出的报告（ERROR / WARN / 达标与否）**仅作为批量筛查的第一道参考**，**不是最终验收结论**。

规则化、启发式判断不可避免存在**误报 / 漏报**，例如：

- 正则启发式（隐私、截断、低质、非技术内容等）会在真实数据上产生边界误判，也可能放过语义层面才发现的瑕疵；
- 自洽性、真实性、权威性、问题与答案是否匹配等**语义级问题，脚本无法真正判断**；
- 报告给出的是"命中规则特征"的候选，命中项仍需逐条确认。

因此：**对脚本检测结果的每条疑问项，都必须经人工复检或大模型逐条确认后方可采信。** 脚本结论用于"筛出来、给依据、划重点"，验收口径的最终判定权在人工 / 大模型复核。

## 组件

| 脚本 | 用途 |
|---|---|
| `code_qa_qc.py` | 代码问答数据集质检：验收硬指标 / 抽样代码功能校验 / 问答真实性 / 重复率 / 脱敏 / 低质过滤 / 整改明细（规范书 §10 全结构报告）|
| `blog_qc.py` | 安全技术博客数据集质检：权威源覆盖率 / 图片处理 / 匿名化与去武器化 / CVE 标注 |
| `vuln_commit_qc.py` | 漏洞修复 commit 数据集质检：diff 自洽还原 / 代码四件套完整性 / CVE 关联 / License 白名单 |
| `text_dup_precise_qc.py` | 文本重复精确 / 近似检测（字符级 MinHash + LSH 召回 + Jaccard 验证，与主脚本的 MD5 判重互补）|

## ⚠️ 近似查重非必要不进行

**精确判重（规范化后 MD5）已能覆盖绝大多数重复场景**，近似查重（主脚本内置 near-dup 与 `text_dup_precise_qc.py`）是**重资源操作**，数据量大时 CPU / 内存 / 磁盘都会显著增长，**仅在数据冻结后的专项终检、或验收方明确要求近似重复率时才执行**。

资源开销现状（`text_dup_precise_qc.py` 已按下列方式优化）：

| 资源 | 现状 | 说明 |
|---|---|---|
| 内存 | 已优化 | ① 逐行流式读取，不再整文件载入；② 不再全量驻留每个文档的 n-gram 集合（原为最大开销，单文档 1 万字符 ≈ 64 万字节），改为**按需计算 + 有界 LRU 缓存**（`--ngram-cache`，默认 200 个文档）；③ 只保留 `n × num_perm` 的 uint32 签名矩阵（约 1KB/条）。**仍需常驻**：规范化正文（约 1~3 字节/字符，base64 图片载荷已剔除）|
| CPU | 已优化 | ① 签名阶段不再构造 n-gram 集合（取 min 与去重无关，结果不变）；② 候选对先按签名估计预筛（`--prefilter-margin`，默认 0.2），与阈值差距大的候选对不做精确 Jaccard；③ 组内两两 Jaccard 复用 L2 已算出的分数，全文相同的对直接判定为 1.0。**仍有平方级**：LSH 桶内两两枚举、组内两两比较（已对超大组打印告警）|
| 磁盘 | 未优化 | 报告逐组展开**全部成员明细**且无条数上限（与主脚本"明细封顶 300 条"不同），重复组多时单份报告可达数百 MB；报告写入后会在终端打印实际大小 |
| IO | 已优化 | 读取阶段改为二进制逐行流式解析，内存与文件大小解耦 |

使用建议：

| 场景 | 做法 |
|---|---|
| 日常迭代质检 | 主脚本加 `--no-near-dup`，只做精确判重 |
| 抽样验收（规范书"随机抽检 ≥1%"） | 加 `--sample 1`（固定 seed 可复现），避免全量 |
| 数据冻结后终检 | 才全量执行 `text_dup_precise_qc.py` |
| 超大数据集（>10 万条） | 先分片，再逐片执行，避免单进程内存上限 |
| 内存紧张 | 调小 `--ngram-cache`（更省内存、更多重算）；CPU 紧张则调大 |
| 要绝对穷尽（不接受任何近似） | 加 `--prefilter-margin 0`，对全部候选对做精确 Jaccard |

> 关于 `--prefilter-margin`：预筛只跳过"签名估计 Jaccard 比阈值低 0.2 以上"的候选对。按 256 位签名，其估计标准差约 0.03，因此真实相似度 ≥ 阈值却估计低 0.2 以上的概率在 10⁻⁹ 量级，可视为无漏检；若要绝对穷尽则设为 0。

`text_dup_precise_qc.py` 已内置分阶段进度日志（读文件 → 提取正文 → 精确判重 → MinHash → LSH 分桶 → 候选召回 → 预筛 → Jaccard 验证 → 聚类 → 写报告），终端实时显示已完成量、百分比与耗时，卡在哪个阶段一眼可见，随时可 Ctrl-C 中断。

## 三类数据集：规范与数据结构

样例见 [样例数据/](./样例数据/)：`代码问答样例.jsonl`、`安全技术博客样例.jsonl`、`开源漏洞样例.jsonl`（每行一条 JSON）。以下结构均以样例数据实际字段为准。

### 1. 代码问答数据集

- 样例文件：`样例数据/代码问答样例.jsonl`
- 质检脚本：`code_qa_qc.py`

```json
{
  "id": "QA_2026_AC_CC_START254A_ALTADD_1352009061",
  "message": [
    { "question": "……题面 / 用户提问……", "answer": "……代码或解答……" }
  ],
  "source": "CodeChef",
  "domain": ["codechef", "competitive-programming", "starters-254", "cpp"],
  "cleaning_status": { "deduplicated": true, "denoised": true, "format_normalized": true },
  "metadata": {
    "primary_language": "cpp",
    "token_count": 853,
    "type": "general_code_qa_dict",
    "ac_contest": "START254A",
    "ac_task": "ALTADD",
    "ac_submission_id": "1352009061",
    "ac_user": "meowww_kittu",
    "ac_original_language": "cpp",
    "ac_url": "https://www.codechef.com/problems/ALTADD",
    "question_time": "2026-09-02T22:30:00",
    "question_tokens": 698,
    "answer_tokens": 155,
    "tokenizer": "tiktoken/o200k_base",
    "answer_time": "2026-09-02T23:32:47"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | string | 是 | 全局唯一，统一前缀 `QA_2026_` |
| `message` | array | 是 | 对话轮次数组，每项含非空 `question` / `answer`；多轮即数组多项 |
| `source` | string | 是 | 数据来源（社区 / 竞赛平台 / 模型名），模型生成的答案须标注来源与模型 |
| `domain` | array[string] | 是 | 领域标签，样例形如 `[平台, 领域, 赛事, 语言]` |
| `cleaning_status` | object | 是 | 清洗状态三布尔：`deduplicated` / `denoised` / `format_normalized` |
| `metadata.primary_language` | string | 是 | 主语言（样例取值：`cpp` / `python` / `go` / `java`）|
| `metadata.token_count` | int | 是 | 样本 token 数，须与正文估算一致 |
| `metadata.type` | string | 是 | 固定值 `general_code_qa_dict` |
| `metadata.ac_*` | string | 否 | 竞赛类来源专有：`ac_contest` / `ac_task` / `ac_submission_id` / `ac_user` / `ac_original_language` / `ac_url` |
| `metadata.question_time` / `answer_time` | string | 否 | ISO8601 时间 |
| `metadata.question_tokens` / `answer_tokens` / `tokenizer` | int / string | 否 | 分项 token 数与分词器标识 |

验收硬指标：单一语言占比 ≤30%、多轮问答占比 ≥10%、重复率 <0.5%、字段全必填、`id` 唯一；正文禁残留图片 / 二进制等非文本资源，隐私须脱敏，禁止混入公开问答数据集与人工 / 大模型合成的虚构提问。

### 2. 安全技术博客数据集

- 样例文件：`样例数据/安全技术博客样例.jsonl`
- 质检脚本：`blog_qc.py`

```json
{
  "id": "000089",
  "content": "……Markdown 正文，图片以 base64 内嵌（data:image/…）或以 <image_desc>…</image_desc> 占位……",
  "meta": {
    "title": "白帽子的匿名时代，正在终结——HackerOne强制身份验证这件事",
    "url": "https://www.anquanke.com/post/id/315921",
    "source_platform": "安全客",
    "author_or_org": "安全客",
    "publish_time": "2026-08-04 11:16",
    "content_category": "漏洞分析",
    "is_original": true,
    "primary_languages": [],
    "related_cves": []
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | string | 是 | 记录 ID（样例为 6 位数字串）|
| `content` | string | 是 | 正文（Markdown），严禁截断；图片须自包含 |
| `meta.title` | string | 是 | 标题 |
| `meta.url` | string | 是 | 原文链接，全局唯一（URL 重复率 ≤2%）|
| `meta.source_platform` | string | 是 | 来源平台（样例取值：`安全客` / `先知社区`）|
| `meta.author_or_org` | string | 是 | 作者或机构 |
| `meta.publish_time` | string | 是 | 发布时间，样例格式 `YYYY-MM-DD HH:MM` |
| `meta.content_category` | string | 是 | 内容分类（样例取值：`漏洞分析` / `注入` / `RCE` / `恶意样本` / `应急工具`）|
| `meta.is_original` | bool | 是 | 是否原创 |
| `meta.primary_languages` | array[string] | 否 | 涉及的编程语言，无则空数组（样例取值：`Python` / `PHP` / `C++` / `汇编`）|
| `meta.related_cves` | array[string] | 否 | 关联 CVE 编号，无则空数组 |

验收硬指标：权威源覆盖率 ≥95%、必填字段缺失率 ≤1%、重复率（URL / 正文）≤2%、非技术内容占比 ≤0.5%、单一语言占比 ≤30%；正文不得截断（如以 `poc:` / `exp:` / 冒号结尾）、图片不得残留 `blob:` 或未内嵌外链、隐私须匿名化、IOC 须去武器化（Defang）。

### 3. 开源项目漏洞修复 commit 数据集

- 样例文件：`样例数据/开源漏洞样例.jsonl`
- 质检脚本：`vuln_commit_qc.py`

```json
{
  "id": "CVE-2022-21654-envoy-e9f936d85dc1",
  "text": "CVE ID: CVE-2022-21654\n\nProject: envoy\n\nProgramming Language: C++\n\nVulnerability Type: Other\n\nCWE Classification: CWE-295\n\nSeverity: HIGH\n\nCVSS Score: 7.4\n\nCVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N\n\nFix Commit: e9f936d85dc1…\n",
  "meta": {
    "commit_message": "……",
    "vulnerable_code": "……修复前完整代码……",
    "fixed_code": "……修复后完整代码……",
    "unified_diff": "diff --git a/… b/…\n…",
    "cve_id": "CVE-2022-21654",
    "project_name": "envoy",
    "project_owner": "envoyproxy",
    "github_url": "https://github.com/envoyproxy/envoy/commit/e9f936d85dc1edc34fabd0a1725ec180f2316353",
    "programming_language": "C++",
    "vulnerability_type": "Other",
    "cwe_classification": ["CWE-295"],
    "severity": "HIGH",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "fix_commit_hash": "e9f936d85dc1edc34fabd0a1725ec180f2316353",
    "fix_pattern": "Session Digest Validation",
    "vulnerability_cause": "……漏洞成因说明……",
    "data_language": "en",
    "year": "2022",
    "source_platform": "NVD + GitHub",
    "collection_time": "2026-08-12",
    "cwe_id": "CWE-295",
    "complete_code_fetched": true,
    "primary_file": "source/extensions/transport_sockets/tls/cert_validator/default_validator.cc",
    "license": "Apache-2.0"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | string | 是 | 样例形如 `<CVE-ID>-<项目名>-<commit 短哈希>` |
| `text` | string | 是 | 人类可读概览，**只承载属性**（CVE ID / Project / 语言 / 类型 / CWE / 评级 / CVSS / Fix Commit 等）；字段随来源略有差异（样例中存在 9 字段与 13 字段两种模板）|
| `meta.commit_message` | string | 是 | commit 提交信息 |
| `meta.vulnerable_code` | string | 是 | 修复前代码（完整文件内容）|
| `meta.fixed_code` | string | 是 | 修复后代码（完整文件内容）|
| `meta.unified_diff` | string | 是 | 修复 diff，须为纯 diff 格式 |
| `meta.cve_id` | string | 是 | CVE 编号 |
| `meta.project_name` / `meta.project_owner` | string | 是 | 项目名 / 归属组织 |
| `meta.programming_language` | string | 是 | 编程语言（样例取值：`C++` / `Python` / `JavaScript` / `Java` / `Ruby` / `C#` / `Rust`）|
| `meta.vulnerability_type` | string | 是 | 漏洞类型（样例取值：`Authorization Bypass` / `OS Command Injection` / `Code Injection` / `XXE` / `Denial of Service` / `Out-of-Bounds Read` / `Use-After-Free` / `Other`）|
| `meta.cwe_classification` | array[string] | 是 | CWE 列表，样例 1~3 项 |
| `meta.severity` | string | 是 | 危险等级（`CRITICAL` / `HIGH` / `MEDIUM`）|
| `meta.cvss_score` / `meta.cvss_vector` | float / string | 是 | CVSS 分值 / 向量 |
| `meta.fix_commit_hash` | string | 是 | 修复 commit 完整哈希 |
| `meta.fix_pattern` | string | 是 | 修复模式 |
| `meta.vulnerability_cause` | string | 是 | 漏洞成因说明 |
| `meta.license` | string | 是 | 开源许可证（样例取值：`Apache-2.0` / `MIT`），要求 100% 覆盖 |
| `meta.github_url` | string | 否 | commit 页面链接 |
| `meta.data_language` / `meta.year` | string | 否 | 数据语言 / CVE 年份（样例：`en`、`2022` / `2024`）|
| `meta.source_platform` / `meta.collection_time` | string | 否 | 来源与采集时间（样例：`NVD + GitHub`）|
| `meta.cwe_id` | string | 否 | 主 CWE（`cwe_classification` 的镜像）|
| `meta.complete_code_fetched` | bool | 是 | 代码是否完整抓取 |
| `meta.primary_file` | string | 否 | 被修复的主文件路径 |

验收硬指标：代码四件套（`commit_message` + `vulnerable_code` + `fixed_code` + `unified_diff`）齐全、`vulnerable_code + unified_diff = fixed_code` 自洽、有效代码 ≥5 行、单一语言占比 ≤30%、近 3 年 CVE 占比 ≥30%、Revert / 无效修复样本 ≤0.5%、不完整性文本 ≤0.5%；须剔除 revert / 纯文档变更，主文件不得误选文档文件（`.md` / `.txt` / `.rst` 等），代码脱敏须用语法安全占位符（严禁纯 `x` 覆盖）。

## 特性

- **流式读取**：`iter_jsonl` 逐行迭代替代全量加载，10 万条 / 500MB 语料内存峰值 ~23MB
- **近似查重前置决策**：样本量超上限时自动跳过 shingles 收集（从根上避免"先建集合才停"），支持 `--no-near-dup` 显式关闭
- **蓄水池抽样**：`--sample` 单遍流式均匀随机，无需全量加载
- **计数与明细解耦**：ERROR/WARN 计数恒准确，明细列表封顶防膨胀，报告展示前 300 条
- **误报抑制**：算法代码语境常见内容（AVX 指令集名、题目要求输出的 `?` 串、样例 IO 小数据块）不误判

## 安装

```bash
pip install lxml
```

依赖：Python 3.8+，lxml（HTML 解析）。

## 快速开始

```bash
# 代码问答数据集全量质检(流式, 大规模安全)
python code_qa_qc.py 样例数据/代码问答样例.jsonl --no-near-dup

# 抽样 1% 质检(§9 抽检要求, 固定 seed 可复现)
python code_qa_qc.py 样例数据/代码问答样例.jsonl --sample 1

# 博客 / 漏洞 commit 数据集质检
python blog_qc.py 样例数据/安全技术博客样例.jsonl
python vuln_commit_qc.py 样例数据/开源漏洞样例.jsonl

# 文本精确/近似重复检测(重资源, 非必要不进行, 见上节; 大数据集请先分片)
python text_dup_precise_qc.py 样例数据/*.jsonl
```

输出：`质检报告_<时间戳>.md` + `.html` 双格式报告（总体结论 / 验收硬指标 / 抽样功能校验 / 真实性 / 重复率 / 脱敏 / 低质过滤 / 整改明细）。

## 报告结构

报告按数据集交付规范（§10 交付物料清单）组织：

1. 总体结论（达标 / 不达标）
2. 验收硬指标（全局）：语言占比 / 多轮占比 / 重复率 / 脱敏 / 合成与混入检测
3. 抽样代码功能校验：语法解析、入口结构、括号配平
4. 问答真实性校验：溯源字段、合成水印、开源数据集混入特征
5. 重复率校验：精确 md5 + 近似 shingles
6. 脱敏校验：邮箱 / 手机 / 证件 / 社交账号 / 内网 IP（白名单与占位符豁免）
7. 低质样本过滤记录（LQ1-LQ7 七规则）
8. 问题整改明细：类别 × 数量 × 样本 ID × 整改建议

> 报告中的"达标 / 不达标"及全部 ERROR / WARN 明细**仅为参考**，须经人工复检或大模型逐条确认后才能作为验收结论（详见开头[重要声明](#️-重要声明检测结果仅供参考)）。

## 已知语境误报（算法语料场景，已内置抑制）

下表是**已知的一类误报**（脚本已内置抑制）。除这些之外，规则化检测仍会产生其他误报与漏报，**任何命中项都需人工复检或大模型逐条确认**。

| 特征串 | 实际含义 |
|---|---|
| `avx512vl` 等 | AVX-512 CPU 指令集（编译指令），非社交账号 |
| `??????` 串 | 题目要求输出的内容，非灌水占位 |
| 1-3 行围栏块 | 样例输入输出（` ```text `），非残缺代码 |
| `for (auto &qq : queries)` | C++ 循环变量名，非 QQ 号（账号串须含数字才检出）|

## License

MIT
