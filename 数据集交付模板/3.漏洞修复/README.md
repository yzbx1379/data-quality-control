# 开源项目漏洞修复 commit 数据集· 抽样交付包 README

> 交付批次：`开源项目代码修复commit_抽样10条`（人工核验抽样 10 条，2026-09-02 构造 / 复检）
> 用途：0824/0828/0901 验收意见整改后的**样例交付包**，供验收方逐条核验（含严格 git-apply 自洽）。正式规模目标见「数据使用规范」末节。
> 权威口径：`spec/开源项目漏洞修复commit 数据集采集与标注技术规范书.docx`（本文简称「规范书」）。

## 1. 交付物料清单（规范书 §10）

| # | 物料          | 文件                                             | 状态                                                                               |
| - | ----------- | ---------------------------------------------- | -------------------------------------------------------------------------------- |
| 1 | 核心数据（JSONL） | `data.jsonl`                                   | ✅ 10 条                                                                           |
| 2 | 元数据统计表      | `metadata.csv`                                 | ✅                                                                                |
| 3 | 安全数据质检报告    | `漏洞修复commit_质检报告_20260904_142131.md` / `.html` | ✅ 记录ERROR 0 / 全局ERROR 0 / WARN 9(建议级: 全部为 hunk 上下文建议项)（含完整性/格式规范/数据来源/安全知识覆盖度四维） |
| 4 | README      | 本文件                                            | ✅                                                                                |
| 5 | License 合规声明 | 本文第 8 节                                       | ✅                                                                                |

## 2. 数据格式

JSONL，UTF-8 无 BOM，每行一条，结构 `{id, text, meta}`（规范书 §7.1/7.2）：

* `id`：`<CVE>-<项目>-<commit前缀>`，如 `CVE-2022-21654-envoy-e9f936d85dc1`。

* `text`：其余属性按 `Key: Value` 英文键值对拼接（概览信息，不含代码四件套）。

* `meta`：

  * **代码四件套**（强制存放）：`commit_message / vulnerable_code / fixed_code / unified_diff`

  * **属性字段**：`cve_id / project_name / project_owner / github_url / programming_language / vulnerability_type / cwe_classification / severity / cvss_score / cvss_vector / fix_commit_hash / fix_pattern / vulnerability_cause / data_language / year / source_platform / collection_time / cwe_id / complete_code_fetched / primary_file / license`

**代码完整性**：`vulnerable_code`/`fixed_code` 为承载修复的主代码文件完整原始代码（`complete_code_fetched=true`），不含 diff 拼接标记；**自洽校验**：`vulnerable_code + unified_diff` 可精确还原 `fixed_code`（git apply 严格双向验证，仅精确 old\_start 匹配，无 ±6 行模糊）。

## 3. 采集流程

1. **漏洞源**：CVE 关联 NVD（+OSV/GHSA 兜底）等权威库，剔除 REJECTED/DISPUTED。
2. **commit 定位**：NVD references 直链 + OSV/GHSA `GIT range fixed` → GitHub API（commit 详情 / 仓库 license / 修复前后两版完整文件）。
3. **diff 重算**：本地 difflib 重算 15 行上下文 diff，保证自洽恒成立。
4. **主文件选择**：优先代码文件（.go/.py/.c/.cc 等），排除 md/txt/rst 文档类（0828 反馈 b）。
5. **预过滤**：剔除 merge/revert/rollback、纯注释变更、>10 文件、非白名单 License、无代码文件；单 commit 仅关联 1 个 CVE（§6.1）；diff SHA-256 去重。

## 4. 清洗 / 标注 / 脱敏流程

1. **diff 头过滤**：剔除 git format-patch 邮件头 `From <sha>`（大小写不敏感，0828 反馈 a）。
2. **占位污染清除**：新增文件场景 `vulnerable_code` 不拼接 `(New file)` 等无关占位（0828 反馈 d）。
3. **脱敏**（commit 口径，与博客不同——**不破坏语法**的占位符）：

   * diff `From:` 行邮箱已脱敏

   * 代码中真实密钥/邮箱 → 语法安全占位符（`dummy_key_123`、`user@example.com`），**严禁纯** **`x`** **无差别覆盖**（会破坏 AST）
4. **标注**：`cwe_classification` / `cwe_id` / `severity` / `cvss_score` / `cvss_vector` / `vulnerability_type` / `fix_pattern` / `vulnerability_cause`。

## 5. 数据分类 / 覆盖说明

* **编程语言**（7 种，单一语言 ≤30% 达标，最高 20%）：C++ 2 / Python 2 / JavaScript 2 / Java 1 / Ruby 1 / C# 1 / Rust 1

* **CVE 年份**：2022 ×7、2024 ×3，**近 3 年占比 30%**（规范书 ≥30% 达标）。

* **严重程度**：CRITICAL 5 / HIGH 4 / MEDIUM 1。

* **数据源渠道**：NVD + GitHub（10/10）。

* **领域**：覆盖代理（envoy）、数据库变更（liquibase/hazelcast）、Web 库（url-parse/npm-lockfile）、消息（zulip）、图像处理（image\_processing）、JSON/ML/异步运行时（Newtonsoft.Json/onnx/mio）等。

## 6. 数据使用规范

* 本数据集**仅用于网络安全领域大模型训练与评测**（漏洞修复代码理解 / 补丁生成），不得用于武器化。

* 训练主体为 `meta` 代码四件套 + `text` 概览；`vulnerable_code`/`fixed_code`/`unified_diff` 可直接构造「漏洞代码→修复补丁」监督对。

* **规模口径**（正式交付目标，非本抽样包）：text ≥400G、≥100B tokens、约 2500 万条；本抽样包 10 条，代码四件套共 885,472 字（≈222,085 tokens 估算）。

## 7. 质检结果（抽样 10 条）

* `vuln_commit_qc`：**记录级 ERROR 0**；diff 自洽严格模式 **10/10 通过**。

* 完整性：`complete_code_fetched=true` 10/10、必填字段齐全、`primary_file` 非文档类、单 CVE、无邮件头、无 `(New file)` 占位污染。

* 格式规范：JSONL 可解析、`text` 英文键值对无中英混排、代码四件套存于 `meta`。

* 数据来源：`github_url` 可溯源至 GitHub commit，CVE/CVSS 与 NVD 一致。

* 全局重复率（unified\_diff 规范化后 MD5）：**0%**。

* 脱敏覆盖：真实邮箱泄漏 0、内网 IP 残留 0（diff From 行已脱敏，语法安全占位符 2 处）。

## 8. 版权合规声明（License）

* 全部 10 条 License 均为允许 AI 训练的宽松许可（Apache-2.0 / MIT），**License 清单**见 `metadata.csv`「License 分布」节：

| License    | 条数 | AI 训练授权 |
| ---------- | -- | ------- |
| Apache-2.0 | 5  | ✅ 明确允许  |
| MIT        | 5  | ✅ 明确允许  |

