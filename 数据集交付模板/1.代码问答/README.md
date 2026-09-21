# 代码问答数据集 · CodeChef 批次 README

交付批次：代码问答数据_CodeChef（真实竞赛问答，AC 提交 + 官方题面）
权威口径：`spec/10-代码问答数据_技术规范书.docx`（本文简称「规范书」）。

## 1. 交付物料清单（规范书 §10）

| # | 物料 | 文件 | 状态 |
|---|---|---|---|
| 1 | 核心数据（JSONL） | `codechef_qa.jsonl` | ✅ 22,847 条 |
| 2 | 元数据统计表 | `metadata.csv` | ✅ |
| 3 | 代码问答质检报告 | `代码问答_质检报告_20260917_104143.md` / `.html` | ⚠️ 记录 ERROR 0，全局 ERROR 1（cpp 占比，见 §6） |
| 4 | README | 本文件 | ✅ |
| 5 | License 合规声明 | 本文第 7 节 | ✅ |

交付五件套齐备。目录内另含采集状态文件 `progress_mass.json` / `contests_manifest.json`（断点续采依据，非交付物料）。

## 2. 数据格式

JSONL，UTF-8 无 BOM，每行一条，结构 `{id, message, source, domain, cleaning_status, metadata}`：

- **id**：`QA_2026_AC_CC_<CONTEST>_<TASK>_<submission_id>`，全局唯一
- **message**：`[{question, answer}]`；question = CodeChef 官方题面（标题 + 完整题干 + 输入输出格式 + 样例），answer = 用户 AC 提交的完整源代码；本批全为单轮（1 组）
- **source**：CodeChef（真实竞赛题面 + 真实通过提交）
- **domain**：标签数组，如 `["codechef", "competitive-programming", "starters-254", "cpp"]`
- **cleaning_status**：`{deduplicated: true, denoised: true, format_normalized: true}`
- **metadata**：`primary_language / token_count / type(=general_code_qa_dict) / ac_contest / ac_task / ac_submission_id / ac_user / ac_original_language / ac_url / question_time / answer_time / question_tokens / answer_tokens / tokenizer`
  - **token 口径**：tiktoken `o200k_base`，`token_count = question_tokens + answer_tokens`，`tokenizer = "tiktoken/o200k_base"` 逐条标注
  - `question_time` = 比赛开始时间，`answer_time` = 提交通过时间（均 UTC ISO `YYYY-MM-DDTHH:MM:SS`）

## 3. 数据来源

CodeChef 竞赛题目与真实通过提交。每条 question 为某场比赛的完整官方题面，answer 为对应本题的一份 AC 提交源码（`ac_url` 指向题目页，`ac_submission_id` 为可溯源提交号）。无合成虚构提问；不混入 GitHub/HuggingFace 已公开代码问答数据集（QC 全量核验 0 命中）。

## 4. 清洗与标注结论

- **抽样网页核验**：10 条随机抽样经浏览器与 CodeChef 官网逐条比对，10/10 题目标题、题干、是否存在均与线上完全一致（HTTP 200，无缺失、无错误）。
- **去重**：message 规范化 MD5 全局去重，完全重复率 0.00%。
- **脱敏**：隐私明文 0、非文本资源 0、反爬水印 0（QC 全量）。
- **新口径合规**（QC E15-E18）：`domain` 标签数组 0 异常、`question_time` / `answer_time` 0 缺失、`question_tokens/answer_tokens/tokenizer` 0 缺失、`token_count == question + answer` 0 异常。

## 5. 数据规模与分布

| 指标 | 值 |
|---|---|
| 总条数 | 22,847（单轮 100%） |
| 总 tokens | 33,078,852（question 16,175,386 + answer 16,903,466） |
| 语言 | cpp 81.3% / python 11.1% / java 5.4% / c 0.8% / rust 0.7% 等 10 种 |
| 多轮占比 | 0%（构造性单轮，`--exempt-multi-turn` 豁免单列） |

## 6. 质检结果（全量，2026-09-17）

- 记录 ERROR **0** / WARN 0，解析失败 0 行
- **全局 ERROR 1**：单一语言占比 **cpp 81.3%**（红线 ≤30%）——CodeChef 竞赛提交以 C++ 为主，属采集源分布结构，需与验收方明确处理口径
- 完全重复率 0.00%（阈值 <0.5% ✅）；近似重复超 shingle 上限按 QC 约定跳过，全量近似查重需 `text_dup_precise_qc.py` 分片终检
- 隐私明文 0 / 非文本资源 0 / 反爬水印 0 / 疑似合成提问 0 / 开源数据集混入 0 / Python 语法失败 0 / token 内部一致性 0 异常

## 7. 版权合规声明

- 内容来源：CodeChef 竞赛题面与用户提交（`ac_url` 注明来源，`ac_submission_id`/`ac_user` 保留归属）
- 隐私与权益：已执行邮箱/隐私脱敏；不含未授权商用源码、涉密信息、未脱敏个人隐私、网络犯罪内容（QC 全量扫描 0 命中）
- 使用授权：数据按合同约定用于大模型训练与评测，遵循来源平台内容授权与项目保密义务