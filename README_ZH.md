# Codex Memories

**面向 OpenAI Codex 的本地优先持久记忆系统：权威来源重开、渐进披露，无需托管向量数据库。**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[English](README.md) · [架构](docs/memory-control-plane.md) · [测试与边界](docs/retrieval-v2-validation.md)

Codex Memories 适合希望让 Codex 长期记住事实、决策、偏好和工程经验，
但不愿把私人记忆上传到云端记忆服务的开发者。它通过 Codex 生命周期
Hook 自动捕获与召回，以 Git 作为权威来源，以本地 SQLite 作为可丢弃的
sidecar，并由当前 Codex 模型控制最多三轮的渐进式检索。

> [!IMPORTANT]
> 当前状态是 **高级预览 / 真实 dogfood**。系统已经在真实 Codex 环境中
> 使用，公开测试全部通过，但独立 Large-B3 尚未完成，不能宣称全面超过
> Mem0、Graphiti、Letta 或 MemOS。

## 核心特点

- **Codex 原生接入**：通过 Session、Prompt、Tool 和 Stop Hook 工作。
- **简单问题不跑满三轮**：首轮证据足够就直接回答。
- **当前 Codex 负责语义规划**：记忆运行时不会再启动第二个远程模型。
- **本地优先**：私人记忆、索引、会话与授权状态留在本机。
- **权威来源优先**：索引只负责推荐候选，注入前必须重新打开 Git 权威内容。
- **作用域不升级**：后续改写仍绑定最初批准的 `work` 或 `personal` 范围。
- **可回滚**：无需删除记忆即可退回 legacy 检索。

## 快速验证

```bash
git clone https://github.com/libenxier-beep/codex-memories.git
cd codex-memories
python3 -m unittest discover -s tests
```

当前公开仓库包含 270 项合成单元与集成测试。公开 synthetic 三次
Recall@5 为 `0.8800 / 0.8867 / 0.8800`，no-answer FPR 均为 `0`；
但一次仅含 6 条可回答问题的小型 hidden seal 中，候选只有 `3/6`，因此
被正确拒绝。完整说明见[验证记录](docs/retrieval-v2-validation.md)。

## 它和常见方案有什么不同？

| 方案 | 常见代价 | Codex Memories 的取舍 |
| --- | --- | --- |
| 全量塞进上下文 | 重复消耗 Token | 只注入治理后的相关证据 |
| 云端记忆 API | 私人记忆离开本机 | 本地权威与 sidecar |
| 向量库 + Reranker | 基础设施和调参较重 | 无需托管向量数据库 |
| 单轮 RAG | 容易漏掉改写或多跳证据 | 必要时最多三轮渐进检索 |
| 原始聊天日志 | 缺少生命周期和来源治理 | 候选隔离、删除、墓碑与精确重开 |

## 当前边界

- 目前更适合愿意配置 Codex Hook 和本地 authority 的高级用户。
- 还没有面向所有人的一键安装器。
- Large-B3 没有完成，真实私人记忆质量仍需长期 dogfood 验证。
- 仓库不会包含私人记忆、Work Context 正文、隐藏评测集或 consumed seal。

如果你也想要一个本地、可检查、不过度依赖云端基础设施的 Agent Memory，
欢迎提交 Issue、PR，或者点一个 Star 让更多 Codex 用户看到它。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。
