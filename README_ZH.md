# Codex Memories — Git 管理的 Codex 跨会话长期记忆

**让 Codex 跨会话找回项目决定，记忆来源保存在本地，随时可检查。**

用 Git 管理长期规则，按需召回相关证据。无需托管向量数据库或单独的记忆服务账号。

Codex Memories 是面向 OpenAI Codex 的开源、本地优先记忆运行时：
把项目规则和决策保存在 Git 中，通过本地索引跨会话检索相关证据。
这是独立社区项目，并非 OpenAI 官方产品。自动接入需要审阅并配置 Hook；
独立演示无需 Codex 账号即可试跑。

[![Tests](https://github.com/libenxier-beep/codex-memories/actions/workflows/tests.yml/badge.svg)](https://github.com/libenxier-beep/codex-memories/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[English](README.md) · [安装指南](docs/getting-started.md) · [常见问题](docs/faq.md#中文常见问题) · [架构](docs/memory-control-plane.md) · [测试与边界](docs/retrieval-v2-validation.md)

## 先体验，再安装

需要 Python 3.9+ 和 Git。CI 覆盖 macOS 与 Linux；Windows 尚未验证。
演示无需 Codex 账号或 API key：

```bash
git clone https://github.com/libenxier-beep/codex-memories.git
cd codex-memories
python3 scripts/codex_memories.py demo
```

看到 `Codex Memories demo: PASS` 后，会显示找回的合成项目决定：
`The synthetic Aurora project uses SQLite for its offline task queue.`
演示执行真实提交、索引和新进程召回，结束后清理临时环境，不修改现有记忆和 Codex 设置。
这验证本地检索链路；自动会话接入仍需后续配置。

[首次使用指南](docs/getting-started.md) ·
[反馈问题或试用体验](https://github.com/libenxier-beep/codex-memories/issues/new/choose) ·
[版本记录](CHANGELOG.md)

## 关于预览版

Codex Memories 适合希望让 Codex 长期记住事实、决策、偏好和工程经验，
但不愿把私人记忆上传到云端记忆服务的开发者。它通过 Codex 生命周期
Hook 自动捕获与召回，以 Git 作为权威来源，以本地 SQLite 作为可丢弃的
sidecar，并由当前 Codex 模型控制最多三轮的渐进式检索。

> [!IMPORTANT]
> 当前状态是 **高级预览 / 真实 dogfood**。系统已经在真实 Codex 环境中
> 使用，公开测试全部通过，但独立 Large-B3 尚未完成，不能宣称全面超过
> Mem0、Graphiti、Letta 或 MemOS。

## 安装 Codex 长期记忆工具

需要 Python 3.9+、Git 和本地 Codex：

```bash
git clone https://github.com/libenxier-beep/codex-memories.git
cd codex-memories
./install.sh
~/.local/share/codex-memories/bin/codex-memories doctor
```

安装器会明确分开三类内容：

| 部分 | 默认位置 | 内容 |
| --- | --- | --- |
| Runtime | `~/.local/share/codex-memories` | 可替换的产品代码与 CLI |
| Authority | `~/.codex/memories` | 你的私人、Git-backed 长期记忆 |
| Sidecar | `~/.codex/memory-sidecar` | 可丢弃的索引、状态和缓存 |

安装器不会直接修改 `hooks.json`，只会在 Runtime 目录生成经过摘要绑定的
`hooks.merge-plan.json`，交给配置负责人审阅合并。在合并前，`doctor` 会显示
`integration: review_required`，表示产品已安装，但 Codex 自动捕获和召回还未启用。

可以先直接验证 CLI：

```bash
~/.local/share/codex-memories/bin/codex-memories index
~/.local/share/codex-memories/bin/codex-memories recall "governed local memory"
~/.local/share/codex-memories/bin/codex-memories health
```

自定义路径、Hook 审阅、升级、回滚和故障排查见
[Getting Started](docs/getting-started.md)。

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

此前验证记录包含 289 项合成单元与集成测试；当前版本新增首次使用回归用例。公开 synthetic 三次
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

- 本地存储不代表 Codex 全流程离线：召回证据会进入模型上下文，受宿主的数据设置约束。
- 安装已经自动化，但 Hook 合并仍需要配置负责人明确审阅。
- Linux 没有 Apple NaturalLanguage 时会安全降级到 lexical recall。
- Large-B3 没有完成，真实私人记忆质量仍需长期 dogfood 验证。
- 仓库不会包含私人记忆、Work Context 正文、隐藏评测集或 consumed seal。

如果你也想要一个本地、可检查、不过度依赖云端基础设施的 Agent Memory，
欢迎提交 Issue、PR，或者点一个 Star 让更多 Codex 用户看到它。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。
