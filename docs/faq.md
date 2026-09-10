# Codex Memories FAQ: installation, persistent memory, and privacy

[Project overview](../README.md) · [中文说明](../README_ZH.md) · [Installation guide](getting-started.md)

## What is Codex Memories?

Codex Memories is an independent, Apache-2.0 open-source memory runtime for
OpenAI Codex. It keeps durable project rules and decisions in Git and retrieves
relevant evidence across sessions through a local index. It is an advanced
preview, not an official OpenAI product or a hosted memory service.

## How can I try it without changing my Codex configuration?

With Python 3.9+ and Git installed, run:

```bash
git clone https://github.com/libenxier-beep/codex-memories.git
cd codex-memories
python3 scripts/codex_memories.py demo
```

The demo creates an isolated temporary deployment, commits a synthetic decision,
builds its index, and recalls the decision in a new process. It removes the
temporary deployment on exit. No API key or Codex account is needed for this
demo. A passing demo verifies local recall, not live host integration.

## Does installing it automatically enable memory in Codex?

No. The installer generates a review-only hook merge plan and does not overwrite
the host's hooks.json. Automatic capture and recall require the configuration
owner to review and apply that plan. See the [installation guide](getting-started.md)
and [hook protocol](agent-memory-hook-protocol.md).

## How does it relate to AGENTS.md?

Codex Memories is not a replacement for repository instructions such as
AGENTS.md. Use instruction files for explicit project rules; this runtime adds
a separate, governed store and retrieval workflow for durable evidence.
Retrieved memory is untrusted data and cannot grant itself authority or override
the user's current instructions. See the [control-plane design](memory-control-plane.md).

## Does local-first mean that recalled content never leaves the computer?

No. The memory authority and indexes are local, but recalled passages can enter
the Codex model context and are subject to the host's data settings. The
standalone synthetic demo does not call an LLM. Do not treat local storage as
an end-to-end offline guarantee. See the [privacy boundary](../README.md#privacy-and-trust-boundary).

## Which systems and dependencies are supported?

The public quickstart requires Python 3.9+ and Git. CI covers macOS and Linux;
Windows is not yet validated. Live integration additionally requires a local
Codex installation with compatible lifecycle hooks. No hosted vector database
or separate memory-service account is required.

## Is it better than other agent memory tools?

General superiority has not been demonstrated. The project focuses on local
Git authority, source checks, and bounded progressive retrieval. Public synthetic
results and a failed compact hidden evaluation are documented in the
[validation record](retrieval-v2-validation.md); the independent Large-B3
evaluation was not completed. These limits also apply to promotional claims.

## Where should I report installation or recall problems?

Open a [GitHub issue](https://github.com/libenxier-beep/codex-memories/issues/new/choose)
with the product version, operating system, command, expected result, and a
minimal synthetic reproduction. Remove private memories, credentials, and
personal paths before posting. See [contribution guidance](../CONTRIBUTING.md).

## 中文常见问题

### 这是 Codex 官方自带的记忆功能吗？

不是。Codex Memories 是独立社区维护的 Apache-2.0 开源项目，使用 Git
保存项目规则和决策，通过本地索引跨会话召回证据，目前处于高级预览阶段。

### 可以先试用，不修改现有配置吗？

可以。运行上面的 demo 命令即可在临时环境完成合成记忆的提交、索引和
新进程召回，无需 API key 或 Codex 账号。演示结束会清理临时部署。
它验证本地检索链路，不代表自动会话接入已经完成。

### 安装后会自动生效吗？

不会。安装器只生成供审阅的 Hook 合并计划，不直接覆盖 hooks.json。
自动捕获和召回需要配置负责人审阅并应用计划，详见[安装指南](getting-started.md)。

### 本地记忆是否意味着内容绝不上传？

不意味着。记忆来源和索引保存在本地，但召回片段可能进入 Codex 模型上下文，
受宿主的数据设置约束。独立合成演示不调用 LLM。

### 能代替 AGENTS.md 或保证优于其他记忆系统吗？

不能作这样的保证。AGENTS.md 承载明确的项目指令，这个项目提供额外的记忆
存储与检索流程；召回文本不能覆盖当前用户指令。通用效果尚未得到充分验证，
请先阅读[测试结果和已知边界](retrieval-v2-validation.md)。
