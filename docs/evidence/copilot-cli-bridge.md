# Copilot CLI bridge evidence

## Status

**Narrowed, not closed.** Public Copilot CLI extension points can expose
Steward through custom agents, MCP tools, skills, and lifecycle hooks. They
cannot register a remote process as a native Copilot CLI sub-agent or use the
internal `write_agent` / `read_agent` messaging channel.

This evidence narrows E-09 in the
[validation register](../open-questions.md). An executable bridge and
notification replay test are still required.

## Supported public mechanisms

- A custom `*.agent.md` profile can make a Steward-oriented in-process agent
  user-selectable and eligible for model-directed delegation.
- An agent-scoped MCP server can expose typed Steward tools and retain durable
  StewardAgent state outside the Copilot process.
- Skills can teach the parent or custom agent when and how to use those tools.
- `subagentStart` and `subagentStop` hooks can observe most custom-agent
  lifecycle boundaries, inject initial context, and inspect or modify the
  response returned by that in-process sub-agent.
- Programmatic `copilot -p` invocation can run a configured custom agent
  headlessly, but each invocation is independent unless Steward supplies the
  durable session state.

## Unsupported native behavior

- No public API allows Steward to register a remote process as a native
  sub-agent.
- Native sub-agent spawning remains a Copilot CLI/model decision.
- `write_agent`, `read_agent`, and `list_agents` are internal in-process tools
  and are not externally addressable.
- A remote service cannot push a completed StewardAgent response directly into
  a waiting parent-agent context through a documented API.
- Copilot CLI does not expose a public programmatic transcript replay API.
- The built-in `general-purpose` sub-agent does not emit the documented
  `subagentStart` and `subagentStop` hooks.

## Contract consequence

StewardAgent is a Steward domain/runtime concept, not a Copilot sub-agent
implementation. The supported integration is:

1. A Copilot custom agent or the parent agent calls Steward MCP tools to create
   an Agent, enqueue a turn, inspect progress, cancel, and retrieve responses.
2. Steward.Control persists the Agent context, turns, responses, and
   notification cursors independently of Copilot CLI.
3. A local bridge watches Steward's notification outbox and exposes replayable
   events through local RPC/MCP. It must remain useful even when no Copilot
   session is attached.
4. Hooks may improve the in-process custom-agent experience, but correctness
   cannot depend on them. Hook timeouts and unsupported agent types must not
   lose a Steward response.
5. If GitHub later publishes a remote sub-agent or external notification API,
   an adapter may map the same Steward application handlers onto it.

The user-facing goal remains that remote Agents feel like delegated
collaborators. The final acceptance language must distinguish that experience
from unsupported claims of native `write_agent` compatibility.

## Executable follow-up

- Configure a user-scoped Steward custom agent with only Steward MCP tools.
- Create and continue one StewardAgent over multiple MCP calls.
- Complete a turn after the originating Copilot turn has ended.
- Reattach and retrieve the response exactly once using notification cursors.
- Exercise custom-agent hooks and their timeout/failure behavior.
- Verify the local RPC/MCP fallback with no hook configuration.
- Record behavior for local interactive and `copilot -p` modes.

## Sources

- [About GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-copilot-cli)
- [Copilot CLI overview](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/overview)
- [Custom agents configuration](https://docs.github.com/en/copilot/reference/custom-agents-configuration)
- [Adding MCP servers](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers)
- [Adding skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills)
- [Hooks concepts](https://docs.github.com/en/copilot/concepts/agents/hooks)
- [Hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Copilot CLI command reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference)
