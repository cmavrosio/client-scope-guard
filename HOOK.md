---
name: client-scope-guard
description: "Enforces client/tenant isolation — prevents agents from accessing other clients' data via file operations or terminal commands. Uses macOS sandbox-exec for kernel-level enforcement."
metadata:
  openclaw:
    emoji: "🛡️"
    events: ["agent:bootstrap", "tool_result_persist"]
    requires:
      bins: ["sandbox-exec"]
---

# Client Scope Guard

Multi-layer client isolation for OpenClaw agent sessions. When an agent is
spawned for a specific client, this hook ensures it can **never** access
another client's files — enforced at the OS kernel level via macOS `sandbox-exec`.

## How It Works

### Layer 1: Bootstrap Injection (`agent:bootstrap`)
When a new session starts, the hook reads `metadata.client_id` from the session
context and:
1. Generates a macOS `sandbox-exec` profile (`.sb` file) restricting file access
   to only the assigned client's directory
2. Injects a `GUARD.md` into the session's workspace files with explicit
   boundary rules the agent must follow
3. Sets environment variables (`CLIENT_SCOPE_DIR`, `CLIENT_SCOPE_PROFILE`) for
   the terminal wrapper to use

### Layer 2: Tool Result Audit (`tool_result_persist`)
Before tool results are persisted to the session transcript, the hook inspects
file paths in the result and:
1. Validates all paths are within the allowed client scope
2. Logs violations to `audit.jsonl`
3. Blocks persistence of results that contain scope violations

### Layer 3: Terminal Sandboxing (`scope-exec.sh`)
A shell wrapper that applies the generated `sandbox-exec` profile to all
terminal commands the agent executes. Even if the agent constructs a command
like `cat /path/to/other/client/brief.md`, the kernel denies the read.

## Configuration

Set via hook environment variables in your OpenClaw config:

```json5
{
  hooks: {
    internal: {
      entries: {
        "client-scope-guard": {
          enabled: true,
          env: {
            // Base directory containing client directories
            "SCOPE_CLIENTS_DIR": "/path/to/cerebrox/clients",
            // Base project directory (for agent configs, node_modules)
            "SCOPE_PROJECT_DIR": "/path/to/project",
            // Whether to allow network access in sandbox (default: true)
            "SCOPE_ALLOW_NETWORK": "true",
            // Log level: "silent" | "violations" | "all" (default: "violations")
            "SCOPE_LOG_LEVEL": "violations"
          }
        }
      }
    }
  }
}
```

## Session Metadata

The hook expects `metadata.client_id` in the session context. When spawning
sessions via the OpenClaw API, include:

```json
{
  "metadata": {
    "client_id": "clt_abc12345",
    "order_id": "ord_xyz",
    "agent_type": "web-design"
  }
}
```

## Audit Log

Violations are logged to `~/.openclaw/hooks/client-scope-guard/audit.jsonl`:

```jsonl
{"timestamp":"2026-02-14T12:00:00Z","sessionKey":"ses_abc","clientId":"clt_abc","tool":"file_read","path":"/clients/clt_xyz/brief.md","allowed":false,"reason":"Read denied: outside client scope"}
```

## Requirements

- macOS with `sandbox-exec` available (`/usr/bin/sandbox-exec`)
- Node.js 22+
- OpenClaw 2026.2.9+
