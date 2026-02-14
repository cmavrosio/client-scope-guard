# client-scope-guard

**OpenClaw hook for client/tenant isolation — prevents agents from accessing other clients' data, enforced at the macOS kernel level via `sandbox-exec`.**

When you run multiple clients through OpenClaw (e.g., a digital agency spawning agents per client), each agent session should be fully isolated. This hook ensures that an agent assigned to `client_a` can **never** read, write, or list files belonging to `client_b` — even if the LLM is tricked via prompt injection.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    Three Enforcement Layers                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: agent:bootstrap hook                              │
│  ├── Reads metadata.client_id from session                  │
│  ├── Generates macOS sandbox-exec profile (.sb)             │
│  ├── Injects GUARD.md with explicit scope boundaries        │
│  └── Sets CLIENT_SCOPE_* env vars for terminal wrapper      │
│                                                             │
│  Layer 2: tool_result_persist hook                          │
│  ├── Inspects file paths in tool results                    │
│  ├── Validates paths against allowed client scope           │
│  ├── Blocks persistence of scope-violating results          │
│  └── Logs violations to audit.jsonl                         │
│                                                             │
│  Layer 3: macOS sandbox-exec (kernel-level)                 │
│  ├── Terminal wrapper applies .sb profile to all commands   │
│  ├── OS denies file access to other client directories      │
│  ├── Returns "Operation not permitted" on violation         │
│  └── Cannot be bypassed by the agent process                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Verified on macOS

Tested on Darwin 25.2.0 (macOS Tahoe). All isolation tests pass:

| Test | Result |
|------|--------|
| Read own client's files | Allowed |
| Read other client's files | **Operation not permitted** |
| Write to own deliverables | Allowed |
| Write to other client's deliverables | **Operation not permitted** |
| List other client's directory | **Operation not permitted** |
| System tools (Node.js, npm, git) | Work normally |
| Path traversal (`../../`) | **Blocked** |

## Installation

```bash
# Install from GitHub
openclaw hooks install https://github.com/cmavrosio/client-scope-guard

# Or clone and link locally
git clone https://github.com/cmavrosio/client-scope-guard.git
openclaw hooks install ./client-scope-guard --link

# Enable the hook
openclaw hooks enable client-scope-guard
```

## Configuration

Add to your `~/.openclaw/openclaw.json`:

```json5
{
  hooks: {
    internal: {
      entries: {
        "client-scope-guard": {
          enabled: true,
          env: {
            // Directory containing client subdirectories (clients/clt_xxx/)
            "SCOPE_CLIENTS_DIR": "/path/to/your/clients",
            // Log level: "silent" | "violations" | "all"
            "SCOPE_LOG_LEVEL": "violations",
            // Allow network access in sandbox (default: true)
            "SCOPE_ALLOW_NETWORK": "true"
          }
        }
      }
    }
  }
}
```

## Session Metadata

When creating OpenClaw sessions, include `client_id` in the metadata:

```json
{
  "metadata": {
    "client_id": "clt_abc12345"
  }
}
```

The hook reads `metadata.client_id` to determine which client directory to allow and which sibling directories to deny.

## How the Sandbox Profile Works

Instead of the fragile allow-list approach (which breaks system tools), this hook uses a **deny-list strategy**:

```scheme
(version 1)
(allow default)          ; Everything works normally

; Block sibling client directories at the kernel level
(deny file-read*  (subpath "/path/to/clients/clt_other_client"))
(deny file-write* (subpath "/path/to/clients/clt_other_client"))

; Block sensitive system directories
(deny file-read*  (subpath "$HOME/.openclaw/credentials"))
(deny file-read*  (subpath "$HOME/.ssh"))
```

This profile is generated dynamically per session. The hook scans the `clients/` directory, finds all sibling client directories, and creates deny rules for each one.

## Terminal Wrapper

The included `scope-exec.sh` wraps all terminal commands with `sandbox-exec`:

```bash
# Without wrapper: agent can access any file
cat /path/to/clients/clt_other/brief.md  # works

# With wrapper: kernel blocks the access
scope-exec.sh cat /path/to/clients/clt_other/brief.md
# → "Operation not permitted"
```

## Audit Log

Violations are logged to `~/.openclaw/hooks/client-scope-guard/audit.jsonl`:

```jsonl
{"timestamp":"2026-02-14T12:00:00Z","sessionKey":"ses_abc","clientId":"clt_abc","tool":"file_read","path":"/clients/clt_xyz/brief.md","operation":"read","allowed":false,"reason":"Read denied: outside client scope"}
```

## File Structure

```
client-scope-guard/
├── HOOK.md          # Hook metadata (events, requirements)
├── handler.ts       # Main hook handler (bootstrap + audit)
├── validate.ts      # Path validation (traversal, symlinks, scope)
├── sandbox.ts       # macOS sandbox-exec profile generator
├── scope-exec.sh    # Terminal wrapper script
└── README.md        # This file
```

## Requirements

- macOS with `/usr/bin/sandbox-exec` (tested on Darwin 25.2.0)
- OpenClaw 2026.2.9+
- Node.js 22+

## Related Issues

- [openclaw/openclaw#7827](https://github.com/openclaw/openclaw/issues/7827) — Default Safety Posture: Sandbox & Session Isolation
- [openclaw/openclaw#11829](https://github.com/openclaw/openclaw/issues/11829) — Security Roadmap: Protecting API Keys from Agent Access

## License

MIT
