#!/bin/bash
# client-scope-guard — Terminal Wrapper
#
# Wraps terminal commands with macOS sandbox-exec using the session's
# dynamically generated sandbox profile.
#
# Usage: scope-exec.sh <command> [args...]
#
# Environment variables (set by the hook at bootstrap):
#   CLIENT_SCOPE_PROFILE  — Path to the .sb sandbox profile
#   CLIENT_SCOPE_DIR      — Allowed client directory (for logging)
#   CLIENT_SCOPE_ID       — Client ID (for logging)
#
# If CLIENT_SCOPE_PROFILE is set and the file exists, the command runs
# inside sandbox-exec. Otherwise, the command runs normally (no guard).

set -euo pipefail

# Log function
log_scope() {
  local level="$1"
  local msg="$2"
  echo "[scope-guard:${CLIENT_SCOPE_ID:-unknown}] ${level}: ${msg}" >&2
}

# Check if sandboxing is configured for this session
if [ -z "${CLIENT_SCOPE_PROFILE:-}" ]; then
  # No scope profile — run command directly
  exec "$@"
fi

if [ ! -f "${CLIENT_SCOPE_PROFILE}" ]; then
  log_scope "WARN" "Sandbox profile not found at ${CLIENT_SCOPE_PROFILE} — running unguarded"
  exec "$@"
fi

# Quick path check in the command arguments (defense in depth)
# Even though sandbox-exec will block, we log the attempt here
if [ -n "${CLIENT_SCOPE_DIR:-}" ]; then
  CLIENTS_PARENT="$(dirname "${CLIENT_SCOPE_DIR}")"
  CMD_STRING="$*"

  # Check if the command references /clients/ paths that aren't our client
  if echo "${CMD_STRING}" | grep -qE "/clients/[a-z]{3}_[a-zA-Z0-9]+" 2>/dev/null; then
    # Extract all client IDs from the command
    REFERENCED_CLIENTS=$(echo "${CMD_STRING}" | grep -oE "clients/[a-z]{3}_[a-zA-Z0-9]+" | sed 's|clients/||g' | sort -u)
    for ref_client in ${REFERENCED_CLIENTS}; do
      if [ "${ref_client}" != "${CLIENT_SCOPE_ID:-}" ]; then
        log_scope "BLOCK" "Command references client '${ref_client}' but session is scoped to '${CLIENT_SCOPE_ID}'"
        echo "Error: Access denied — this session is scoped to client ${CLIENT_SCOPE_ID}" >&2
        exit 1
      fi
    done
  fi
fi

# Run the command inside sandbox-exec with the session's profile
log_scope "INFO" "Executing under sandbox: $1"
exec /usr/bin/sandbox-exec -f "${CLIENT_SCOPE_PROFILE}" -- "$@"
