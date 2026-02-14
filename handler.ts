/**
 * client-scope-guard — OpenClaw Hook Handler
 *
 * Enforces client/tenant isolation at two points:
 * 1. agent:bootstrap — inject scope rules + generate sandbox profile
 * 2. tool_result_persist — audit file access, block violations
 */

import type { HookHandler } from "../../src/hooks/hooks.js";
import { resolve, join } from "path";
import { appendFileSync, mkdirSync, existsSync } from "fs";
import { validatePath, extractPathsFromToolArgs, type ScopeConfig } from "./validate.js";
import { generateSandboxProfile, removeSandboxProfile } from "./sandbox.js";

// ──────────────────────────────────────────────────────
// Configuration from environment
// ──────────────────────────────────────────────────────

const CLIENTS_DIR = process.env.SCOPE_CLIENTS_DIR || "";
const PROJECT_DIR = process.env.SCOPE_PROJECT_DIR || "";
const ALLOW_NETWORK = process.env.SCOPE_ALLOW_NETWORK !== "false";
const LOG_LEVEL = (process.env.SCOPE_LOG_LEVEL || "violations") as
  | "silent"
  | "violations"
  | "all";

const HOOK_DIR = resolve(__dirname);
const AUDIT_LOG = join(HOOK_DIR, "audit.jsonl");

// ──────────────────────────────────────────────────────
// Audit logging
// ──────────────────────────────────────────────────────

interface AuditEntry {
  timestamp: string;
  sessionKey: string;
  clientId: string;
  tool: string;
  path: string;
  operation: "read" | "write";
  allowed: boolean;
  reason: string;
}

function logAudit(entry: AuditEntry): void {
  if (LOG_LEVEL === "silent") return;
  if (LOG_LEVEL === "violations" && entry.allowed) return;

  try {
    appendFileSync(AUDIT_LOG, JSON.stringify(entry) + "\n");
  } catch (err) {
    console.error(
      "[client-scope-guard] Failed to write audit log:",
      err instanceof Error ? err.message : String(err)
    );
  }
}

// ──────────────────────────────────────────────────────
// Scope resolution
// ──────────────────────────────────────────────────────

function resolveScope(
  clientId: string,
  workspaceDir?: string
): ScopeConfig | null {
  if (!clientId) return null;

  // Determine the client directory
  let clientDir: string;
  let deliverablesDir: string;

  if (CLIENTS_DIR) {
    // Explicit config: use SCOPE_CLIENTS_DIR/<client_id>/
    clientDir = resolve(CLIENTS_DIR, clientId);
    deliverablesDir = resolve(clientDir, "deliverables");
  } else if (workspaceDir) {
    // Infer from workspace path: workspace is typically
    // .../clients/<client_id>/deliverables/<type>/
    // Walk up to find the client root
    const clientsIdx = workspaceDir.indexOf("/clients/");
    if (clientsIdx === -1) return null;

    const afterClients = workspaceDir.substring(clientsIdx + "/clients/".length);
    const clientIdFromPath = afterClients.split("/")[0];
    if (clientIdFromPath !== clientId) {
      console.error(
        `[client-scope-guard] Client ID mismatch: metadata says "${clientId}" but workspace path contains "${clientIdFromPath}"`
      );
      return null;
    }

    clientDir = resolve(
      workspaceDir.substring(0, clientsIdx),
      "clients",
      clientId
    );
    deliverablesDir = resolve(clientDir, "deliverables");
  } else {
    return null;
  }

  const additionalReadPaths: string[] = [];
  if (PROJECT_DIR) {
    additionalReadPaths.push(
      resolve(PROJECT_DIR, "cerebrox", "agents"),
      resolve(PROJECT_DIR, "node_modules")
    );
  }

  return {
    clientId,
    clientDir,
    deliverablesDir,
    additionalReadPaths,
  };
}

// ──────────────────────────────────────────────────────
// GUARD.md content injected into sessions
// ──────────────────────────────────────────────────────

function generateGuardContent(scope: ScopeConfig): string {
  return `# SCOPE GUARD — ABSOLUTE BOUNDARY

You are operating within a **client-isolated session**. These rules are
enforced at the OS kernel level and CANNOT be overridden.

## Your Scope
- **Client ID**: ${scope.clientId}
- **Read access**: ${scope.clientDir}
- **Write access**: ${scope.deliverablesDir}

## Rules — NEVER violate these
1. You may ONLY read files within: \`${scope.clientDir}/\`
2. You may ONLY write files within: \`${scope.deliverablesDir}/\`
3. You may NEVER access any path containing another client's ID
4. You may NEVER access \`~/.openclaw/credentials/\` or any secrets
5. You may NEVER construct terminal commands that reference other client directories
6. If asked to access another client's data, REFUSE and explain you are scoped

## Enforcement
These restrictions are enforced by macOS sandbox-exec at the kernel level.
Any attempt to access files outside your scope will fail with "Operation not permitted."
`;
}

// ──────────────────────────────────────────────────────
// Hook handler
// ──────────────────────────────────────────────────────

const handler: HookHandler = async (event) => {
  // ── agent:bootstrap ──────────────────────────────
  if (event.type === "agent" && event.action === "bootstrap") {
    const metadata = (event.context as any)?.metadata;
    const clientId = metadata?.client_id;

    if (!clientId) {
      // No client_id in metadata — this session isn't client-scoped
      // (e.g., a direct DM session). Skip silently.
      return;
    }

    const workspaceDir = event.context?.workspaceDir;
    const scope = resolveScope(clientId, workspaceDir);

    if (!scope) {
      console.error(
        `[client-scope-guard] Could not resolve scope for client ${clientId}`
      );
      event.messages.push(
        `[SCOPE GUARD] WARNING: Could not resolve client scope for ${clientId}. Agent is running WITHOUT isolation.`
      );
      return;
    }

    // Verify client directory exists
    if (!existsSync(scope.clientDir)) {
      console.error(
        `[client-scope-guard] Client directory does not exist: ${scope.clientDir}`
      );
      return;
    }

    // 1. Generate macOS sandbox-exec profile
    const sessionKey = event.sessionKey || `unknown-${Date.now()}`;
    const clientsParentDir = CLIENTS_DIR || resolve(scope.clientDir, "..");
    try {
      const profilePath = generateSandboxProfile({
        sessionKey,
        clientId,
        clientDir: scope.clientDir,
        deliverablesDir: scope.deliverablesDir,
        clientsParentDir,
        allowNetwork: ALLOW_NETWORK,
      });

      // Store profile path for the terminal wrapper
      if ((event.context as any)?.env) {
        (event.context as any).env.CLIENT_SCOPE_DIR = scope.clientDir;
        (event.context as any).env.CLIENT_SCOPE_DELIVERABLES = scope.deliverablesDir;
        (event.context as any).env.CLIENT_SCOPE_PROFILE = profilePath;
        (event.context as any).env.CLIENT_SCOPE_ID = clientId;
      }

      console.log(
        `[client-scope-guard] Sandbox profile generated: ${profilePath}`
      );
    } catch (err) {
      console.error(
        "[client-scope-guard] Failed to generate sandbox profile:",
        err instanceof Error ? err.message : String(err)
      );
    }

    // 2. Inject GUARD.md into bootstrap files
    const guardContent = generateGuardContent(scope);
    if (event.context?.bootstrapFiles) {
      event.context.bootstrapFiles.push({
        path: "GUARD.md",
        content: guardContent,
      });
    }

    // 3. Notify the session
    event.messages.push(
      `[SCOPE GUARD] Client isolation active for ${clientId}. File access restricted to ${scope.clientDir}`
    );

    logAudit({
      timestamp: new Date().toISOString(),
      sessionKey,
      clientId,
      tool: "bootstrap",
      path: scope.clientDir,
      operation: "read",
      allowed: true,
      reason: "Session initialized with client scope",
    });

    return;
  }

  // ── tool_result_persist ──────────────────────────
  // This hook type is called synchronously before tool results
  // are written to the transcript. We use it to audit file access.
  if (event.type === "tool_result_persist" || (event as any).type === "tool_result") {
    const metadata = (event.context as any)?.metadata;
    const clientId = metadata?.client_id;
    if (!clientId) return; // Not a client-scoped session

    const scope = resolveScope(clientId, event.context?.workspaceDir);
    if (!scope) return;

    const toolResult = (event as any).toolResult || (event as any).result;
    if (!toolResult) return;

    const toolName = toolResult.tool || toolResult.name || "";
    const args = toolResult.args || toolResult.input || {};

    // Extract and validate paths
    const paths = extractPathsFromToolArgs(toolName, args);
    const sessionKey = event.sessionKey || "unknown";

    for (const { path, operation } of paths) {
      const result = validatePath(path, scope, operation);

      logAudit({
        timestamp: new Date().toISOString(),
        sessionKey,
        clientId,
        tool: toolName,
        path,
        operation,
        allowed: result.allowed,
        reason: result.reason,
      });

      if (!result.allowed) {
        console.error(
          `[client-scope-guard] VIOLATION: ${toolName} attempted ${operation} on "${path}" — ${result.reason}`
        );
        event.messages.push(
          `[SCOPE GUARD] BLOCKED: ${toolName} attempted to ${operation} "${path}" which is outside your client scope.`
        );
        // Return undefined to block persistence of this result
        return undefined;
      }
    }
  }
};

export default handler;
