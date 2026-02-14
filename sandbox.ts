/**
 * client-scope-guard — macOS sandbox-exec Profile Generator
 *
 * Generates dynamic .sb (Scheme-based) sandbox profiles that restrict
 * file access at the kernel level per client session.
 *
 * Uses a DENY-LIST approach (allow default + deny sibling client dirs)
 * which is the proven pattern on modern macOS. This doesn't break system
 * operations while still enforcing hard isolation between clients.
 *
 * sandbox-exec enforces restrictions at the syscall level — even if the
 * agent is tricked via prompt injection, the OS blocks the access.
 */

import { writeFileSync, mkdirSync, unlinkSync, readdirSync } from "fs";
import { resolve, basename } from "path";
import { homedir } from "os";

export interface SandboxProfileConfig {
  /** Unique session identifier for the profile filename */
  sessionKey: string;
  /** Client ID for logging */
  clientId: string;
  /** Absolute path to the client's root directory */
  clientDir: string;
  /** Absolute path to the client's deliverables (write-allowed) */
  deliverablesDir: string;
  /** Absolute path to the clients/ parent directory (contains all client dirs) */
  clientsParentDir: string;
  /** Whether to allow network access (default: true for npm/git) */
  allowNetwork?: boolean;
  /** Directory where .sb profiles are stored */
  profileDir?: string;
}

/**
 * Resolve a path to its /private/ prefix form on macOS.
 * On macOS, /tmp -> /private/tmp, and sandbox-exec uses the real paths.
 */
function toPrivatePath(p: string): string {
  if (p.startsWith("/tmp")) return "/private" + p;
  if (p.startsWith("/var")) return "/private" + p;
  if (p.startsWith("/etc")) return "/private" + p;
  return p;
}

/**
 * List all sibling client directories that should be denied access.
 * Returns resolved paths for all client dirs EXCEPT the current one.
 */
function getSiblingClientDirs(clientsParentDir: string, ownClientId: string): string[] {
  try {
    const entries = readdirSync(clientsParentDir, { withFileTypes: true });
    return entries
      .filter((e) => e.isDirectory() && e.name !== ownClientId && e.name.startsWith("clt_"))
      .map((e) => resolve(clientsParentDir, e.name));
  } catch {
    return [];
  }
}

/**
 * Generate a macOS sandbox-exec profile (.sb file) that blocks access
 * to other clients' directories while allowing everything else.
 *
 * Strategy: allow default + explicitly deny sibling client directories
 * and sensitive paths. This is the proven approach on modern macOS.
 *
 * @returns Absolute path to the generated .sb profile
 */
export function generateSandboxProfile(config: SandboxProfileConfig): string {
  const {
    sessionKey,
    clientId,
    clientDir,
    deliverablesDir,
    clientsParentDir,
    allowNetwork = true,
    profileDir = "/tmp/scope-guard",
  } = config;

  // Find all other client directories to deny
  const siblingDirs = getSiblingClientDirs(clientsParentDir, clientId);
  const home = homedir();

  // Build deny rules for sibling clients
  const denyRules = siblingDirs
    .map((dir) => {
      const privateDir = toPrivatePath(dir);
      return [
        `; Block: ${basename(dir)}`,
        `(deny file-read* (subpath "${dir}"))`,
        `(deny file-read* (subpath "${privateDir}"))`,
        `(deny file-write* (subpath "${dir}"))`,
        `(deny file-write* (subpath "${privateDir}"))`,
      ].join("\n");
    })
    .join("\n\n");

  const profile = `; client-scope-guard sandbox profile
; Generated for session: ${sessionKey}
; Client: ${clientId}
; Client directory: ${clientDir}
; Deliverables directory: ${deliverablesDir}
;
; Strategy: allow default + deny sibling client directories
; This ensures the agent can use system tools normally but
; CANNOT access any other client's data.

(version 1)
(allow default)

;; =========================================
;; DENY: other clients' directories
;; Kernel-level enforcement — these paths
;; return "Operation not permitted" on access
;; =========================================

${denyRules || "; (no sibling clients found — nothing to deny)"}

;; =========================================
;; DENY: sensitive system directories
;; =========================================
(deny file-read* (subpath "${home}/.openclaw/credentials"))
(deny file-read* (subpath "${home}/.ssh"))
(deny file-read* (subpath "${home}/.gnupg"))
(deny file-write* (subpath "${home}/.openclaw/credentials"))

;; =========================================
;; DENY: cross-client data leakage via UI
;; Blocks clipboard and screen capture so
;; agents cannot exfiltrate data visually
;; =========================================
(deny mach-lookup (global-name-prefix "com.apple.pasteboard"))
(deny mach-lookup (global-name-prefix "com.apple.window"))
(deny mach-lookup (global-name-prefix "com.apple.screencapture"))

${
  !allowNetwork
    ? `;; =========================================
;; Network DENIED (isolated mode)
;; =========================================
(deny network*)`
    : ""
}
`;

  // Write profile to disk
  mkdirSync(profileDir, { recursive: true });
  const profilePath = resolve(profileDir, `${sessionKey}.sb`);
  writeFileSync(profilePath, profile, { mode: 0o600 });

  return profilePath;
}

/**
 * Remove a sandbox profile after the session ends.
 */
export function removeSandboxProfile(sessionKey: string, profileDir = "/tmp/scope-guard"): void {
  try {
    const profilePath = resolve(profileDir, `${sessionKey}.sb`);
    unlinkSync(profilePath);
  } catch {
    // Profile may already be cleaned up
  }
}

/**
 * Generate a test profile for manual verification.
 *
 * Usage:
 *   sandbox-exec -f /tmp/scope-guard/test.sb -- cat /path/to/blocked/file
 *   → "Operation not permitted"
 */
export function generateTestProfile(
  allowedClientDir: string,
  blockedClientDir: string
): string {
  const profile = `; client-scope-guard TEST profile
; Allowed: ${allowedClientDir}
; Blocked: ${blockedClientDir}
(version 1)
(allow default)
(deny file-read* (subpath "${blockedClientDir}"))
(deny file-read* (subpath "${toPrivatePath(blockedClientDir)}"))
(deny file-write* (subpath "${blockedClientDir}"))
(deny file-write* (subpath "${toPrivatePath(blockedClientDir)}"))
`;

  const profilePath = "/tmp/scope-guard/test-profile.sb";
  mkdirSync("/tmp/scope-guard", { recursive: true });
  writeFileSync(profilePath, profile, { mode: 0o600 });
  return profilePath;
}
