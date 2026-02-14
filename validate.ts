/**
 * client-scope-guard — Path Validation Module
 *
 * Validates that file paths stay within an assigned client scope.
 * Handles path traversal attacks, symlink escapes, and normalization.
 *
 * Reusable by both the OpenClaw hook and CEREBROX middleware.
 */

import { resolve, normalize, relative, sep } from "path";
import { realpathSync, lstatSync } from "fs";

export interface ScopeConfig {
  /** Client ID (e.g., clt_abc12345) */
  clientId: string;
  /** Absolute path to the client's root directory (read access) */
  clientDir: string;
  /** Absolute path to the client's deliverables directory (write access) */
  deliverablesDir: string;
  /** Additional read-only paths allowed (e.g., agent configs) */
  additionalReadPaths?: string[];
}

export interface ValidationResult {
  allowed: boolean;
  reason: string;
  resolvedPath: string;
  scope: "client_read" | "deliverables_write" | "additional_read" | "denied";
}

/**
 * Check if a target path is contained within an allowed directory.
 * Resolves symlinks and normalizes to prevent traversal.
 */
function isContainedIn(targetPath: string, allowedDir: string): boolean {
  const normalizedTarget = normalize(resolve(targetPath));
  const normalizedAllowed = normalize(resolve(allowedDir));

  // Ensure the allowed dir ends with separator for prefix matching
  const allowedPrefix = normalizedAllowed.endsWith(sep)
    ? normalizedAllowed
    : normalizedAllowed + sep;

  return (
    normalizedTarget === normalizedAllowed ||
    normalizedTarget.startsWith(allowedPrefix)
  );
}

/**
 * Attempt to resolve symlinks safely. If the target doesn't exist yet
 * (write operation), resolve the parent directory instead.
 */
function safeRealpath(targetPath: string): string {
  try {
    return realpathSync(targetPath);
  } catch {
    // File doesn't exist — resolve parent to check for symlink escapes
    const parent = resolve(targetPath, "..");
    try {
      const realParent = realpathSync(parent);
      const basename = targetPath.split(sep).pop() || "";
      return resolve(realParent, basename);
    } catch {
      // Parent doesn't exist either — use normalized path
      return normalize(resolve(targetPath));
    }
  }
}

/**
 * Detect path traversal patterns in the raw input.
 * This catches attempts before normalization.
 */
function hasTraversalPattern(rawPath: string): boolean {
  const patterns = [
    /\.\.\//,      // ../
    /\.\.\\/,      // ..\
    /\.\.$/,       // ends with ..
    /\/\.\.\//,    // /../
    /\\\.\.\\/,    // \..\
  ];
  return patterns.some((p) => p.test(rawPath));
}

/**
 * Validate whether a file path is within the allowed client scope.
 *
 * @param targetPath  The path the agent is trying to access
 * @param scope       The client's scope configuration
 * @param operation   Whether this is a 'read' or 'write' operation
 */
export function validatePath(
  targetPath: string,
  scope: ScopeConfig,
  operation: "read" | "write" = "read"
): ValidationResult {
  const resolvedPath = safeRealpath(targetPath);

  // Check for traversal patterns in raw input
  if (hasTraversalPattern(targetPath)) {
    const rel = relative(scope.clientDir, resolvedPath);
    // If after resolution it's still within scope, allow it
    // but flag the traversal attempt
    if (!isContainedIn(resolvedPath, scope.clientDir)) {
      return {
        allowed: false,
        reason: `Path traversal detected: "${targetPath}" resolves outside client scope to "${resolvedPath}"`,
        resolvedPath,
        scope: "denied",
      };
    }
  }

  // For write operations, must be within deliverables directory
  if (operation === "write") {
    if (isContainedIn(resolvedPath, scope.deliverablesDir)) {
      return {
        allowed: true,
        reason: "Within deliverables directory (write allowed)",
        resolvedPath,
        scope: "deliverables_write",
      };
    }
    return {
      allowed: false,
      reason: `Write denied: "${resolvedPath}" is outside deliverables scope "${scope.deliverablesDir}"`,
      resolvedPath,
      scope: "denied",
    };
  }

  // For read operations, check client directory
  if (isContainedIn(resolvedPath, scope.clientDir)) {
    return {
      allowed: true,
      reason: "Within client directory (read allowed)",
      resolvedPath,
      scope: "client_read",
    };
  }

  // Check additional read-only paths (agent configs, node_modules, etc.)
  if (scope.additionalReadPaths) {
    for (const allowedPath of scope.additionalReadPaths) {
      if (isContainedIn(resolvedPath, allowedPath)) {
        return {
          allowed: true,
          reason: `Within additional read path: ${allowedPath}`,
          resolvedPath,
          scope: "additional_read",
        };
      }
    }
  }

  return {
    allowed: false,
    reason: `Read denied: "${resolvedPath}" is outside client scope "${scope.clientDir}"`,
    resolvedPath,
    scope: "denied",
  };
}

/**
 * Extract file paths from a tool call's arguments.
 * Handles common OpenClaw tool argument shapes.
 */
export function extractPathsFromToolArgs(
  toolName: string,
  args: Record<string, unknown>
): { path: string; operation: "read" | "write" }[] {
  const paths: { path: string; operation: "read" | "write" }[] = [];

  switch (toolName) {
    case "file_read":
    case "read":
      if (typeof args.path === "string") {
        paths.push({ path: args.path, operation: "read" });
      }
      if (typeof args.file_path === "string") {
        paths.push({ path: args.file_path, operation: "read" });
      }
      break;

    case "file_write":
    case "write":
    case "edit":
    case "apply_patch":
      if (typeof args.path === "string") {
        paths.push({ path: args.path, operation: "write" });
      }
      if (typeof args.file_path === "string") {
        paths.push({ path: args.file_path, operation: "write" });
      }
      break;

    case "terminal":
    case "exec":
      // Terminal commands are harder to validate — handled by sandbox-exec
      // But we can check for obvious file path arguments
      if (typeof args.command === "string") {
        const pathMatches = args.command.match(
          /(?:^|\s)(\/[^\s;|&]+)/g
        );
        if (pathMatches) {
          for (const match of pathMatches) {
            const p = match.trim();
            // Heuristic: if the command contains paths to clients/, flag them
            if (p.includes("/clients/")) {
              paths.push({ path: p, operation: "read" });
            }
          }
        }
      }
      break;

    default:
      // For unknown tools, check common path-like fields
      for (const [key, value] of Object.entries(args)) {
        if (
          typeof value === "string" &&
          (key.includes("path") || key.includes("file") || key.includes("dir"))
        ) {
          paths.push({ path: value, operation: "read" });
        }
      }
  }

  return paths;
}

/**
 * Validate all paths in a tool call against the client scope.
 * Returns the first violation found, or null if all paths are allowed.
 */
export function validateToolCall(
  toolName: string,
  args: Record<string, unknown>,
  scope: ScopeConfig
): ValidationResult | null {
  const paths = extractPathsFromToolArgs(toolName, args);

  for (const { path, operation } of paths) {
    const result = validatePath(path, scope, operation);
    if (!result.allowed) {
      return result;
    }
  }

  return null; // All paths valid
}
