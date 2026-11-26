// Paths that go to Trojan's servers (and the AI model behind them) must not
// name the user's home folder, which is usually their name:
// /Users/alice/clients/acme-shop. Send the project's folder name, and file
// paths relative to the project. Mirrors internal/outbound in the CLI.

/** Last element of a folder path ("acme-shop"); "" for "" or a root. */
export function folderName(p: string | null | undefined): string {
  const s = (p ?? "").trim().replace(/[/\\]+$/, "");
  if (s === "") return "";
  const name = s.slice(Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\")) + 1);
  return name === "" || name.endsWith(":") ? "" : name;
}

const isUrl = (p: string) => /^(https?|wss?):\/\//i.test(p);
const isAbs = (p: string) => p.startsWith("/") || p.startsWith("\\\\") || /^[a-z]:[\\/]/i.test(p);
const slash = (p: string) => p.replace(/\\/g, "/");

/**
 * p relative to root ("src/a.ts", or "." for root itself), or just the file
 * name when an absolute p is outside root. Relative paths and web addresses
 * are returned as they are.
 */
export function relativeToProject(root: string | null | undefined, p: string | null | undefined): string {
  const path = p ?? "";
  if (path === "" || isUrl(path) || !isAbs(path)) return path;
  const r = slash(root ?? "").replace(/\/+$/, "");
  const q = slash(path);
  if (r !== "") {
    if (q.toLowerCase() === r.toLowerCase()) return ".";
    if (q.startsWith(r + "/")) return q.slice(r.length + 1);
  }
  return folderName(path);
}

// Finding fields that can hold a local file path. Scan JSON from the CLI uses
// FilePath and source_file; the desktop's own Finding type calls it file.
const PATH_FIELDS = ["FilePath", "source_file", "file"] as const;

/** Copies of findings with their file paths made relative to root. */
export function findingsForUpload<T extends object>(root: string | null | undefined, findings: T[]): T[] {
  return findings.map((f) => {
    const out = { ...f } as Record<string, unknown>;
    for (const k of PATH_FIELDS) {
      if (typeof out[k] === "string") out[k] = relativeToProject(root, out[k] as string);
    }
    return out as T;
  });
}
