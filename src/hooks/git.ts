/**
 * Git pre-commit hook. Table stakes rather than the point of the project, but
 * the agent hooks only cover what goes through an agent — a developer can still
 * paste a key straight into a file and commit it.
 */
import { execFileSync } from "node:child_process";
import { loadConfig } from "../config/index.js";
import { scan, blocking } from "../core/scan.js";

const NUL = String.fromCharCode(0);

function stagedFiles(): string[] {
  try {
    const out = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], {
      encoding: "utf8",
    });
    return out.split("\n").map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function stagedContent(path: string): string {
  try {
    return execFileSync("git", ["show", `:${path}`], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  } catch {
    return "";
  }
}

export function runPreCommit(): number {
  const config = loadConfig();
  const problems: string[] = [];

  for (const path of stagedFiles()) {
    const content = stagedContent(path);
    // Skip anything that is not text; a binary blob produces noise, not signal.
    if (!content || content.indexOf(NUL) !== -1) continue;

    const { findings } = scan(content, { ...config, path });
    for (const f of blocking(findings, config)) {
      const line = content.slice(0, f.start).split("\n").length;
      problems.push(`  ${path}:${line}  ${f.ruleId} (${f.provider})`);
    }
  }

  if (problems.length === 0) return 0;

  process.stderr.write(
    [
      "",
      `secretgate: ${problems.length} credential(s) in staged changes`,
      "",
      ...problems,
      "",
      "Options:",
      "  - remove the credential and commit again",
      '  - add "# secretgate:allow" on the line if this is a false positive',
      "  - run `secretgate baseline` to accept everything currently flagged",
      "  - `git commit --no-verify` to override, if you are certain",
      "",
    ].join("\n"),
  );
  return 1;
}
