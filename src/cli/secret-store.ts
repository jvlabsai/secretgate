import { execFileSync } from "node:child_process";
import { basename, dirname } from "node:path";

/**
 * Telling someone their `.env` contains credentials is true and useless. That
 * is what the file is for. Reporting it as a finding to "fix, suppress or
 * baseline" is worse than useless — all three suggestions are wrong for a
 * secrets file, and a tool that gives wrong advice on the most common file in
 * the project teaches people to stop reading its output.
 *
 * The question actually worth answering is whether git is going to publish it.
 */

const SECRET_STORE =
  /^\.env(?!\.(?:example|sample|template|dist|schema|defaults)\b)(\.[\w-]+)*$|^\.npmrc$|^\.netrc$|^\.pypirc$/i;

export function isSecretStore(path: string): boolean {
  return SECRET_STORE.test(basename(path));
}

export type IgnoreStatus = "ignored" | "not-ignored" | "no-repo";

/**
 * Asks git rather than parsing .gitignore ourselves. Negation rules, nested
 * ignore files, core.excludesFile and the global config are all things git
 * already knows and we would get subtly wrong.
 */
export function gitIgnoreStatus(path: string): IgnoreStatus {
  try {
    execFileSync("git", ["check-ignore", "-q", "--", path], {
      cwd: dirname(path) || ".",
      stdio: "ignore",
    });
    return "ignored";
  } catch (err) {
    const code = (err as { status?: number }).status;
    // 1 means "not ignored"; anything else means git could not answer, which
    // most often means we are not inside a repository at all.
    if (code === 1) return "not-ignored";
    return "no-repo";
  }
}

export interface StoreVerdict {
  path: string;
  status: IgnoreStatus;
  credentials: number;
  /** True when this is the case worth shouting about. */
  exposed: boolean;
}

export function assessStore(path: string, credentials: number): StoreVerdict {
  const status = gitIgnoreStatus(path);
  return { path, status, credentials, exposed: status === "not-ignored" };
}
