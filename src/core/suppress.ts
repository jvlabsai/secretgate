import { createHash } from "node:crypto";
import type { Config, Finding } from "./types.js";

/**
 * Long enough to be unambiguous, so a plain substring test is safe. Nothing
 * shorter belongs here: a random 80-character key contains a given 4-letter
 * sequence roughly once in a thousand, and silently dropping one real key in a
 * thousand is exactly the failure a secret scanner must not have.
 */
const STRONG_MARKERS = [
  "example",
  "changeme",
  "change_me",
  "change-me",
  "placeholder",
  "redacted",
  "notreal",
  "not_real",
  "donotuse",
  "do_not_use",
  "dont_use",
  "secretgate",
  "yourapikey",
  "your_api_key",
  "youraccountkey",
  "loremipsum",
];

/**
 * Credentials that ship inside vendor documentation. Everyone's scanner needs a
 * list like this; these two are in the AWS docs verbatim and turn up in every
 * tutorial ever written.
 */
const WELL_KNOWN_FAKES = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "AKIAI44QH8DHBEXAMPLE",
  "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
]);

/**
 * One of these as a whole delimiter-separated token is enough to call a value
 * fake. Matched as tokens, never substrings, so a real key containing the
 * letters "test" survives while `sk-test-abc` does not.
 */
const STRONG_TOKENS = new Set([
  "your",
  "yours",
  "example",
  "examples",
  "sample",
  "dummy",
  "todo",
  "tbd",
  "fixme",
  "insert",
  "replace",
  "here",
  "test",
  "testing",
  "fake",
  "mock",
  "foo",
  "bar",
  "baz",
  "foobar",
  "abc",
  "abcd",
  "abcdef",
  "lorem",
  "ipsum",
  "none",
  "null",
  "nil",
  "undefined",
  "empty",
  "unset",
]);

/**
 * Words that describe a credential rather than being one. A single occurrence
 * proves nothing — Mailgun keys genuinely start `key-`, and every PEM block
 * contains the word KEY twice — so these only count when two *different* ones
 * show up, which is the signature of a human-written stand-in like
 * `my-secret-password`.
 */
const WEAK_TOKENS = new Set([
  "key",
  "keys",
  "token",
  "secret",
  "password",
  "passwd",
  "pass",
  "credential",
  "credentials",
  "value",
  "string",
  "api",
  "auth",
  "my",
  "the",
  "some",
  "goes",
  "put",
]);

const SEQUENTIAL = /(?:0123456789|abcdefghij|qwertyuiop|1234567890)/i;

export function isPlaceholderValue(value: string): boolean {
  const v = value.toLowerCase();

  if (WELL_KNOWN_FAKES.has(value)) return true;

  for (const marker of STRONG_MARKERS) {
    if (v.includes(marker)) return true;
  }

  // Delimiter-separated words only. Splitting on non-alphanumerics means
  // `sk-test-9f2a` is caught by its `test` token, while `Rt3sTk9...` is not.
  const weakSeen = new Set<string>();
  for (const token of v.split(/[^a-z0-9]+/)) {
    if (!token) continue;
    if (STRONG_TOKENS.has(token)) return true;
    if (WEAK_TOKENS.has(token)) weakSeen.add(token);
  }
  if (weakSeen.size >= 2) return true;

  // The value is nothing but the word for the thing: `password`, `token`.
  const bare = v.replace(/[^a-z0-9]/g, "");
  if (WEAK_TOKENS.has(bare) || STRONG_TOKENS.has(bare)) return true;

  // A reference to a secret rather than the secret itself: `var.db_password`,
  // `process.env.API_KEY`, `secrets.GITHUB_TOKEN`, `settings.SECRET_KEY`.
  if (/^(?:var|local|data|module|env|process|os|config|conf|cfg|settings|secrets|vault|self|this)\b[.[]/i.test(value)) {
    return true;
  }

  // Angle-bracket / brace / dollar templating: <API_KEY>, ${API_KEY}, {{key}}.
  if (/^[<{$%]/.test(value) || /[>}%]$/.test(value)) return true;

  // Four or more x's in a row is a redaction, never a CSPRNG.
  if (/x{4,}/i.test(value)) return true;

  // Effectively one or two distinct characters once a provider prefix is
  // stripped: AKIAXXXXXXXXXXXXXXXX, ghp_aaaaaaaa...
  const body = value.replace(/^[A-Za-z]{2,12}[_-]/, "");
  if (body.length > 3 && new Set(body.toLowerCase()).size <= 2) return true;

  if (SEQUENTIAL.test(v)) return true;

  // A run of 6+ identical characters is not something a CSPRNG produces.
  if (/(.)\1{5,}/.test(value)) return true;

  return false;
}

const PRAGMA = /(?:^|[#/*;-]|<!--)\s*secretgate\s*:\s*(?:allow|ignore|disable)/i;

/** `# secretgate:allow` on the finding's own line opts that line out. */
export function hasInlinePragma(text: string, index: number): boolean {
  const lineStart = text.lastIndexOf("\n", index) + 1;
  let lineEnd = text.indexOf("\n", index);
  if (lineEnd === -1) lineEnd = text.length;
  return PRAGMA.test(text.slice(lineStart, lineEnd));
}

const TEST_PATH =
  /(?:^|[\\/])(?:tests?|__tests__|fixtures?|testdata|mocks?|__mocks__|examples?|spec|specs)[\\/]|(?:\.|_|-)(?:test|spec)\.[a-z]+$|_test\.go$|\.example$|\.sample$|\.template$/i;

export function isTestPath(path: string | undefined): boolean {
  if (!path) return false;
  return TEST_PATH.test(path.replace(/\\/g, "/"));
}

/**
 * Minimal glob support: `**` any depth, `*` within a segment, `?` one char.
 * A real glob library would be a dependency for something this small.
 * ponytail: no brace expansion or negation; add picomatch if users ask for it.
 */
export function globMatch(pattern: string, path: string): boolean {
  const normalized = path.replace(/\\/g, "/");
  let rx = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        i++;
        if (pattern[i + 1] === "/") {
          i++;
          rx += "(?:.*/)?"; // `**/` is allowed to match zero directories
        } else {
          rx += ".*";
        }
      } else {
        rx += "[^/]*";
      }
    } else if (c === "?") {
      rx += "[^/]";
    } else if (".+^${}()|[]\\".includes(c)) {
      rx += `\\${c}`;
    } else {
      rx += c;
    }
  }
  // Anchored at the start for absolute patterns, and again at any segment
  // boundary so `**/fixtures/**` still works on a path given to us relative.
  return new RegExp(`^${rx}$`).test(normalized) || new RegExp(`(?:^|/)${rx}$`).test(normalized);
}

export function isAllowlistedPath(path: string | undefined, patterns: string[]): boolean {
  if (!path) return false;
  return patterns.some((p) => globMatch(p, path));
}

export function matchesAllowlistPattern(value: string, patterns: string[]): boolean {
  return patterns.some((p) => {
    try {
      return new RegExp(p).test(value);
    } catch {
      return false;
    }
  });
}

/**
 * Salted so a baseline file cannot be brute-forced back into the secrets it
 * describes. The salt sits next to the hashes, which is fine — it defeats
 * precomputed tables, not someone who already holds both the file and a guess.
 */
export function fingerprint(value: string, salt: string): string {
  return createHash("sha256").update(salt).update(" ").update(value).digest("hex").slice(0, 32);
}

export interface SuppressionVerdict {
  suppressed: boolean;
  downgraded: boolean;
  note?: string;
}

export function evaluateSuppression(finding: Finding, text: string, config: Config): SuppressionVerdict {
  if (isPlaceholderValue(finding.match)) {
    return { suppressed: true, downgraded: false, note: "placeholder value" };
  }
  if (hasInlinePragma(text, finding.start)) {
    return { suppressed: true, downgraded: false, note: "secretgate:allow pragma" };
  }
  if (matchesAllowlistPattern(finding.match, config.allowlist.patterns)) {
    return { suppressed: true, downgraded: false, note: "allowlist pattern" };
  }
  if (isAllowlistedPath(config.path, config.allowlist.paths)) {
    return { suppressed: true, downgraded: false, note: "allowlisted path" };
  }
  if (config.baseline && config.baselineSalt) {
    if (config.baseline.has(fingerprint(finding.match, config.baselineSalt))) {
      return { suppressed: true, downgraded: false, note: "accepted in baseline" };
    }
  }
  if (isTestPath(config.path)) {
    // Downgraded rather than dropped: fixtures do occasionally hold a live key,
    // and the developer should still get to see it.
    return { suppressed: false, downgraded: true, note: "test/fixture path" };
  }
  return { suppressed: false, downgraded: false };
}
