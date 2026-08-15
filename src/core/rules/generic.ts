import type { Rule } from "../types.js";

/**
 * The catch-all pack: `SOMETHING_SECRET=value` in .env / YAML / code.
 *
 * These carry the whole project's false-positive risk, so they are gated hard —
 * a meaningful key name, a minimum length, and an entropy floor. They are also
 * the first rules a user disables (`rules.disable: [generic-api-key]`), which
 * is a supported and reasonable thing to do.
 */

// Key names that actually imply a credential. Deliberately excludes `key` on
// its own — `primary_key`, `sort_key`, `key_name`, and `foreign_key` are not
// secrets and used to be the single biggest source of noise.
const SECRET_KEY_NAME = String.raw`(?:[a-z0-9_.-]*(?:api[_.-]?key|secret[_.-]?key|access[_.-]?key|private[_.-]?key|auth[_.-]?token|access[_.-]?token|refresh[_.-]?token|bearer[_.-]?token|client[_.-]?secret|app[_.-]?secret|api[_.-]?secret|secret|password|passwd|credential|token)[a-z0-9_.-]*)`;

export const genericRules: Rule[] = [
  {
    id: "generic-api-key",
    provider: "generic",
    description: "Generic credential assignment",
    regex: new RegExp(
      String.raw`\b${SECRET_KEY_NAME}\s*[:=]\s*["'` + "`" + String.raw`]([^\s"'` + "`" + String.raw`]{12,256})["'` + "`" + String.raw`]`,
      "gi",
    ),
    group: 1,
    entropyMin: 3.2,
    confidence: "medium",
  },
  {
    id: "generic-env-assignment",
    provider: "generic",
    // Unquoted .env shape: KEY=value to end of line. Requires SCREAMING_CASE,
    // which is what makes it specific enough to be worth having.
    description: "Credential in .env-style assignment",
    regex: new RegExp(
      String.raw`^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:API_KEY|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|APP_SECRET|API_SECRET|SECRET|PASSWORD|PASSWD|TOKEN|CREDENTIAL)[A-Z0-9_]*[ \t]*=[ \t]*["']?([^\s"'#]{12,256})["']?[ \t]*(?:#.*)?$`,
      "gim",
    ),
    group: 1,
    entropyMin: 3.0,
    confidence: "medium",
  },
  {
    id: "generic-yaml-assignment",
    provider: "generic",
    // YAML and TOML: `POSTGRES_PASSWORD: hunter2Kx9`, unquoted. The `[ \t]*`
    // rather than `\s*` matters — `\s` would cross a newline and pair a key
    // with the following line's value, which is how `secretKeyRef:` blocks get
    // misread as leaks.
    description: "Credential in an unquoted YAML/TOML assignment",
    regex: new RegExp(String.raw`\b${SECRET_KEY_NAME}[ \t]*[:=][ \t]*([^\s"'` + "`" + String.raw`#]{12,256})[ \t]*$`, "gim"),
    group: 1,
    entropyMin: 3.6,
    confidence: "medium",
    // Generated credentials essentially always mix digits with upper and lower
    // case. English stand-ins like `database-password` do not, and this is what
    // keeps the rule from firing on every Helm chart in existence.
    validate: (s) => /[0-9]/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s),
  },
  {
    id: "authorization-header",
    provider: "http",
    description: "Authorization header with a credential",
    regex: /authorization["'\s]*[:=]\s*["']?(?:bearer|token|basic)\s+([A-Za-z0-9_\-.=+/]{16,512})["']?/gi,
    prefilter: ["uthorization", "UTHORIZATION"],
    group: 1,
    entropyMin: 3.2,
    confidence: "medium",
  },
  {
    id: "curl-user-flag",
    provider: "http",
    description: "curl -u with an inline password",
    regex: /curl\s(?:[^\n]*?\s)?(?:-u|--user)[ =]["']?[^\s:"']{1,64}:([^\s"']{3,128})["']?/g,
    prefilter: ["curl"],
    group: 1,
    confidence: "high",
  },
  {
    id: "npmrc-auth-token",
    provider: "npm",
    description: ".npmrc auth token",
    regex: /\/\/[^\s/]+\/:_authToken\s*=\s*(\S{16,})/g,
    prefilter: ["_authToken"],
    group: 1,
    entropyMin: 3.0,
    confidence: "high",
  },
];
