import type { Rule } from "../types.js";

function decodeBase64Url(part: string): string | null {
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    return Buffer.from(b64 + pad, "base64").toString("utf8");
  } catch {
    return null;
  }
}

/**
 * A three-segment base64url string is not automatically a JWT — plenty of
 * dotted identifiers have that shape. Requiring the payload to decode to a JSON
 * object is what keeps this rule out of the false-positive business.
 */
function isRealJwt(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [headerPart, payloadPart] = parts;
  if (!headerPart || !payloadPart) return false;

  const header = decodeBase64Url(headerPart);
  const payload = decodeBase64Url(payloadPart);
  if (!header || !payload) return false;

  try {
    const h = JSON.parse(header);
    const p = JSON.parse(payload);
    if (typeof h !== "object" || h === null || Array.isArray(h)) return false;
    if (typeof p !== "object" || p === null || Array.isArray(p)) return false;
    // A JWT without an alg is not a JWT.
    return typeof h.alg === "string";
  } catch {
    return false;
  }
}

export const keyRules: Rule[] = [
  {
    id: "private-key-block",
    provider: "pem",
    description: "Private key block",
    // PUBLIC KEY blocks deliberately do not match.
    regex:
      /-----BEGIN\s+((?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?:\s+BLOCK)?)-----[\s\S]{0,8000}?-----END\s+\1-----/g,
    prefilter: ["PRIVATE KEY"],
    group: 0,
    confidence: "high",
  },
  {
    id: "private-key-header-only",
    provider: "pem",
    // Catches a truncated paste, which still tells us a key was in play even
    // though the body never arrived.
    description: "Private key header (truncated block)",
    regex: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?:\s+BLOCK)?-----/g,
    prefilter: ["PRIVATE KEY"],
    group: 0,
    confidence: "high",
  },
  {
    id: "jwt",
    provider: "jwt",
    description: "JSON Web Token",
    regex: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g,
    prefilter: ["eyJ"],
    group: 1,
    confidence: "high",
    validate: isRealJwt,
  },
  {
    id: "ssh-authorized-key-with-private-material",
    provider: "ssh",
    description: "PuTTY private key file",
    regex: /PuTTY-User-Key-File-\d:\s*ssh-\w+[\s\S]{0,4000}?Private-Lines:/g,
    prefilter: ["PuTTY-User-Key-File"],
    group: 0,
    confidence: "high",
  },
];

export { isRealJwt };
