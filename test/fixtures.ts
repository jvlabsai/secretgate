/**
 * Fake credentials for the test suite.
 *
 * Every value here is assembled from fragments at runtime rather than written
 * as a literal. The runtime strings are byte-identical to what the tests need;
 * the point is that no committed file contains a contiguous run of characters
 * matching a provider's pattern.
 *
 * This is not an attempt to sneak anything past a scanner. These are random
 * strings that were never issued by anyone. It is that a repository full of
 * literals shaped exactly like live keys is a repository that trips push
 * protection, sets off every downstream scanner its users run, and asks
 * everyone to click "allow" on two hundred warnings — which is precisely the
 * habit this whole project exists to argue against.
 *
 * Keep new test credentials in this file and split the provider prefix from
 * the body, as below.
 */

const j = (...parts: string[]) => parts.join("");

export const FAKE = {
  /** AWS access key ID. */
  awsKey: j("AKIA", "4KTNQ7VZL2WXMP3D"),
  /** Same shape, second value, for "two different secrets" tests. */
  awsKeyAlt: j("AKIA", "2E7RQMPX4LK9WNTZ"),
  /** Valid shape, no entropy — the placeholder suppressor should catch it. */
  awsKeyRedacted: j("AKIA", "X".repeat(16)),
  /** The key printed in the AWS documentation. Universally fake. */
  awsDocKey: j("AKIA", "IOSFODNN7", "EXAMPLE"),
  awsDocSecret: j("wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLE", "KEY"),

  /** GitHub personal access token, classic. */
  githubToken: j("ghp", "_", "9fK2mQ7xLp4RtY8vN3wZ6bH1jC5sD0aG4eU2"),

  /** Mailgun key. `key-` is its real prefix, which is why it needs splitting. */
  mailgunKey: j("key", "-", "0d06f997373a089e552dc76d83dbbc05"),

  /** Password inside a connection string. */
  dbPassword: "h4Kd9wQz2Lp8Nx7",
  dbUrl: j("postgres://svc_api:", "h4Kd9wQz2Lp8Nx7", "@db.internal:5432/orders"),

  /** High-entropy blob with no provider shape at all. */
  entropyBlob: "Xk9mQ2pL7vN4wR8tY3zB6cF1dG5hJ0sA",
} as const;

/** A structurally valid JWT, built rather than pasted. */
export function fakeJwt(): string {
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return [
    enc({ alg: "HS256", typ: "JWT" }),
    enc({ sub: "1234567890", name: "John Doe", iat: 1516239022 }),
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  ].join(".");
}

/** A PEM private key block, built rather than pasted. */
export function fakePem(): string {
  const body = [
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm",
  ].join("\n");
  const label = j("RSA", " ", "PRIVATE", " ", "KEY");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

/** A PEM *public* key block — must never be treated as a secret. */
export function fakePublicPem(): string {
  const label = j("PUBLIC", " ", "KEY");
  return `-----BEGIN ${label}-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1nQ2vRZ8xKlPqWmT9dYs\n-----END ${label}-----`;
}
