/**
 * Regenerates test/corpus/*.json.
 *
 * The generator is seeded, so re-running it produces a byte-identical corpus
 * and a reviewable diff. Its output is committed — the tests read the JSON, not
 * this file, so nobody has to trust the generator to trust the numbers.
 *
 * On circularity: the true positives here are *shapes* (real prefix, real
 * length, random body from the real alphabet), which is what an actual
 * credential is. They prove rules fire and that suppression does not eat live
 * keys. They do not prove precision — precision comes from the hand-written
 * negatives below, and that is the number CI gates on.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const CORPUS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "test", "corpus");

// mulberry32 — small, seeded, good enough to make fake keys look real.
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = rng(0x5ec0e7a7);

const ALPHA_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX = "0123456789abcdef";
const B64 = `${ALPHA_NUM}+/`;
const B64URL = `${ALPHA_NUM}_-`;
const UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

function body(n: number, alphabet = ALPHA_NUM): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

export interface TruePositive {
  id: string;
  provider: string;
  /** The credential on its own. */
  secret: string;
  /** The credential embedded in something a developer would actually paste. */
  text: string;
}

export interface Negative {
  id: string;
  why: string;
  text: string;
}

export interface MixedSample {
  id: string;
  text: string;
  /** Every secret that must be found. Anything else found is a false positive. */
  secrets: string[];
}

// --- true positives -------------------------------------------------------

const CONTEXTS: ((s: string, name: string) => string)[] = [
  (s, n) => `${n.toUpperCase()}=${s}`,
  (s, n) => `${n}: "${s}"`,
  (s, n) => `const ${n} = "${s}";`,
  (s, n) => `export ${n.toUpperCase()}="${s}"`,
  (s) => `Here's the key I'm using: ${s} — can you tell me why auth fails?`,
  (s, n) => `  ${n}: ${s}\n  region: us-east-1`,
  (s, n) => `${n.toUpperCase()}: ${s}  # rotate quarterly`,
  (s) => `curl -H "Authorization: Bearer ${s}" https://api.internal/v1/status`,
];

let ctxCursor = 0;
function embed(secret: string, name: string): string {
  const ctx = CONTEXTS[ctxCursor % CONTEXTS.length]!;
  ctxCursor++;
  return ctx(secret, name);
}

interface Generator {
  provider: string;
  name: string;
  count: number;
  make: () => string;
  /**
   * The generator already emits realistic surroundings (an assignment, a URI,
   * a connection string). Wrapping those in another context produces samples no
   * developer would ever paste, and scoring against nonsense teaches us nothing.
   */
  selfContained?: boolean;
}

const GENERATORS: Generator[] = [
  { provider: "aws", name: "aws_access_key_id", count: 6, make: () => `AKIA${body(16, UPPER_NUM)}` },
  { provider: "aws", name: "aws_access_key_id", count: 3, make: () => `ASIA${body(16, UPPER_NUM)}` },
  {
    provider: "aws",
    name: "aws_secret_access_key",
    count: 6,
    selfContained: true,
    make: () => `aws_secret_access_key = "${body(40, B64)}"`,
  },
  { provider: "github", name: "github_token", count: 6, make: () => `ghp_${body(36)}` },
  { provider: "github", name: "github_token", count: 3, make: () => `gho_${body(36)}` },
  { provider: "github", name: "github_token", count: 3, make: () => `ghs_${body(36)}` },
  { provider: "github", name: "github_pat", count: 5, make: () => `github_pat_${body(22)}_${body(59)}` },
  { provider: "gitlab", name: "gitlab_token", count: 4, make: () => `glpat-${body(20, B64URL)}` },
  { provider: "anthropic", name: "anthropic_api_key", count: 6, make: () => `sk-ant-api03-${body(95, B64URL)}` },
  { provider: "openai", name: "openai_api_key", count: 6, make: () => `sk-${body(48)}` },
  { provider: "openai", name: "openai_api_key", count: 4, make: () => `sk-proj-${body(64, B64URL)}` },
  { provider: "openrouter", name: "openrouter_key", count: 3, make: () => `sk-or-v1-${body(64, HEX)}` },
  { provider: "google", name: "google_api_key", count: 5, make: () => `AIza${body(35, B64URL)}` },
  { provider: "google", name: "google_oauth_secret", count: 3, make: () => `GOCSPX-${body(28, B64URL)}` },
  { provider: "stripe", name: "stripe_secret_key", count: 5, make: () => `sk_live_${body(24)}` },
  { provider: "stripe", name: "stripe_restricted_key", count: 3, make: () => `rk_live_${body(24)}` },
  {
    provider: "slack",
    name: "slack_bot_token",
    count: 5,
    make: () => `xoxb-${body(12, "0123456789")}-${body(12, "0123456789")}-${body(24)}`,
  },
  {
    provider: "slack",
    name: "slack_webhook",
    count: 3,
    make: () => `https://hooks.slack.com/services/T${body(10, UPPER_NUM)}/B${body(10, UPPER_NUM)}/${body(24)}`,
  },
  { provider: "sendgrid", name: "sendgrid_api_key", count: 4, make: () => `SG.${body(22, B64URL)}.${body(43, B64URL)}` },
  { provider: "npm", name: "npm_token", count: 4, make: () => `npm_${body(36)}` },
  { provider: "huggingface", name: "hf_token", count: 3, make: () => `hf_${body(34)}` },
  { provider: "groq", name: "groq_api_key", count: 3, make: () => `gsk_${body(52)}` },
  { provider: "replicate", name: "replicate_token", count: 3, make: () => `r8_${body(37)}` },
  { provider: "shopify", name: "shopify_token", count: 3, make: () => `shpat_${body(32, HEX)}` },
  { provider: "square", name: "square_token", count: 3, make: () => `sq0atp-${body(22, B64URL)}` },
  { provider: "digitalocean", name: "do_token", count: 3, make: () => `dop_v1_${body(64, HEX)}` },
  { provider: "supabase", name: "supabase_key", count: 3, make: () => `sbp_${body(40, HEX)}` },
  { provider: "newrelic", name: "newrelic_key", count: 2, make: () => `NRAK-${body(27, UPPER_NUM)}` },
  { provider: "telegram", name: "telegram_bot_token", count: 3, make: () => `${body(10, "123456789")}:AA${body(33, B64URL)}` },
  { provider: "mailgun", name: "mailgun_api_key", count: 3, make: () => `key-${body(32, HEX)}` },
  {
    provider: "database",
    name: "database_url",
    count: 5,
    selfContained: true,
    make: () => `postgres://svc_${body(6, "abcdefghijklmnopqrstuvwxyz")}:${body(20, B64URL)}@db-prod.internal:5432/app`,
  },
  {
    provider: "mongodb",
    name: "mongo_uri",
    count: 3,
    selfContained: true,
    make: () => `mongodb+srv://appuser:${body(24, B64URL)}@cluster0.ab1cd.mongodb.net/prod`,
  },
  {
    provider: "azure",
    name: "azure_storage",
    count: 3,
    selfContained: true,
    make: () =>
      `DefaultEndpointsProtocol=https;AccountName=prodblob;AccountKey=${body(86, B64)}==;EndpointSuffix=core.windows.net`,
  },
  {
    provider: "datadog",
    name: "datadog_api_key",
    count: 2,
    selfContained: true,
    make: () => `dd_api_key: "${body(32, HEX)}"`,
  },
];

function makeJwt(): string {
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const header = enc({ alg: "HS256", typ: "JWT" });
  const payload = enc({
    sub: body(12, "0123456789"),
    name: "svc-billing",
    iat: 1767225600,
    exp: 1798761600,
    scope: "read:invoices write:invoices",
  });
  return `${header}.${payload}.${body(43, B64URL)}`;
}

function makePem(): string {
  const lines: string[] = [];
  for (let i = 0; i < 8; i++) lines.push(body(64, B64));
  return `-----BEGIN RSA PRIVATE KEY-----\n${lines.join("\n")}\n-----END RSA PRIVATE KEY-----`; // secretgate:allow
}

function buildTruePositives(): TruePositive[] {
  const out: TruePositive[] = [];
  let n = 0;

  for (const gen of GENERATORS) {
    for (let i = 0; i < gen.count; i++) {
      const raw = gen.make();
      const text = gen.selfContained ? raw : embed(raw, gen.name);
      const secret = gen.selfContained ? extractSecret(raw) : raw;
      out.push({ id: `tp-${String(++n).padStart(3, "0")}-${gen.provider}`, provider: gen.provider, secret, text });
    }
  }

  for (let i = 0; i < 5; i++) {
    const jwt = makeJwt();
    out.push({
      id: `tp-${String(++n).padStart(3, "0")}-jwt`,
      provider: "jwt",
      secret: jwt,
      text: `Authorization: Bearer ${jwt}`,
    });
  }

  for (let i = 0; i < 4; i++) {
    const pem = makePem();
    out.push({
      id: `tp-${String(++n).padStart(3, "0")}-pem`,
      provider: "pem",
      secret: pem,
      text: `Here is the deploy key that stopped working:\n${pem}\n`,
    });
  }

  return out;
}

/** For generators that emit their own assignment, the secret is the quoted part. */
function extractSecret(raw: string): string {
  const quoted = raw.match(/["']([^"']{12,})["']/);
  if (quoted?.[1]) return quoted[1];
  const uri = raw.match(/:\/\/[^:@\s]+:([^@\s]+)@/);
  if (uri?.[1]) return uri[1];
  const accountKey = raw.match(/AccountKey=([A-Za-z0-9+/]+={0,2})/);
  if (accountKey?.[1]) return accountKey[1];
  return raw;
}

// --- hard negatives -------------------------------------------------------
// Hand-written. This is the half that decides precision, and precision is the
// number that decides whether anyone keeps the tool installed.

const NEGATIVES: Negative[] = [
  { id: "neg-sha-1", why: "git commit SHA", text: "commit 9f2a4c1b8e7d3f5a6c0b2e4d8f1a3c5b7e9d0f2a" },
  { id: "neg-sha-2", why: "git short SHA in log", text: "* 4b7f2ad (HEAD -> main) fix: retry on 503" },
  { id: "neg-sha-3", why: "tree hash in git cat-file", text: "tree 8a9c1f0e2b3d4a5f6c7b8e9d0a1b2c3d4e5f6a7b" },
  { id: "neg-uuid-1", why: "UUID v4", text: "request_id: 550e8400-e29b-41d4-a716-446655440000" },
  { id: "neg-uuid-2", why: "UUID in JSON", text: '{"traceId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}' },
  { id: "neg-uuid-3", why: "list of UUIDs", text: "ids = [6ba7b810-9dad-11d1-80b4-00c04fd430c8, 6ba7b811-9dad-11d1-80b4-00c04fd430c8]" },
  { id: "neg-docker-1", why: "docker image digest", text: "image: nginx@sha256:2c930d010525941c1d56ec53b97bd057a67ae1865eebf042686d2a2d18271ced" },
  { id: "neg-docker-2", why: "docker layer id", text: "Pulling fs layer 7d63c13d9b9b6ec5f05a1f38f9dcd52a0b1c0dfa3a6a4b1a9c8d7e6f5a4b3c2d" },
  { id: "neg-lock-1", why: "npm lockfile integrity hash", text: '"integrity": "sha512-K2SGXmwGrHcvhLCTGAAFYr4vFLRFqOEBqbxGSJfhBFPFDvJfWLBGl9pnDvBRfL8YCDrHYLBBEAHTVEuFdiN8Xw=="' },
  { id: "neg-lock-2", why: "yarn lockfile resolved hash", text: "resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c\"" },
  { id: "neg-lock-3", why: "cargo checksum", text: 'checksum = "d75a2a4b1b190afb6f5425f10f6a8f959d2ea0b9c2b1d79fe0c0e01c1e19b6c3"' },
  { id: "neg-b64-img", why: "base64 png data URI", text: 'src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="' },
  { id: "neg-minified", why: "minified JS", text: "!function(e,t){\"object\"==typeof exports&&\"undefined\"!=typeof module?t(exports):\"function\"==typeof define&&define.amd?define([\"exports\"],t):t(e.dayjs={})}(this,function(e){\"use strict\"" },
  { id: "neg-tailwind", why: "tailwind class string", text: 'className="flex min-h-screen flex-col items-center justify-between p-24 text-sm lg:flex md:w-auto xl:grid-cols-3"' },
  { id: "neg-css-hex", why: "array of hex colours", text: "const palette = ['#1a2b3c', '#4d5e6f', '#7a8b9c', '#adbecf', '#d0e1f2', '#ff6b35', '#004e89'];" },
  { id: "neg-pubkey", why: "ssh public key, not private", text: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA9K1lXQKGVWjTMxNzYwODk deploy@ci" },
  { id: "neg-pubkey-pem", why: "PEM public key block", text: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1nQ2vRZ8xKlPqWmT9dYs\n-----END PUBLIC KEY-----" },
  { id: "neg-cert", why: "x509 certificate block", text: "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n-----END CERTIFICATE-----" },
  { id: "neg-jwt-header", why: "JWT header segment alone, no payload", text: "The header decodes to eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" },
  { id: "neg-jwt-garbage", why: "three dotted base64 segments that are not a JWT", text: "cache key: eyJhbGciXXXX.eyJzdWIiYWJj.notarealsignature1234" },
  { id: "neg-env-placeholder-1", why: "env template", text: "OPENAI_API_KEY=your-api-key-here" },
  { id: "neg-env-placeholder-2", why: "env template with brackets", text: "STRIPE_SECRET_KEY=<your_stripe_secret_key>" },
  { id: "neg-env-placeholder-3", why: "env template with shell var", text: "DATABASE_URL=postgres://user:${DB_PASSWORD}@localhost:5432/dev" },
  { id: "neg-env-placeholder-4", why: "redacted value", text: "AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
  { id: "neg-env-placeholder-5", why: "changeme", text: "ADMIN_PASSWORD=changeme" },
  { id: "neg-conn-nopass", why: "connection string with no password", text: "DATABASE_URL=postgres://localhost:5432/myapp_development" },
  { id: "neg-conn-nopass-2", why: "redis url, no credentials", text: "REDIS_URL=redis://127.0.0.1:6379/0" },
  { id: "neg-akia-doc", why: "AWS docs placeholder key", text: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" },
  { id: "neg-aws-doc-secret", why: "AWS docs placeholder secret", text: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
  { id: "neg-semver", why: "long version list", text: "versions: 1.0.0, 1.0.1, 1.2.0-beta.4, 2.0.0-rc.1, 2.0.0, 2.1.3, 3.0.0-alpha.12" },
  { id: "neg-i18n", why: "i18n blob", text: '{"welcome_message_long":"Willkommen bei unserem Dienst, bitte melden Sie sich an um fortzufahren"}' },
  { id: "neg-css-class-hash", why: "css-modules generated class", text: ".Button_primary__3xK9d { background: var(--brand); }" },
  { id: "neg-webpack-chunk", why: "webpack chunk filename", text: "static/chunks/pages/index-8f2a91c4b7e3d5a6.js" },
  { id: "neg-nextjs-buildid", why: "next.js build id", text: '"buildId": "kR3nP9wQzL2mX7vB4tYc"' },
  { id: "neg-etag", why: "http etag", text: 'ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"' },
  { id: "neg-content-hash", why: "subresource integrity", text: '<script src="/app.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script>' },
  { id: "neg-mac", why: "mac addresses", text: "arp: 00:1b:44:11:3a:b7 aa:bb:cc:dd:ee:ff 3c:22:fb:9a:1d:5e" },
  { id: "neg-ipv6", why: "ipv6 addresses", text: "listen [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443 ssl;" },
  { id: "neg-hex-colors-long", why: "long hex run that is graphics data", text: "vertices: 0xff00ff00 0x00ff00ff 0xdeadbeef 0xcafebabe 0xfeedface 0x8badf00d" },
  { id: "neg-timestamp-ids", why: "snowflake ids", text: "message_ids = [1234567890123456789, 1234567890123456790, 1234567890123456791]" },
  { id: "neg-base32", why: "base32 otp secret label, no value", text: "otpauth://totp/Example:alice@example.com?issuer=Example&algorithm=SHA1&digits=6" },
  { id: "neg-license-key-fake", why: "obvious dummy licence", text: "LICENSE_KEY=AAAA-BBBB-CCCC-DDDD-EEEE" },
  { id: "neg-import-hash", why: "go module sum", text: "github.com/spf13/cobra v1.8.0 h1:e5/vxKd/rZsfSJMUX1agtjeTDf+qv1/JdBF8gg5k9ZM=" },
  { id: "neg-terraform-var", why: "terraform variable reference", text: 'password = var.db_password  # set via TF_VAR_db_password' },
  { id: "neg-k8s-secretref", why: "kubernetes secretKeyRef, not a value", text: "valueFrom:\n  secretKeyRef:\n    name: db-credentials\n    key: password" },
  { id: "neg-gh-actions-secret", why: "github actions expression", text: "env:\n  API_KEY: ${{ secrets.API_KEY }}" },
  { id: "neg-doc-prose", why: "documentation prose about keys", text: "Set your API key in the environment before running the server. Never commit it." },
  { id: "neg-sql", why: "sql with column named password", text: "SELECT id, email, password_hash FROM users WHERE last_login > NOW() - INTERVAL '30 days';" },
  { id: "neg-bcrypt", why: "bcrypt hash in a fixture dump", text: "password_hash: $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.4bK6" },
  { id: "neg-argon", why: "argon2 hash", text: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG" },
  { id: "neg-uuid-list-long", why: "many uuids in a csv", text: "a1b2c3d4-e5f6-7890-abcd-ef1234567890,b2c3d4e5-f6a7-8901-bcde-f23456789012,c3d4e5f6-a7b8-9012-cdef-345678901234" },
  { id: "neg-long-path", why: "long filesystem path", text: "/Users/dev/Library/Caches/com.apple.dt.Xcode/DerivedData/App-fkjhsdfkjhsdfkjhsdf/Build/Products" },
  { id: "neg-useragent", why: "user agent string", text: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
  { id: "neg-jwt-alg-none", why: "not a jwt, random dotted tokens", text: "metric.path.identifier.aggregate.p99.by.region.us-east-1.service.checkout" },
  { id: "neg-graphql", why: "graphql persisted query hash", text: '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"c8f9d1e2b3a4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8"}}}' },
  { id: "neg-sentry-dsn-public", why: "sentry public dsn, safe by design", text: "SENTRY_DSN=https://a1b2c3d4e5f6@o123456.ingest.sentry.io/7654321" },
  { id: "neg-css-font", why: "font subset hash", text: "@font-face{src:url(/fonts/inter-latin-a1b2c3d4e5f6a7b8.woff2) format('woff2')}" },
  { id: "neg-hexdump", why: "hexdump output", text: "00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|" },
  { id: "neg-color-tokens", why: "design tokens", text: "--color-primary-500: #0ea5e9; --color-primary-600: #0284c7; --color-primary-700: #0369a1;" },
  { id: "neg-morse", why: "long repeated punctuation", text: "======================================================================" },
  { id: "neg-lorem", why: "lorem ipsum", text: "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore." },
  { id: "neg-stacktrace", why: "java stack trace", text: "at com.example.service.OrderProcessor.validate(OrderProcessor.java:142)\n\tat com.example.web.OrderController.post(OrderController.java:88)" },
  { id: "neg-npm-pkg", why: "package names", text: "dependencies: react@18.3.1 react-dom@18.3.1 @tanstack/react-query@5.59.0 zod@3.23.8" },
  { id: "neg-crontab", why: "crontab", text: "0 */6 * * * /usr/local/bin/backup.sh --target s3://backups-prod --retain 30" },
  { id: "neg-http-log", why: "nginx access log", text: '10.0.1.42 - - [22/Jul/2026:14:03:11 +0000] "GET /api/v1/orders?limit=50 HTTP/1.1" 200 8241' },
  { id: "neg-openapi", why: "openapi security scheme declaration", text: "securitySchemes:\n  bearerAuth:\n    type: http\n    scheme: bearer\n    bearerFormat: JWT" },
  { id: "neg-test-fixture-key", why: "clearly-labelled fake in prose", text: "In the docs we use the fake key sk-test-not-a-real-key so readers can copy it." },
  { id: "neg-b64-text", why: "base64 of ordinary text", text: "echo 'aGVsbG8gd29ybGQgdGhpcyBpcyBqdXN0IHNvbWUgcGxhaW4gdGV4dCBlbmNvZGVk' | base64 -d" },
  { id: "neg-git-diff", why: "diff header", text: "index 83db48f..bf269f4 100644\n--- a/src/index.ts\n+++ b/src/index.ts" },
  { id: "neg-aws-arn", why: "aws arn, not a credential", text: "arn:aws:iam::123456789012:role/service-role/lambda-execution-role" },
  { id: "neg-aws-bucket", why: "s3 bucket path", text: "s3://prod-assets-eu-west-1/uploads/2026/07/22/a1b2c3d4e5f6.jpg" },
  { id: "neg-k8s-name", why: "kubernetes pod name with hash", text: "pod/checkout-api-7d9f8b6c5d-x2k9p   1/1   Running   0   4d2h" },
  { id: "neg-prometheus", why: "prometheus metric line", text: 'http_request_duration_seconds_bucket{le="0.25",method="GET",route="/api/orders"} 48291' },
  { id: "neg-uuid-urn", why: "urn uuid", text: "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6" },
  { id: "neg-hash-list", why: "list of md5 hashes", text: "d41d8cd98f00b204e9800998ecf8427e  empty.txt\n5eb63bbbe01eeed093cb22bb8f5acdc3  hello.txt" },
  { id: "neg-tsconfig", why: "tsconfig json", text: '{"compilerOptions":{"target":"ES2023","moduleResolution":"bundler","strict":true}}' },
  { id: "neg-svg-path", why: "svg path data", text: '<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor"/>' },
  { id: "neg-regex", why: "a regex literal", text: "const RE = /^[A-Za-z0-9+/]{40,}={0,2}$/;" },
  { id: "neg-uuid-mixed-case", why: "mixed case uuid", text: "Correlation-Id: 3F2504E0-4F89-11D3-9A0C-0305E82C3301" },
  { id: "neg-jwt-in-docs", why: "prose describing a jwt without one", text: "The response includes a JWT in the Authorization header; decode it at jwt.io to inspect claims." },
  { id: "neg-encoded-url", why: "url-encoded query string", text: "?redirect=https%3A%2F%2Fapp.example.com%2Fdashboard%3Ftab%3Dbilling%26period%3D30d" },
  { id: "neg-flag-list", why: "compiler flags", text: "-O2 -fno-strict-aliasing -Wall -Wextra -Wno-unused-parameter -fstack-protector-strong" },
  { id: "neg-hex-uuid-nodash", why: "uuid without dashes", text: "session=550e8400e29b41d4a716446655440000" },
  { id: "neg-numeric-run", why: "long numeric id", text: "order_number: 90210847362519374650" },
  { id: "neg-emoji-blob", why: "unicode blob", text: "reactions: 🎉🚀✅💡🔥📦🧪🛠️🎯📈🙌👀💬🧵📌" },
  { id: "neg-ascii-art", why: "ascii art banner", text: "  ___  ___  ___ _ __ ___| |_ __ _  __ _| |_ ___ " },
  { id: "neg-csv-header", why: "csv header row", text: "id,created_at,customer_email,total_cents,currency,status,payment_intent_id" },
  { id: "neg-md5-in-name", why: "cache filename", text: ".cache/babel-loader/9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d.json" },
  { id: "neg-proto", why: "protobuf definition", text: "message Order { string id = 1; int64 total_cents = 2; string currency = 3; }" },
  { id: "neg-yaml-anchor", why: "yaml anchors", text: "defaults: &defaults\n  adapter: postgresql\n  encoding: unicode\n  pool: 5" },
  { id: "neg-make", why: "makefile target", text: "build: ## Build the binary\n\t@go build -ldflags=\"-s -w\" -o bin/app ./cmd/app" },
  { id: "neg-uuid-in-url", why: "uuid in a url path", text: "GET /v1/workspaces/8f14e45f-ceea-467a-9f52-1c2d3e4f5a6b/members" },
  { id: "neg-nanoid", why: "short nanoid, below length floor", text: "shortId: V1StGXR8_Z5j" },
  { id: "neg-otel-traceid", why: "opentelemetry trace id", text: "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" },
  { id: "neg-sri-css", why: "css sourcemap comment", text: "/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbXX0= */" },
  { id: "neg-locale-keys", why: "long translation key list", text: "checkout.payment.errors.card_declined.title, checkout.payment.errors.insufficient_funds.body" },
  { id: "neg-comment-todo", why: "todo comment", text: "// TODO: rotate the signing key before the next release cycle" },
  { id: "neg-hex-seed", why: "labelled random test seed", text: "const TEST_SEED = 0xdeadbeefcafebabe;" },
  { id: "neg-uuid-v7", why: "uuid v7", text: "018f6c1a-9b2e-7c3d-8e4f-5a6b7c8d9e0f" },
  { id: "neg-ulid", why: "ulid", text: "01ARZ3NDEKTSV4RRFFQ69G5FAV" },
  { id: "neg-badge-url", why: "shields.io badge url", text: "![build](https://img.shields.io/github/actions/workflow/status/jvlabs/secretgate/ci.yml?branch=main)" },
  { id: "neg-license-spdx", why: "spdx identifier", text: "SPDX-License-Identifier: Apache-2.0" },
  { id: "neg-jsdoc", why: "jsdoc block", text: "/**\n * @param {string} apiKey - the caller's API key, read from the environment\n * @returns {Promise<Response>}\n */" },
  { id: "neg-import-map", why: "import map", text: '{"imports":{"react":"https://esm.sh/react@18.3.1","zod":"https://esm.sh/zod@3.23.8"}}' },
  { id: "neg-pkg-lock-name", why: "lockfile package path", text: '"node_modules/@babel/plugin-transform-react-jsx-development": {' },
  { id: "neg-git-blame", why: "git blame line", text: "8f2a91c4 (Ada Lovelace 2026-03-14 09:22:01 +0000 142) return client.send(req);" },
  { id: "neg-hex-in-prose", why: "hex mentioned in prose", text: "The magic bytes are 89 50 4e 47 0d 0a 1a 0a for a PNG file." },
  { id: "neg-terraform-plan", why: "terraform plan output, values hidden", text: '  ~ secret_string = (sensitive value)\n  ~ version_id    = "3" -> (known after apply)' },
  { id: "neg-helm", why: "helm values reference", text: "existingSecret: app-credentials\nexistingSecretKey: database-password" },
  { id: "neg-dotenv-comment", why: "commented-out env line", text: "# OPENAI_API_KEY=sk-replace-this-with-your-own-key" },
  { id: "neg-sample-file", why: "env sample with empty values", text: "DATABASE_URL=\nREDIS_URL=\nSTRIPE_SECRET_KEY=\nSENTRY_DSN=" },
  { id: "neg-swagger-example", why: "swagger example value", text: "example: Bearer eyJhbGciOiJIUzI1NiJ9.PLACEHOLDER.PLACEHOLDER" },
  { id: "neg-uuid-braced", why: "braced guid, windows style", text: "{6F9619FF-8B86-D011-B42D-00CF4FC964FF}" },
  { id: "neg-checksum-file", why: "sha256sums file", text: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  secretgate-linux-amd64" },
  { id: "neg-pip-hash", why: "pip requirements hash", text: "requests==2.32.3 --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6" },
  { id: "neg-jwt-expired-note", why: "prose about a token", text: "The refresh token expires after 30 days; store it in the OS keychain, not in the repo." },
  { id: "neg-b64-json", why: "base64 of a small json config", text: "eyJlbmFibGVkIjp0cnVlLCJyZWdpb24iOiJ1cy1lYXN0LTEifQ==" },
  { id: "neg-color-name-list", why: "list of css named colours", text: "cornflowerblue, mediumseagreen, palevioletred, darkslategray, lightgoldenrodyellow" },
];

// --- mixed realistic prompts ---------------------------------------------

function buildMixed(): MixedSample[] {
  const out: MixedSample[] = [];
  let n = 0;
  const add = (text: string, secrets: string[]) =>
    out.push({ id: `mix-${String(++n).padStart(3, "0")}`, text, secrets });

  const awsKey = `AKIA${body(16, UPPER_NUM)}`;
  const awsSecret = body(40, B64);
  const ghToken = `ghp_${body(36)}`;
  const openaiKey = `sk-${body(48)}`;
  const stripeKey = `sk_live_${body(24)}`;
  const dbPass = body(20, B64URL);
  const slackToken = `xoxb-${body(12, "0123456789")}-${body(12, "0123456789")}-${body(24)}`;
  const sendgrid = `SG.${body(22, B64URL)}.${body(43, B64URL)}`;

  add(
    `I'm getting a 403 from S3. Here's my config:\n\n[default]\naws_access_key_id = ${awsKey}\naws_secret_access_key = ${awsSecret}\nregion = eu-west-2\n\nAnd the error:\nAn error occurred (AccessDenied) when calling the PutObject operation`,
    [awsKey, awsSecret],
  );

  add(
    `Can you review this GitHub Action?\n\nname: deploy\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci && npm run build\n        env:\n          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}\n          NODE_ENV: production`,
    [],
  );

  add(
    `Here's my .env.example, does it look complete?\n\nDATABASE_URL=postgres://user:password@localhost:5432/dev\nREDIS_URL=redis://localhost:6379\nOPENAI_API_KEY=sk-your-key-here\nSENTRY_DSN=`,
    [],
  );

  add(
    `The webhook keeps failing. My handler:\n\nconst stripe = require('stripe')('${stripeKey}');\napp.post('/webhook', (req, res) => {\n  const sig = req.headers['stripe-signature'];\n  ...\n});`,
    [stripeKey],
  );

  add(
    `docker-compose.yml — is the healthcheck right?\n\nservices:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: ${dbPass}\n      POSTGRES_DB: app\n    healthcheck:\n      test: ["CMD-SHELL", "pg_isready -U postgres"]\n      interval: 10s`,
    [dbPass],
  );

  add(
    `Terraform plan output — why is it replacing the instance?\n\n  # aws_instance.web must be replaced\n-/+ resource "aws_instance" "web" {\n      ~ ami           = "ami-0c55b159cbfafe1f0" -> "ami-0aa7d40eeae50c9a9" # forces replacement\n      ~ id            = "i-0abcd1234efgh5678" -> (known after apply)\n        instance_type = "t3.medium"\n    }`,
    [],
  );

  add(
    `Stack trace from prod:\n\nOSError: [Errno 13] Permission denied: '/var/lib/app/cache'\n  File "/app/src/storage.py", line 88, in _ensure_dir\n    os.makedirs(path, exist_ok=True)\n  File "/usr/lib/python3.12/os.py", line 225, in makedirs\n    mkdir(name, mode)`,
    [],
  );

  add(
    `Migrating our Slack bot. Current token is ${slackToken} and it needs chat:write plus channels:history. What scopes am I missing for threads?`,
    [slackToken],
  );

  add(
    `CI log:\n\n$ npm ci\nnpm warn deprecated inflight@1.0.6: This module is not supported\nadded 1284 packages, and audited 1285 packages in 23s\n$ npm test\n> vitest run\n Test Files  42 passed (42)\n      Tests  318 passed (318)`,
    [],
  );

  add(
    `Trying to send email. This returns 401:\n\ncurl -X POST https://api.sendgrid.com/v3/mail/send \\\n  -H "Authorization: Bearer ${sendgrid}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"personalizations":[{"to":[{"email":"a@example.com"}]}]}'`,
    [sendgrid],
  );

  add(
    `Review this Dockerfile for size:\n\nFROM node:20-alpine AS build\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY . .\nRUN npm run build\n\nFROM gcr.io/distroless/nodejs20\nCOPY --from=build /app/dist /app/dist\nCMD ["/app/dist/index.js"]`,
    [],
  );

  add(
    `My git history has a problem:\n\n$ git log --oneline -5\n8f2a91c fix: handle null customer on refund\n4b7f2ad feat: add idempotency keys\nc0d3e1f chore: bump deps\n1a2b3c4 refactor: extract billing client\n9e8d7c6 test: cover partial refunds`,
    [],
  );

  add(
    `Deploying with this token: ${ghToken}\n\ngh release create v1.4.0 --generate-notes\n\nBut it says "Resource not accessible by personal access token". Which scope?`,
    [ghToken],
  );

  add(
    `Here's the OpenAPI spec fragment:\n\ncomponents:\n  securitySchemes:\n    ApiKeyAuth:\n      type: apiKey\n      in: header\n      name: X-API-Key\nsecurity:\n  - ApiKeyAuth: []`,
    [],
  );

  add(
    `Why does this test fail?\n\ntest('formats currency', () => {\n  expect(format(1999, 'USD')).toBe('$19.99');\n  expect(format(1999, 'EUR')).toBe('€19.99');\n});\n\nGot: '$19.99' vs '€19.99' — the EUR case returns '$19.99'.`,
    [],
  );

  add(
    `Full app config, sanity check please:\n\nmodule.exports = {\n  openai: { apiKey: '${openaiKey}', model: 'gpt-4o' },\n  db: { url: 'postgres://app:${dbPass}@db.internal:5432/prod' },\n  logLevel: 'info',\n};`,
    [openaiKey, dbPass],
  );

  add(
    `kubectl output:\n\nNAME                             READY   STATUS    RESTARTS   AGE\ncheckout-api-7d9f8b6c5d-x2k9p    1/1     Running   0          4d2h\ncheckout-api-7d9f8b6c5d-m4n8q    1/1     Running   2          4d2h\nredis-0                          1/1     Running   0          12d`,
    [],
  );

  add(
    `Package.json audit:\n\n{\n  "name": "billing-service",\n  "version": "2.4.1",\n  "dependencies": {\n    "stripe": "^17.3.0",\n    "fastify": "^5.1.0",\n    "pino": "^9.5.0"\n  }\n}`,
    [],
  );

  add(
    `Nginx config review:\n\nserver {\n  listen 443 ssl http2;\n  server_name api.example.com;\n  ssl_certificate     /etc/letsencrypt/live/api.example.com/fullchain.pem;\n  ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;\n  location / { proxy_pass http://127.0.0.1:3000; }\n}`,
    [],
  );

  add(
    `Got this from a colleague over Slack, is it safe to commit?\n\nexport AWS_ACCESS_KEY_ID=${awsKey}\nexport AWS_SECRET_ACCESS_KEY=${awsSecret}\nexport AWS_DEFAULT_REGION=us-east-1`,
    [awsKey, awsSecret],
  );

  // Pad out to 60 with alternating clean/dirty variations so the mixed set is
  // not dominated by either class.
  const fillers: [string, string[]][] = [
    [`README badge row:\n\n![ci](https://img.shields.io/badge/ci-passing-brightgreen)\n![license](https://img.shields.io/badge/license-Apache--2.0-blue)`, []],
    [`Prisma schema:\n\nmodel User {\n  id        String   @id @default(cuid())\n  email     String   @unique\n  createdAt DateTime @default(now())\n}`, []],
    [`SQL migration:\n\nALTER TABLE orders ADD COLUMN idempotency_key text;\nCREATE UNIQUE INDEX CONCURRENTLY orders_idem_idx ON orders (idempotency_key);`, []],
    [`Why is my regex slow?\n\n/^(a+)+$/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaX')`, []],
    [`Rust error:\n\nerror[E0502]: cannot borrow \`v\` as mutable because it is also borrowed as immutable\n  --> src/main.rs:8:5`, []],
    [`Go module list:\n\ngithub.com/gin-gonic/gin v1.10.0\ngithub.com/stretchr/testify v1.9.0\ngolang.org/x/sync v0.8.0`, []],
    [`tsconfig question — why isn't strictNullChecks catching this?\n\nfunction f(x?: string) { return x.length; }`, []],
    [`GraphQL query:\n\nquery Orders($first: Int!) {\n  orders(first: $first) { edges { node { id total status } } }\n}`, []],
    [`Webpack bundle report: main.8f2a91c4b7e3d5a6.js is 412 KB gzipped. Biggest chunk is moment locales.`, []],
    [`CSS question:\n\n.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 1rem; }`, []],
  ];
  for (const [text, secrets] of fillers) add(text, secrets);

  // A second pass of credential-bearing prompts, different shapes.
  const moreKeys = [
    `hf_${body(34)}`,
    `npm_${body(36)}`,
    `glpat-${body(20, B64URL)}`,
    `AIza${body(35, B64URL)}`,
    `dop_v1_${body(64, HEX)}`,
    `gsk_${body(52)}`,
    `shpat_${body(32, HEX)}`,
    `sbp_${body(40, HEX)}`,
    `r8_${body(37)}`,
    `key-${body(32, HEX)}`,
  ];
  const templates = [
    (k: string) => `Getting 401 on model download. Token: ${k}\n\nfrom transformers import AutoModel\nmodel = AutoModel.from_pretrained("meta-llama/Llama-3-8B")`,
    (k: string) => `.npmrc has:\n//registry.npmjs.org/:_authToken=${k}\n\nStill getting E401 on publish. Scoped package, public access.`,
    (k: string) => `CI can't clone the submodule. Using ${k} as CI_JOB_TOKEN replacement — is that the right variable?`,
    (k: string) => `Maps API returns REQUEST_DENIED.\n\nconst loader = new Loader({ apiKey: '${k}', version: 'weekly' });`,
    (k: string) => `Terraform provider config:\n\nprovider "digitalocean" {\n  token = "${k}"\n}`,
    (k: string) => `Streaming completions time out after 30s:\n\nconst groq = new Groq({ apiKey: '${k}' });`,
    (k: string) => `Shopify admin API returns 403 on products/write.\n\nX-Shopify-Access-Token: ${k}`,
    (k: string) => `Supabase RLS is blocking inserts even with the service key:\n\nSUPABASE_SERVICE_KEY=${k}`,
    (k: string) => `Replicate prediction stuck in "starting":\n\nreplicate.run("owner/model", { input: {...} })  // REPLICATE_API_TOKEN=${k}`,
    (k: string) => `Mailgun bounces everything:\n\ncurl -s --user 'api:${k}' https://api.mailgun.net/v3/mg.example.com/messages`,
  ];
  moreKeys.forEach((k, i) => add(templates[i]!(k), [k]));

  const moreClean: string[] = [
    `How do I make this idempotent?\n\nawait db.insert(orders).values(row).onConflictDoNothing();`,
    `Explain the difference between a debounce and a throttle, with a React example.`,
    `Our p99 latency jumped from 120ms to 900ms after the last deploy. Where would you look first?`,
    `Is it safe to run ALTER TABLE ... SET NOT NULL on a 40M row Postgres table in production?`,
    `Review this error handling:\n\ntry { await send(); } catch (e) { logger.error({ e }, 'send failed'); throw e; }`,
    `What's the cleanest way to type a discriminated union for these three webhook events?`,
    `Our Docker build takes 9 minutes. Layers: deps install 4m, build 3m, tests 2m. Ideas?`,
    `Should I use a queue or a cron for sending 50k emails per day?`,
    `Explain why this useEffect runs twice in development but once in production.`,
    `Best practice for rotating credentials without downtime in a 6-node cluster?`,
    `git rebase vs merge for a team of four — what would you standardise on?`,
    `How do I test code that reads from process.env without leaking state between tests?`,
    `Convert this callback-based API to async/await:\n\nfs.readFile(p, (err, buf) => { ... })`,
    `Postgres: when is a partial index better than a filtered query?`,
    `What does "cache-control: private, max-age=0, must-revalidate" actually do?`,
    `Our bundle grew 200KB after adding date-fns. How do I tree-shake it properly?`,
    `Design a retry policy for a payment API that is not idempotent.`,
    `Why would a Kubernetes pod be OOMKilled at 400Mi when the heap caps at 256Mi?`,
    `Write a GitHub Action that fails the build if coverage drops below the previous commit.`,
    `Explain CORS preflight in one paragraph, for a backend engineer who keeps disabling it.`,
  ];
  for (const t of moreClean) add(t, []);

  return out;
}

// --- write ----------------------------------------------------------------

mkdirSync(CORPUS_DIR, { recursive: true });

const truePositives = buildTruePositives();
const mixed = buildMixed();

writeFileSync(join(CORPUS_DIR, "true-positives.json"), `${JSON.stringify(truePositives, null, 2)}\n`);
writeFileSync(join(CORPUS_DIR, "hard-negatives.json"), `${JSON.stringify(NEGATIVES, null, 2)}\n`);
writeFileSync(join(CORPUS_DIR, "mixed.json"), `${JSON.stringify(mixed, null, 2)}\n`);

console.log(
  `corpus written: ${truePositives.length} true positives, ${NEGATIVES.length} hard negatives, ${mixed.length} mixed`,
);
