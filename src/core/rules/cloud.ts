import type { Rule } from "../types.js";

/** AWS, GCP, Azure, DigitalOcean, Cloudflare, Heroku. */
export const cloudRules: Rule[] = [
  {
    id: "aws-access-key-id",
    provider: "aws",
    description: "AWS access key ID",
    // ABIA/ACCA are STS and context-specific variants; all share the shape.
    regex: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    prefilter: ["AKIA", "ASIA", "ABIA", "ACCA"],
    group: 1,
    entropyMin: 2.6,
    confidence: "high",
  },
  {
    id: "aws-secret-access-key",
    provider: "aws",
    // 40 chars of base64 is far too generic on its own, so this one is
    // context-anchored: it only fires next to a key-ish identifier.
    description: "AWS secret access key",
    regex:
      /aws[_.\-]?(?:secret[_.\-]?)?access[_.\-]?key(?:[_.\-]?id)?["'\s]*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    prefilter: ["aws_secret", "aws-secret", "awsSecret", "aws_access", "AWS_SECRET", "aws.secret"],
    group: 1,
    entropyMin: 3.5,
    confidence: "high",
  },
  {
    id: "aws-session-token",
    provider: "aws",
    description: "AWS session token",
    regex: /aws[_.\-]?session[_.\-]?token["'\s]*[:=]\s*["']?([A-Za-z0-9/+=]{100,})["']?/gi,
    prefilter: ["session_token", "session-token", "sessionToken", "SESSION_TOKEN"],
    group: 1,
    entropyMin: 4.0,
    confidence: "high",
  },
  {
    id: "gcp-service-account-key",
    provider: "gcp",
    // The private_key field inside a service-account JSON blob. The generic
    // private-key rule would catch the PEM too, but naming the provider makes
    // the placeholder more useful to the agent.
    description: "GCP service account private key",
    regex: /"type"\s*:\s*"service_account"[\s\S]{0,600}?"private_key"\s*:\s*"(-----BEGIN[^"]+?-----END[^"]*?-----\\n?)"/g,
    prefilter: ["service_account"],
    group: 1,
    confidence: "high",
  },
  {
    id: "gcp-api-key",
    provider: "google",
    description: "Google API key",
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    prefilter: ["AIza"],
    group: 1,
    entropyMin: 3.2,
    confidence: "high",
  },
  {
    id: "gcp-oauth-client-secret",
    provider: "google",
    description: "Google OAuth client secret",
    regex: /\b(GOCSPX-[A-Za-z0-9_-]{28})\b/g,
    prefilter: ["GOCSPX-"],
    group: 1,
    confidence: "high",
  },
  {
    id: "azure-storage-key",
    provider: "azure",
    description: "Azure storage account key",
    regex: /AccountKey\s*=\s*([A-Za-z0-9+/]{86}==)/g,
    prefilter: ["AccountKey"],
    group: 1,
    entropyMin: 4.0,
    confidence: "high",
  },
  {
    id: "azure-ad-client-secret",
    provider: "azure",
    description: "Azure AD client secret",
    regex: /\b([A-Za-z0-9~._-]{3}8Q~[A-Za-z0-9~._-]{31,34})\b/g,
    prefilter: ["8Q~"],
    group: 1,
    entropyMin: 3.8,
    confidence: "high",
  },
  {
    id: "digitalocean-token",
    provider: "digitalocean",
    description: "DigitalOcean personal access token",
    regex: /\b(dop_v1_[a-f0-9]{64})\b/g,
    prefilter: ["dop_v1_"],
    group: 1,
    confidence: "high",
  },
  {
    id: "cloudflare-api-token",
    provider: "cloudflare",
    description: "Cloudflare API token",
    regex: /cloudflare[_.\-]?(?:api[_.\-]?)?token["'\s]*[:=]\s*["']?([A-Za-z0-9_-]{40})["']?/gi,
    prefilter: ["cloudflare", "CLOUDFLARE", "Cloudflare"],
    group: 1,
    entropyMin: 4.0,
    confidence: "medium",
  },
  {
    id: "heroku-api-key",
    provider: "heroku",
    description: "Heroku API key",
    regex:
      /heroku[_.\-]?(?:api[_.\-]?)?key["'\s]*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
    prefilter: ["heroku", "HEROKU", "Heroku"],
    group: 1,
    confidence: "high",
  },
];
