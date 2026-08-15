import type { Rule } from "../types.js";

/**
 * LLM provider keys. Worth their own pack: these are the credentials most
 * likely to be sitting in the exact file an AI agent is being asked to read.
 */
export const aiRules: Rule[] = [
  {
    id: "anthropic-api-key",
    provider: "anthropic",
    description: "Anthropic API key",
    regex: /\b(sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{80,120})\b/g,
    prefilter: ["sk-ant-"],
    group: 1,
    entropyMin: 4.0,
    confidence: "high",
  },
  {
    id: "openai-api-key",
    provider: "openai",
    // Classic keys are sk- + 48. Project keys are sk-proj- + a longer body.
    // Deliberately does not match Stripe's sk_live_ (underscore, not hyphen).
    description: "OpenAI API key",
    regex: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g,
    prefilter: ["sk-"],
    group: 1,
    entropyMin: 3.8,
    confidence: "high",
    // sk-ant- keys are Anthropic's; let that rule own them so the placeholder
    // names the right provider.
    validate: (s) => !s.startsWith("sk-ant-"),
  },
  {
    id: "openrouter-api-key",
    provider: "openrouter",
    description: "OpenRouter API key",
    regex: /\b(sk-or-v1-[a-f0-9]{64})\b/g,
    prefilter: ["sk-or-v1-"],
    group: 1,
    confidence: "high",
  },
  {
    id: "huggingface-token",
    provider: "huggingface",
    description: "Hugging Face access token",
    regex: /\b(hf_[A-Za-z0-9]{34,40})\b/g,
    prefilter: ["hf_"],
    group: 1,
    entropyMin: 3.2,
    confidence: "high",
  },
  {
    id: "replicate-api-token",
    provider: "replicate",
    description: "Replicate API token",
    regex: /\b(r8_[A-Za-z0-9]{37,40})\b/g,
    prefilter: ["r8_"],
    group: 1,
    entropyMin: 3.2,
    confidence: "high",
  },
  {
    id: "groq-api-key",
    provider: "groq",
    description: "Groq API key",
    regex: /\b(gsk_[A-Za-z0-9]{52})\b/g,
    prefilter: ["gsk_"],
    group: 1,
    entropyMin: 3.5,
    confidence: "high",
  },
  {
    id: "cohere-api-key",
    provider: "cohere",
    description: "Cohere API key",
    regex: /cohere[_.\-]?(?:api[_.\-]?)?key["'\s]*[:=]\s*["']?([A-Za-z0-9]{40})["']?/gi,
    prefilter: ["cohere", "COHERE", "Cohere"],
    group: 1,
    entropyMin: 3.8,
    confidence: "medium",
  },
];
