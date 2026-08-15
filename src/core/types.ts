export type Confidence = "high" | "medium" | "low";

export type Action = "block" | "redact" | "warn" | "ignore";

export interface Finding {
  ruleId: string;
  provider: string;
  /** The credential itself, not the surrounding context. */
  match: string;
  start: number;
  end: number;
  confidence: Confidence;
  entropy: number;
  /** Why a finding was downgraded or dropped, for `--explain`. */
  note?: string;
}

export interface Rule {
  id: string;
  provider: string;
  description: string;
  /**
   * Must be constructed with the `g` flag. `lastIndex` is reset before every
   * use, so a single compiled instance is safe to share across scans.
   */
  regex: RegExp;
  /**
   * Literal substrings, at least one of which must appear in the text for the
   * regex to be worth running. Rules with strong prefixes (AKIA, ghp_, sk-)
   * get a large speedup; rules without one simply always run.
   */
  prefilter?: string[];
  /** Capture group holding the secret. Defaults to 0 (whole match). */
  group?: number;
  /** Reject matches whose Shannon entropy falls below this. */
  entropyMin?: number;
  confidence?: Confidence;
  /**
   * Last word on whether a match is real. Regex gets us the shape; this catches
   * what shape alone cannot (a JWT whose payload is not decodable JSON, a
   * connection string with no password in it).
   */
  validate?: (secret: string, wholeMatch: string) => boolean;
}

export interface EntropyConfig {
  enabled: boolean;
  threshold: number;
  action: Action;
}

export interface VaultConfig {
  persist: boolean;
}

export interface Config {
  mode: "redact" | "block" | "warn";
  entropy: EntropyConfig;
  rules: { disable: string[] };
  allowlist: { paths: string[]; patterns: string[] };
  vault: VaultConfig;
  /** Absolute path of the file being scanned, when scanning a file. */
  path?: string;
  /** Salted hashes of findings the developer has already accepted. */
  baseline?: Set<string>;
  baselineSalt?: string;
}

export interface ScanResult {
  findings: Finding[];
  /** Findings that matched but were suppressed. Surfaced by `--explain`. */
  suppressed: Finding[];
}
