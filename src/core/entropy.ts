/**
 * Shannon entropy in bits per character.
 *
 * Used two ways:
 *  - as a gate on structured rules that would otherwise match placeholder junk
 *    (`AKIAXXXXXXXXXXXXXXXX` has a valid shape but ~1.2 bits/char)
 *  - as the standalone layer-2 detector for credentials we have no rule for
 */
export function shannon(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

const HEX = /^[0-9a-fA-F]+$/;

/**
 * Hex strings top out around 4 bits/char by definition, so holding them to the
 * base64 threshold would mean never flagging one. Callers use this to pick the
 * right bar.
 */
export function isHex(s: string): boolean {
  return HEX.test(s);
}

export function entropyThresholdFor(s: string, base64Threshold: number): number {
  // 3.0 for hex, configured value (default 4.0) for everything else.
  return isHex(s) ? Math.min(3.0, base64Threshold) : base64Threshold;
}
