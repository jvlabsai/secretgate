/**
 * stdin -> stdout filter. The escape hatch that makes secretgate usable with
 * tools nobody has written an adapter for.
 *
 *   cat prompt.txt | secretgate filter | some-agent
 *
 * Exit 0 clean or redacted, 2 blocked.
 */
import { loadConfig } from "../config/index.js";
import { guardOutbound, guardInbound, readStdin } from "./shared.js";

export async function runFilter(opts: { rehydrate?: boolean; quiet?: boolean } = {}): Promise<number> {
  const text = await readStdin();
  const config = loadConfig();

  if (opts.rehydrate) {
    const { text: restored, warnings } = guardInbound(text, config);
    process.stdout.write(restored);
    if (!opts.quiet) for (const w of warnings) process.stderr.write(`${w}\n`);
    return warnings.length > 0 ? 1 : 0;
  }

  const outcome = guardOutbound(text, config);
  if (outcome.action === "deny") {
    if (!opts.quiet) process.stderr.write(`${outcome.message}\n`);
    return 2;
  }

  process.stdout.write(outcome.text);
  if (!opts.quiet && outcome.message) process.stderr.write(`${outcome.message}\n`);
  return 0;
}
