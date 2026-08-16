/**
 * A deliberately small YAML reader for secretgate.yml.
 *
 * secretgate has zero runtime dependencies, which for a security tool is worth
 * more than generality: there is no supply chain to audit and nothing to
 * bundle. The config schema is fixed and tiny — a handful of scalars, one level
 * of nesting, and two lists of strings — so a full YAML parser would be a
 * dependency carried for features this file will never use.
 *
 * Supported, and nothing else:
 *
 *   key: value
 *   section:
 *     key: value
 *     list:
 *       - item
 *       - item
 *
 * Anything it does not understand is skipped rather than guessed at. The caller
 * validates every field it reads, so an unparsed line becomes a default.
 *
 * ponytail: no anchors, multi-line scalars, flow syntax or multiple documents.
 * If the config ever needs them, take the dependency then.
 */

export type YamlValue = string | number | boolean | string[] | YamlMap | YamlMap[];
export interface YamlMap {
  [key: string]: YamlValue;
}

/** `- key: value` starts a map entry; a plain identifier before the colon. */
const LIST_MAP_ENTRY = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/;

function stripComment(line: string): string {
  // A `#` inside quotes is content, not a comment.
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "#" && (i === 0 || /\s/.test(line[i - 1]!))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function coerce(raw: string): string | number | boolean {
  const v = raw.trim();
  if (
    (v.startsWith('"') && v.endsWith('"') && v.length >= 2) ||
    (v.startsWith("'") && v.endsWith("'") && v.length >= 2)
  ) {
    return v.slice(1, -1);
  }
  if (v === "true") return true;
  if (v === "false") return false;
  if (v === "null" || v === "~" || v === "") return "";
  if (/^-?\d+(?:\.\d+)?$/.test(v)) return Number(v);
  return v;
}

interface Line {
  indent: number;
  content: string;
}

export function parseSimpleYaml(source: string): YamlMap {
  const lines: Line[] = [];
  for (const raw of source.split(/\r?\n/)) {
    const withoutComment = stripComment(raw);
    if (!withoutComment.trim()) continue;
    lines.push({ indent: withoutComment.length - withoutComment.trimStart().length, content: withoutComment.trim() });
  }

  let cursor = 0;

  /**
   * A list is either scalars or maps, never both in practice. `rules.custom` is
   * the reason maps are supported at all: a user-defined detection rule needs
   * an id, a regex and a handful of options, and expressing that as a flat
   * string would be worse than parsing one more shape.
   */
  function parseList(listIndent: number): string[] | YamlMap[] {
    const scalars: string[] = [];
    const maps: YamlMap[] = [];

    while (cursor < lines.length) {
      const item = lines[cursor]!;
      if (item.indent !== listIndent || !item.content.startsWith("- ")) break;
      const body = item.content.slice(2).trim();
      cursor++;

      // A quoted value is a scalar even if it contains a colon, which keeps
      // things like "postgres://host" out of the map branch.
      const asEntry = body.startsWith('"') || body.startsWith("'") ? null : body.match(LIST_MAP_ENTRY);
      if (!asEntry) {
        scalars.push(String(coerce(body)));
        continue;
      }

      const entry: YamlMap = {};
      entry[asEntry[1]!] = coerce(asEntry[2] ?? "");

      // Continuation lines: further keys of this same list item.
      while (cursor < lines.length) {
        const cont = lines[cursor]!;
        if (cont.indent <= listIndent || cont.content.startsWith("- ")) break;

        const colon = cont.content.indexOf(":");
        if (colon === -1) {
          cursor++;
          continue;
        }
        const k = cont.content.slice(0, colon).trim();
        const v = cont.content.slice(colon + 1).trim();
        cursor++;

        if (v) {
          entry[k] = coerce(v);
          continue;
        }
        // Bare key: a nested list belonging to this entry, e.g. prefilter.
        const nested = lines[cursor];
        entry[k] = nested && nested.indent > cont.indent && nested.content.startsWith("- ") ? parseList(nested.indent) : "";
      }

      maps.push(entry);
    }

    return maps.length > 0 ? maps : scalars;
  }

  function parseBlock(minIndent: number): YamlMap {
    const map: YamlMap = {};

    while (cursor < lines.length) {
      const line = lines[cursor]!;
      if (line.indent < minIndent) break;
      if (line.content.startsWith("- ")) break; // a list belongs to the key above

      const colon = line.content.indexOf(":");
      if (colon === -1) {
        cursor++;
        continue;
      }

      const key = line.content.slice(0, colon).trim();
      const inline = line.content.slice(colon + 1).trim();
      cursor++;

      if (inline) {
        map[key] = coerce(inline);
        continue;
      }

      // Nothing after the colon: either a nested map or a list, both indented.
      const next = lines[cursor];
      if (!next || next.indent <= line.indent) {
        map[key] = "";
        continue;
      }

      if (next.content.startsWith("- ")) {
        map[key] = parseList(next.indent);
        continue;
      }

      map[key] = parseBlock(next.indent);
    }

    return map;
  }

  return parseBlock(0);
}
