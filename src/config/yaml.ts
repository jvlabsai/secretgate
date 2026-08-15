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

export type YamlValue = string | number | boolean | string[] | YamlMap;
export interface YamlMap {
  [key: string]: YamlValue;
}

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
        const items: string[] = [];
        while (cursor < lines.length) {
          const item = lines[cursor]!;
          if (item.indent <= line.indent || !item.content.startsWith("- ")) break;
          items.push(String(coerce(item.content.slice(2))));
          cursor++;
        }
        map[key] = items;
        continue;
      }

      map[key] = parseBlock(next.indent);
    }

    return map;
  }

  return parseBlock(0);
}
