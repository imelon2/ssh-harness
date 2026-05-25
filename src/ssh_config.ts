import * as fs from 'node:fs';

/**
 * Parse Host aliases declared in an OpenSSH client config file.
 * - Line-by-line, case-insensitive on the "Host" keyword
 * - Multi-alias "Host a b c" registers a, b, c (all lowercased)
 * - "Host *" wildcard is ignored (matches everything; would defeat the check)
 * - Comments (#) and blank lines skipped
 */
export function parseHostAliases(configText: string): Set<string> {
  const aliases = new Set<string>();
  for (const rawLine of configText.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const tokens = line.split(/\s+/);
    if (tokens[0].toLowerCase() !== 'host') continue;
    for (const alias of tokens.slice(1)) {
      if (alias === '*') continue;
      aliases.add(alias.toLowerCase());
    }
  }
  return aliases;
}

export function loadHostAliases(configPath: string): Set<string> {
  const text = fs.readFileSync(configPath, 'utf8');
  return parseHostAliases(text);
}
