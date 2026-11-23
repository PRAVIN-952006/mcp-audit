# Contributing to `mcp-audit`

Contributions—especially new MCP config rules, tool-poisoning / steganography signatures, and client auto-discovery paths—are welcome.

## Local Development (Zero Install Required on Node 22.18+)

```bash
# Run the full adversarial test suite
node --test test/mcp-audit.test.ts

# Run the built-in adversarial showcase
node src/cli.ts demo

# Typecheck & build dist/
npm install
npm run typecheck
npm run build
```

## Adding a New Rule
1. Add the rule metadata to `CONFIG_RULES` (`src/rules/config-rules.ts`), `TOOL_RULES` (`src/rules/tool-rules.ts`), or `RUGPULL_RULES` (`src/lockfile.ts`).
2. Keep zero runtime dependencies (`"dependencies": {}` in `package.json`).
3. Add a positive and negative regression test in `test/mcp-audit.test.ts`.
4. Update the rule table in `README.md`.
