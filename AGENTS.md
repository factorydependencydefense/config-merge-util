# AGENTS.md

## What this repo is

`config-merge-util`: layered configuration merging and secret redaction, used by the other fleet services. Part of the `factorydependencydefense` fleet.

## Commands

- Install: `npm ci`
- Build: `npm run build` (esbuild bundle to `dist/index.js`)
- Test: `npm test` (`node --test`, under 60 seconds)

## Rules

- Lodash is imported per function (`lodash/merge.js`), not as a whole. Keep it that way.
- Never push to `main`. Commit on a `droid/<job>` branch; the harness opens the PR.
- Never pick a package version from memory. Use `npm view <pkg> versions --json`.
- A change is done only when `npm run build` and `npm test` both pass.
- Keep diffs small: one concern per PR.
