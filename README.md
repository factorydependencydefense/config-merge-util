# config-merge-util

Layered configuration merging and secret redaction. Part of the dependency-defense demo fleet.

```bash
npm ci
npm test
npm run build
```

## Tests

`npm test` runs `test/*.test.js`:

- `test/config.test.js` and `test/preservation.test.js` pin the public behaviour of `mergeLayers`,
  `redact`, `readPath` and `sameConfig` with legitimate inputs. They must stay green across a lodash
  upgrade, so a remediation PR can use them as proof it changed no behaviour.
- `test/characterization.test.js` pins today's *vulnerable* behaviour. A remediation PR is expected to
  invert these assertions; that inversion is the visible evidence of the fix.

`npm run test:security` runs `test/security/**/*.test.js` and is deliberately **not** part of
`npm test`. It asserts the secure invariant, so it is red wherever the vulnerability is real.

Red today (3 of 6):

- `mergeLayers must not let a single untrusted layer reach Object.prototype`
- `mergeLayers must not let a nested untrusted layer reach Object.prototype`
- `the lodash omit build behind redact must not delete an inherited property for a crafted key path`

The first two are red because `mergeLayers(oneLayer)` calls `merge({}, layer)`, and the pinned lodash
walks into `Object.prototype` through a `constructor.prototype` payload. Called with two or more
layers the same payload is contained, which is why that case passes. The third is red because the
pinned `lodash/omit` unsets through a `__proto__.x` path and deletes a property off `Object.prototype`.

What these tests do **not** cover: the planted unused dependencies (`left-pad`, `underscore`), the
bundled `dist/index.js`, dynamic `require`, any network or filesystem path, and the fact that `redact`
copies inherited enumerable properties into its output (unchanged by the upgrade, so not asserted).
