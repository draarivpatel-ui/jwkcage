# Contributing

## Development setup

Node.js 18 or newer. There are no dependencies to install.

```sh
node scripts/run-tests.mjs
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
node scripts/check-pack.mjs
```

## Rules for changes

- Every security behavior change ships with regression tests, including the hostile input matrix.
- The CommonJS build is generated: edit `src/`, then run `node scripts/build-cjs.mjs` and commit the result.
- No dependencies, runtime or development.
- No network access in library code, tests, or examples.
- Private key material never appears in error messages, findings, or logs. Tests use generated throwaway keys only.
- Line endings are LF everywhere; `scripts/build-cjs.mjs` normalizes generated output.
