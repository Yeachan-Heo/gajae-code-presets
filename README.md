# Gajae Code Presets

Public, hot-updatable model preset and profile registry for Gajae Code.

The registry publishes strict, versioned, credential-free JSON documents under
immutable `revisions/` directories. `latest.json` is the canonical signed
pointer that consumers validate before atomically accepting a snapshot.

## Registry layout

- `latest.json` — byte-identical copy of the selected immutable manifest.
- `revisions/NNNNNNNN/` — manifest, snapshot, presets, and profiles for one revision.
- `schemas/` — JSON Schema 2020-12 contracts.
- `keys/` — public Ed25519 verification keys only.
- `scripts/` — deterministic import, signing, and validation tooling.
- `docs/registry-contract.md` — consumer, compatibility, trust, cache, and rollback contract.
- `docs/contributing.md` — contributor and publication workflow.

Private signing keys are never committed. Test fixture keys are explicitly
non-production and live only under `test/fixtures/`.

```sh
npm ci
npm test
npm run validate
```

The initial data projection is attributed in [ATTRIBUTION.md](ATTRIBUTION.md).
