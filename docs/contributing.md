# Contributing registry data

## Requirements

- Base work on current `dev`.
- Use exactly one PR to `dev` for one registry publication.
- Never edit an existing `revisions/` file.
- Never commit private keys, credentials, headers, endpoint configuration, or executable data.
- Never publish an npm package, GitHub release, or Git tag for registry changes.

## Deterministic upstream import

Check out the intended `Yeachan-Heo/gajae-code` commit locally. Record its full 40-character commit and canonical UTC commit timestamp. Generate the next eight-digit revision:

```sh
npm ci
npm run import:upstream -- \
  --source-root ../gajae-code \
  --source-revision FULL_40_CHARACTER_COMMIT \
  --source-date 2026-08-24T09:41:42.000Z \
  --revision 00000002 \
  --key-id ACTIVE_KEY_ID
```

The importer parses TypeScript literals without executing upstream code and projects model data through an explicit safe-field allowlist. It records repository, source paths, source revision, source timestamp, and generator version in manifest/snapshot provenance. Update `ATTRIBUTION.md` when the upstream source revision changes.

Inspect the generated diff. New names must be unique under exact, case-folded, normalized, and confusable checks. Reserved `gjc-`, `gajae-`, `system-`, `internal-`, and `__` namespaces are unavailable. Profile selectors must resolve to a catalog preset or a declared dynamic provider.

## Signing

A maintainer signs the generated manifest with an active Ed25519 private key supplied outside Git:

```sh
REGISTRY_SIGNING_PRIVATE_KEY="$(security-tool read registry-key)" npm run sign -- \
  --manifest revisions/00000002/manifest.json \
  --public-key keys/ACTIVE_KEY_ID.json \
  --latest latest.json
```

The signer proves that the private key matches the committed public JWK, signs only canonical `manifest.signed`, writes canonical JSON, and copies the exact manifest bytes to `latest.json`. Do not print, paste into review, or persist the private key. Repository CI validates signatures with public keys only.

Keys under `test/fixtures/` are deterministic, publicly known, and marked **NON-PRODUCTION**. They exist only to test verification failure/success paths and MUST never sign a registry revision.

Adding a production key also requires `keys/transitions/<new-key-id>.json`, signed by a key already trusted on the base branch and binding the canonical SHA-256 digest of the complete new public-key document. A self-signed key addition does not pass validation. Once merged, public-key and transition documents are immutable; revocation adds a separately authorized record or ships through a trusted consumer trust-store update.

## Verification and review

Run all gates on the exact proposed head:

```sh
npm test
npm run check:reproducible
BASE_REF=origin/dev npm run validate
```

The validator covers schemas, canonical bytes, signatures, digests, reproducibility, duplicate/case-confusable names, reserved namespaces, profile/model references, dynamic-provider declarations, unsafe fields/URLs/secrets, revision monotonicity, immutable history, and `latest.json` consistency.

Push the branch and open exactly one PR to `dev`. Independent review and required CI MUST refer to the exact head SHA that is merged. Any head change invalidates the earlier review and requires review/checks again. Merge only after the exact-head checks succeed. The merged `dev` commit is the data publication; do not create a release, package, or tag.

## Rollback and key operations

Emergency rollback changes only `latest.json` to the exact bytes of a previously trusted immutable manifest, then follows the same exact-head validation and review workflow. Key rotation and revocation follow [registry-contract.md](registry-contract.md); a compromised key cannot self-authorize its own replacement.
