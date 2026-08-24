# Registry contract v1

## Security boundary

This repository is a public data plane. Registry documents are declarative JSON, never executable configuration. The schemas reject unknown fields and do not permit credentials, request headers, API keys, base URLs, arbitrary request bodies, commands, or scripts. Model presets contain only approved capability, pricing, context, thinking, and compatibility metadata. Profiles contain only provider requirements and bindings for `default`, `executor`, `architect`, `planner`, and `critic`.

Consumers MUST apply bounded HTTPS response size and timeout limits before parsing. They MUST NOT treat any registry string as code, a shell argument, a request header, a credential, or an endpoint.

## Files and immutable revisions

Each `revisions/NNNNNNNN/` directory is immutable after merge. Its decimal revision equals `registryRevision` and increases monotonically for new publications. It contains canonical `manifest.json`, `snapshot.json`, `presets.json`, and `profiles.json` documents.

`latest.json` MUST be byte-identical to one immutable revision's `manifest.json`. Changing `latest.json` is the only publication or rollback pointer operation. A rollback points it to an already trusted older manifest; immutable content is never edited or copied into a new historical directory merely to roll back.

## Canonical JSON and digests

All registry JSON uses UTF-8 canonical JSON with lexicographically sorted object keys, ECMAScript JSON number serialization, no insignificant whitespace, and no trailing newline. Non-finite numbers, sparse arrays, unsupported values, cycles, and lone Unicode surrogates are rejected.

Every descriptor records the canonical file's lowercase SHA-256 digest, exact byte count, path, and item count. Consumers MUST verify byte count and digest before parsing dependent content. The snapshot repeats content descriptors; the signed manifest and snapshot copies MUST agree exactly.

## Ed25519 signature envelope

A manifest has a `signed` payload and a `signature` envelope. The signed bytes are exactly the canonical UTF-8 encoding of `manifest.signed`. The envelope is:

```json
{"algorithm":"Ed25519","keyId":"registry-root-2026-01","value":"BASE64_SIGNATURE"}
```

Consumers pin an explicit key-id-to-public-key trust store. They MUST reject unknown key ids, malformed base64, non-Ed25519 keys, invalid signatures, keys not yet valid at `publishedAt`, and revoked keys. Private keys are never stored in Git, artifacts, logs, or registry documents. The repository secret `REGISTRY_SIGNING_PRIVATE_KEY` is the operational signing input; CI validation does not need or expose it.

### Rotation and revocation

Planned rotation publishes the new public key and a transition record signed by the currently trusted key before any manifest uses the new key. Consumers accept the new key only after validating that transition or receiving the key in a trusted Gajae Code trust-store update. After the overlap window, a later signed transition marks the old key revoked and identifies its replacement.

Compromise response is fail-closed: stop moving `latest.json`, revoke the key in consumer trust stores, and publish a replacement key through an already trusted key or a Gajae Code trust-store update. A repository-only revocation signed by the compromised key is not sufficient evidence. Consumers MUST reject a manifest whose key is listed as revoked even when its mathematical signature verifies.

## Compatibility

`compatibility.consumerContract.minVersion` and `maxVersion` are inclusive semantic versions of this data contract, not application release versions. A consumer with contract version `V` accepts only when `minVersion <= V <= maxVersion`. Unknown schema versions or fields are rejected; there is no permissive downgrade or compatibility fallback.

## Consumer cache behavior

Consumers fetch `latest.json`, verify its canonical form, compatibility, key, signature, revision policy, and descriptor bounds, then fetch and verify the snapshot and content into a temporary cache location. They atomically replace the active cache only after the entire snapshot passes. Startup and explicit refresh use cached-last-known-good data when the network is unavailable or an update is malformed, incompatible, downgraded, partial, oversized, or untrusted. A rejected update never modifies the active cache. Cache writes SHOULD use fsync plus atomic rename appropriate to the platform.

A lower revision is accepted only when its exact signed manifest is selected by `latest.json` and local rollback policy permits it; transient network responses cannot silently downgrade cached state.

## Publication and emergency rollback

Publication is one reviewed PR to `dev` containing a new immutable revision and a byte-identical `latest.json` update. Merge is atomic at the Git commit level. No package, release, or tag is part of this data-plane publication.

For emergency rollback, copy the chosen existing immutable `manifest.json` bytes over `latest.json`, validate, obtain exact-head review and CI, and merge that pointer-only PR. Never modify the old revision, signatures, or digests.
