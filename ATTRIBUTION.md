# Attribution

Each registry revision is a deterministic, safety-filtered projection of model metadata and built-in model profiles from [Yeachan-Heo/gajae-code](https://github.com/Yeachan-Heo/gajae-code).

Revision `00000005`:

- Source revision: `7f1b3c7ec416382371577c21cfc09e75be5725d9` (gajae-code #6163, `feat/codex-pro-sol61`, on top of `dev` 467f6c1)
- Source timestamp: `2026-09-30T13:15:41.000Z`
- Adds the Claude Sonnet 5.5 and GPT-6.1-Sol catalog entries. Built-in Codex profile roles on `gpt-6-sol` or `gpt-5.6-terra` move to `gpt-6.1-sol` at the same effort, `codex-eco` becomes GPT-6 Luna in every role, and Sonnet 5 roles move to Sonnet 5.5. Profile count stays at 63: the upstream `codex-sol61` profile is removed because `codex-pro` now carries GPT-6.1 Sol.

Revision `00000004`:

- Source revision: `69e39df425b182694000bfcc81162c2bffb071c6` (gajae-code #5995, after #5993)
- Source timestamp: `2026-09-26T12:26:53.000Z`
- Updates Opus profiles to 5.5 and imports the intervening GPT-6 model/profile changes.

Revision `00000003`:

- Source revision: `bf6a86b3107a2a2a21dfed38edb617bedd280c27`
- Source timestamp: `2026-09-05T06:27:11.000Z`
- Adds the GPT-6 Astra Codex catalog entry and five ASTRA tier/Fable combination profiles while preserving the previous 58 profiles.

Revision `00000002`:

- Source revision: `67fb0355a6c7d124a2dbbfd701228069b991858b`
- Source timestamp: `2026-09-02T00:38:18.000Z`

Revision `00000001`:

- Source revision: `65d0d2fdae36a4512959a6a8c143339b8ec98c58`
- Source timestamp: `2026-08-24T09:41:42.000Z`
- Source files:
  - `packages/ai/src/models.json`
  - `packages/coding-agent/src/config/model-profiles.ts`
- Imported by: `scripts/import-upstream.mjs@1`

The upstream project is licensed under the MIT License. The imported projection omits transport configuration, headers, credentials, arbitrary request bodies, and other fields outside this registry's strict safe-data schemas.

The generated revision manifest and snapshot repeat this provenance in machine-readable form.
