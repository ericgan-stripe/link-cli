# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

Link CLI — lets agents get secure, one-time-use payment credentials from a Link wallet. pnpm + Turborepo monorepo:

- **`@stripe/link-sdk`** (`packages/sdk`): Repository interfaces, API implementations, types, and local storage. Entry: `src/index.ts`.
- **`@stripe/link-cli`** (`packages/cli`): Commander.js + Ink/React CLI that consumes `@stripe/link-sdk`. Entry: `src/cli.tsx`.

## Commands

```bash
pnpm install                    # install dependencies
pnpm run build                  # build all packages (turbo)
pnpm run dev                    # watch mode
pnpm run test                   # run all tests
pnpm run typecheck              # type-check all packages
pnpm biome check .              # lint + format check (CI)
pnpm run check                  # lint + format with auto-fix
```

Run a single test:
```bash
cd packages/cli && pnpm vitest run src/utils/__tests__/line-item-parser.test.ts
```

The CLI integration tests in `packages/cli/src/__tests__/cli.test.ts` run against the compiled `dist/cli.js`. Run `pnpm run build` before running them if the source has changed.

Run the CLI locally:
```bash
node packages/cli/dist/cli.js <command>
```

## Architecture

### SDK Resources

Defined in `packages/sdk/src/resources/interfaces.ts`:
- `IAuthResource` — device auth flow (initiate, poll, refresh)
- `ISpendRequestResource` — CRUD + request-approval for spend requests

### CLI Command Structure

Commands in `packages/cli/src/cli.tsx` (incur framework). Each has two output modes:
- **Interactive** (default): Ink/React components from `packages/cli/src/commands/`
- **JSON** (`--format json`): JSON to stdout, errors as JSON with `code` and `message` fields with exit code 1

Commands: `auth login|logout|status`, `spend-request create|update|retrieve|request-approval|cancel`, `payment-methods list`, `shipping-address list`, `mpp pay|decode`, `attestations request`, `credentials issue`, `request`, `serve`.

The CLI also runs as an MCP server (`--mcp`) and serves skill files via `skills` subcommand, both provided by incur.

**When changing commands, flags, or schema descriptions, always update all three together:** `README.md`, `skills/create-payment-credential/SKILL.md`, the schema description strings in the relevant `schema.ts` file, and `CLAUDE.md`. These can easily drift apart.

Input is passed via flags. Define options in the command's zod schema — incur registers CLI flags automatically from the schema.

### auth login

- `auth login --client-name <name>` — optional flag to identify the agent or app; shown in the user's Link app as `<name> on <hostname>`. Defined in `loginOptions` in `packages/cli/src/commands/auth/schema.ts`.
- `auth login --interval <seconds> [--timeout <seconds>] [--max-attempts <n>]` — when `--interval` is provided, the command yields the verification code immediately then polls inline until authenticated or timed out. Without `--interval`, returns the code with a `_next` hint for separate polling via `auth status`.
- The token endpoint echoes `scope` and `authorization_details` back with the tokens on login/refresh. These are persisted in the credential file (part of `AuthTokens`) and surfaced on `auth status` in both interactive and JSON modes, only when present.
- **Gotcha — two parallel `AuthResource` implementations.** `packages/cli/src/auth/auth-resource.ts` duplicates `packages/sdk/src/resources/auth.ts` (device auth flow, token parsing). The CLI uses its *own* via `ResourceFactory.createAuthResource()` (`packages/cli/src/utils/resource-factory.ts`) — the SDK class is not on the CLI's runtime path. Any change to token-response handling (new fields, parsing) must be applied to **both**, or the CLI silently drops it.

### spend-request command

CLI command is `spend-request` (user-facing). Implemented in `packages/cli/src/commands/spend-request/`. SDK interfaces: `ISpendRequestResource`, `CreateSpendRequestParams`, `UpdateSpendRequestParams`. API endpoint: `/spend_requests`.

Key input field notes:
- CLI input uses `payment_method_id`; mapped to `payment_details` when calling the SDK
- `context` requires min 100 characters; `amount` is in cents with max 500000
- `--metadata` (create only) is a repeatable `key:value` flag (CLI) or a `{ key: value }` object (MCP/agent), merged into a single `metadata` string→string map. Max 50 keys, key ≤ 40 chars, value ≤ 500 chars. Reuses `parseKvString` from `line-item-parser.ts`.
- `--test` flag creates testmode credentials (real testmode SPT from test card data) instead of livemode ones
- `create --request-approval` and `request-approval` both show an approval URL in interactive mode and poll until approved/denied/expired/failed/canceled. In JSON mode (`--format json`), they return immediately with an `_next.command` for `spend-request retrieve`.
- `retrieve --interval <seconds>` polls until approved/denied/expired/succeeded/failed/canceled. If `--timeout` is reached or `--max-attempts` is exhausted while the request is still non-terminal, it exits non-zero with `POLLING_TIMEOUT`.
- `cancel <id>` cancels a spend request. Can cancel from `created`, `pending_approval`, or `approved` states. Returns the spend request with `status: "canceled"`.
- `--approval-detail` — optional JSON object (MCP/agent) or JSON string (CLI) with approval details for delegated flows. Required fields: `approved_at` (unix timestamp int), `approval_method` (`click`|`programmatic`|`voice`), `app_name`, `external_user_id`. Optional: `ip_address`, `user_agent`, `device_type` (`mobile`|`web`), `agent_log_id`, `external_user_name`, `external_session_id`, `authentication_method` (`biometric_face`|`biometric_fingerprint`|`passkey`). Sent as `approval_details` in the API request body.
- `card` credentials include `billing_address` (name, line1, line2, city, state, postal_code, country) and `valid_until` (ISO date string — when the card expires/stops working)
- `--output-file <path>` on `retrieve` or `create` writes full card credentials to a local file (0600 permissions) and redacts card data in stdout. `--force` allows overwriting an existing file.

### mpp pay

- `mpp pay <url> --context <ctx> [-X <method>] [-d <body>] [-H <header>]... [--amount <cents>] [--payment-method-id <id>] [--test]` — handles the full MPP flow end-to-end: probes the URL for a 402 challenge, parses the `www-authenticate` header to extract network_id and amount, creates a spend request (credential_type: shared_payment_token), gets user approval, retrieves the SPT, and pays. Amount/currency are derived from the 402 challenge; `--amount` overrides. `--context` is required (min 100 chars) — describe the purchase and rationale. Default payment method is used unless `--payment-method-id` is specified.
- `mpp pay <url> --spend-request-id <id> [--method <method>] [--data <body>] [--header <header>]...` — backward-compat mode: uses a pre-approved spend request directly, skipping creation/approval.
- `--header` is repeatable and uses `"Name: Value"` format. `Content-Type: application/json` is auto-applied when `--data` is provided; user-provided headers take precedence.
- The SPT is one-time-use — a failed payment requires running `mpp pay` again (creates a new spend request).
- Implemented in `packages/cli/src/commands/mpp/` — pay.tsx (logic), schema.ts (input/output schema), index.tsx (incur registration).

### demo command

- `demo [--only-card] [--only-spt]` — Interactive demo of both payment flows. Always uses `--test` mode (no real charges). Shows a menu to choose: virtual card flow, SPT/machine payment flow, or both. `--only-card` and `--only-spt` skip the menu. Requires a TTY (no JSON output mode).

### onboard command

- `onboard` — Guided setup: authenticates (skips if already logged in), checks payment methods (prompts to add one if missing, shows picker if multiple), shows app download QR code, then runs the full demo. Requires a TTY.

### attestations command (AAP)

`attestations request --count <n> [--issuer <url>] [--target-origin <origin>] [--access-token <t>]` — mints Agent Attestation Tokens via the Privacy Pass Blind RSA protocol (token type `0x0002`, RFC 9578 / RFC 9577). Agent-only output (no interactive mode). Implemented in `packages/cli/src/commands/attestations/`: `blind-rsa.ts` (blinding, EMSA-PSS with SHA-384, unblinding, SPKI parsing), `request.ts` (the issuance flow), `schema.ts`, `index.tsx`.

- Discovery: `GET <issuer>/.well-known/aap-issuer` → metadata, then `GET` its `token_keys` URL. Default issuer `https://api.link.com`.
- The served `token-key` is an **`id-RSASSA-PSS`** SPKI, whose algorithm parameters contain bytes that look like BIT STRING/INTEGER tags. The DER must be walked structurally — scanning for tag bytes mis-parses it. Node's `createPublicKey` can parse this key but cannot export it as JWK or PKCS#1, which is why the modulus is parsed by hand.
- Issuance is **binary**, not JSON (`Content-Type: application/private-token-request`). Request is a `BatchTokenRequest`: `uint16` byte-length prefix + N × (`uint16` token_type ‖ `uint8` truncated_token_key_id ‖ 256-byte blinded_msg). Response is a `BatchTokenResponse`: `uint16` prefix + N × 256-byte blind signatures. `truncated_token_key_id` is the **last byte** of SHA-256(SPKI DER); a mismatch is a 400 "unknown token key".
- Server-side max batch is 100, rate-limited hourly per (consumer, client). Requires the `aap:represent` scope.
- Token order in the response matches request order — unblinding is positional.
- Auth: `--access-token`, else `AAP_ACCESS_TOKEN`, else the stored CLI credentials.

### credentials command (AAP)

`credentials issue [--key-file <path>] [--key-type ed25519|p256] [--access-token <t>]` — mints a short-lived (1h) holder-bound SD-JWT-VC with the user's identity claims (`email`, `phone_number`, `given_name`, `family_name`). Agent-only output. Implemented in `packages/cli/src/commands/credentials/`.

- `POST /credentials` with `{"cnf": {"jwk": <public JWK>}}` (RFC 7800 key confirmation). The issuer validates the holder key strictly: only `OKP`/`Ed25519` (`kty`, `crv`, `x`) or `EC`/`P-256` (plus `y`), unpadded base64url, 32-byte members, on-curve, and **no extra members and no `d`** — so only the allowed members may be sent.
- The holder key is persisted at `--key-file` (default `~/.link/holder-key.jwk`, mode 0600) and reused across runs: the credential is bound to it and presenting the credential later requires signing a KB-JWT with it.
- The result includes `claims` decoded from the credential's `~`-separated disclosures (each is base64url of `[salt, name, value]`).
- Requires the `aap:represent`, `userinfo:read` and `payment_methods.agentic` scopes.
- **Gated server-side** by the `enable_agent_credentials_endpoint` feature flag, which short-circuits with a 404 *before* auth. A 404 whose body is `{"error":{"message":"Not found"}}` means the flag is off; nginx's "Unrecognized request URL" means the route isn't deployed.
- Respects `LINK_API_BASE_URL`.

### request command (AAP)

`request <url> [--claims "a,b,c"] [-X <method>] [-d <body>] [-H <header>]... [--key-file <path>] [--key-type ed25519|p256]` — makes an HTTP request that satisfies an identity-claims challenge, collapsing the whole disclosure flow into one command. Agent-only output. Implemented in `packages/cli/src/commands/request/`: `present.ts` (challenge parsing, presentation + KB-JWT construction), `schema.ts`, `index.tsx`.

- Sends the request; if the response is **401 with a JSON body whose `type` is `urn:aap:claims-required`**, it issues a credential (reusing `issueCredential`), builds an SD-JWT-VC presentation, and retries with an `Identity-Presentation` header. Any other response is passed straight through with `identity_required: false` — no credential is minted.
- `--claims` is a comma-separated allowlist of what to disclose; defaults to exactly the challenge's `claims`. Disclosing *less* than the server requires is allowed here and rejected by the server — useful for demoing that the holder controls disclosure.
- Errors with `CLAIMS_UNAVAILABLE` *before* sending anything if the credential doesn't hold a requested claim.
- The KB-JWT binds `aud` (from the challenge), `nonce` (single-use), and `sd_hash` (SHA-256 over the presentation up to and including the final `~`) — so a presentation can't be replayed or trimmed after signing. Signed with the holder key: `EdDSA` for ed25519, `ES256` (raw r‖s via `dsaEncoding: 'ieee-p1363'`, not DER) for p256.
- **Gotcha:** root-level `Cli.create` commands don't accept `middleware`, so the auth check calls `requireAuthGuard(c, ...)` inline instead of `requireAuth(...)`.

### serve command

- `serve [--port <n>] [--host <host>]` — HTTP server that exposes the CLI's MCP endpoint. Implemented in `packages/cli/src/commands/serve/index.ts`. The handler forwards to `rootCli.fetch()` (incur), but is a **privilege boundary**: `requireAuth` only proves the CLI *owner* is authenticated, not that the HTTP caller is authorized.

## Code Conventions

- **ESM everywhere** — `"type": "module"` in all package.json files
- **Biome** — 2-space indent, single quotes, organized imports
- **tsup** — ESM output, Node 18 target
- **Vitest** — test files in `__tests__/` directories adjacent to source
- **TypeScript strict mode** — `tsconfig.base.json` at root
- **React 18 + Ink 5** for interactive rendering
- **`conf`** for local auth token storage

## Global Flags

| Flag | Effect |
|------|--------|
| `--auth <path>` | Store auth credentials in a specific file instead of the default platform config location. `auth login` writes to this file; all other commands read from it. Parsed from `process.argv` and stripped before incur processes flags. |

## Security: Terminal Output Sanitization

Server-returned strings can contain ANSI escape sequences or control characters that spoof the terminal approval UI. Sanitization is handled automatically via `sanitizeDeep()` from `packages/cli/src/utils/sanitize-text.ts`:

- **Commands using `useAsyncAction` hook** — sanitized automatically. The hook calls `sanitizeDeep()` on all returned data before it reaches components.
- **Commands with manual state management** (e.g. `create.tsx`, `retrieve.tsx`, `request-approval.tsx`, `mpp/pay.tsx`) — must call `sanitizeDeep()` on API responses before calling `setRequest()`/`setState()`.

JSON output mode (`--format json`) is **not** affected — `JSON.stringify` encodes escape sequences as Unicode literals.
## Environment Variables

| Variable | Effect |
|----------|--------|
| `LINK_AUTH_FILE` | Same as `--auth` — override the auth credential file path (flag takes precedence) |
| `LINK_ACCESS_TOKEN` | Use this access token directly, bypassing auth storage |
| `LINK_REFRESH_TOKEN` | Refresh token to use when `LINK_ACCESS_TOKEN` is expired |
| `LINK_NO_REFRESH` | When set, never auto-refresh the access token — error instead |
| `LINK_API_BASE_URL` | Override API base URL |
| `LINK_AUTH_BASE_URL` | Override auth base URL |
| `LINK_HTTP_PROXY` | Route all SDK requests through an HTTP proxy (requires `undici` installed) |
