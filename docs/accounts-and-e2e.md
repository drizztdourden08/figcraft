# Accounts and end-to-end encryption (draft)

Status: proposal, milestone M9 ("accounts and teams" in [`ROADMAP.md`](../ROADMAP.md)). Sections
say what is built as the implementation lands. Builds on [`collab-protocol.md`](collab-protocol.md)
(live sessions) and [`server.md`](server.md) (running `figcraft-server`).

Goal: a `figcraft-server` can (1) let people in by **who they are** instead of only by share links,
through **pluggable identity providers**, and (2) keep files **end-to-end encrypted** ("sealed"), so
whoever runs or breaks into the server can't read them. Both are **off by default**: a server with
no new settings behaves exactly as before, and the desktop app's own sessions (hosting from the
app, on the local network) don't change.

## Ground rules

- **Two independent switches**: `auth.mode` (who may get in) and `e2e.mode` (whether files are
  sealed). Every combination works (see *Configuration*).
- **No vendor in the core.** Identity comes through the [`IdentityProvider`](#identity-providers)
  trait. The built-in providers implement standards (OpenID Connect, the OAuth device flow) or call
  a verifier you run (`external`); Google is a preset of OpenID Connect, not special code. Nothing
  assumes a hosting company.
- **The server talks to providers, the app doesn't.** The app opens the provider's sign-in page and
  hands what comes back to the server; the server exchanges it, checks it and gives the app a
  **session token** of its own. So the app needs no HTTP client and holds no provider secrets, and
  one implementation per *flow* serves every provider.
- **Identity and keys are separate.** A provider only says who someone is. Encryption keys are made
  by the apps and registered under that identity; changing providers never touches them.

## Configuration

Two settings in `server.toml` (each also a command-line flag, like every other setting); leaving
them out keeps today's server.

| `auth.mode` ↓ / `e2e.mode` → | `off` (default) | `optional` | `required` |
|---|---|---|---|
| `links` (default): share links and join codes | Today's server | Owners may seal a file; its key travels in the link's `#` part (never sent to the server); join codes can't carry a key, so sealed files have none | Every published file is sealed, key in the link |
| `accounts`: signing in is required; people have a role per file | Private server with real sign-in; the server can read files | Owners choose per file; sealed files keep a keyring per device | Every file sealed; keys per account and device |
| `accounts+links`: both; links keep working, a file can demand sign-in | Teams plus share links | Either, per file | Sealed; a link carries the key and still checks sign-in when the file demands it |

```toml
[auth]
mode = "accounts"                 # "links" | "accounts" | "accounts+links"
admins = ["owner@example.com"]    # manage the server like the server key does
allow_emails = []                 # who may sign in (both empty: anyone a provider vouches for)
allow_domains = ["example.com"]
session_days = 30                 # how long a sign-in lasts without being used

[[auth.provider]]
id = "google"                     # what apps show and send; any name
kind = "oidc"
preset = "google"                 # fills issuer and scopes
client_id = "1234-abc.apps.googleusercontent.com"
client_secret_file = "/etc/figcraft-server/google.secret"

[[auth.provider]]
id = "company"
kind = "oidc"
issuer = "https://sso.example.com/realms/design"   # Keycloak, Authentik, Entra ID, Okta, Zitadel…
client_id = "figcraft"
client_secret_file = "/etc/figcraft-server/company.secret"

[[auth.provider]]
id = "tokens"
kind = "external"                 # anything else: LDAP, an in-house SSO, API keys
verify_url = "https://auth.internal/figcraft/verify"
label = "Company token"

[e2e]
mode = "optional"                 # "off" | "optional" | "required"
```

`figcraft-server check` validates the combination; `figcraft-server providers` fetches each
issuer's discovery document and reports what's wrong.

## Identity providers

`crates/auth` (L2, no sockets) holds the types every side shares and the provider trait:

```rust
pub struct Identity {
    pub provider: String,      // the configured provider id
    pub subject: String,       // the provider's stable id for the person
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

pub trait IdentityProvider: Send + Sync {
    fn info(&self) -> ProviderInfo;  // id, label and the flows apps may use
    fn exchange_code(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<Identity, AuthError>;
    fn start_device(&self) -> Result<DeviceStart, AuthError>;
    fn poll_device(&self, device_code: &str) -> Result<Option<Identity>, AuthError>;
    fn verify_token(&self, token: &str) -> Result<Identity, AuthError>;
}

pub trait Fetch: Send + Sync {   // HTTPS, supplied by the server binary
    fn get(&self, url: &str) -> Result<Vec<u8>, AuthError>;
    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Vec<u8>, AuthError>;
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, AuthError>;
}
```

A person is `(provider id, subject)`, never an email alone, so two providers can't collide. The
methods a provider doesn't support return `AuthError::Unsupported`.

| Kind | Flows | How the server checks |
|---|---|---|
| `oidc` | `browser` (authorization code + PKCE, loopback redirect), `device` (RFC 8628) when the issuer has a device endpoint | Discovery document → token endpoint → ID token signature against the issuer's keys (cached, refetched when a key id is new), `iss`, `aud`, `exp`, `nbf`, `iat`; `email_verified` for allow-lists |
| `oidc` + `preset = "google"` | `browser`, `device` | The same code; the preset only fills the issuer and scopes |
| `external` | `token` | POSTs `{"token": …}` to `verify_url`, expects `{"subject", "email"?, "name"?}` (200) or a refusal; reference verifier in `examples/auth-verifier/` |

**Adding a provider**: a config block for any OpenID Connect issuer; an `external` verifier in any
language, with no rebuild; or an `IdentityProvider` implementation in Rust registered with
`figcraft_server::providers::register` for those who want it in the binary.

### Signing in

```
app                                server                          provider
 │ Info ─────────────────────────────▶ │
 │ ◀──────────── Info{providers, flows, e2e}
 │ opens the provider's page (browser + PKCE, redirect to 127.0.0.1:port)
 │ ◀──────────────────────────────────────────────────────────── code
 │ SignIn{Code{provider, code, verifier, redirect_uri}} ──▶ │ exchange, check ───▶ │
 │ ◀──────────── SignedIn{session token, me}
 │ (later connections) SignIn{Session(token)} then Hello / Manage / OpenAccount
```

- `Info` and `SignIn` may come before a connection's first real message (`Hello`, `Manage`, …);
  the connection then carries that person. Old servers don't know them and refuse; the app says
  the server has no accounts.
- **Session tokens** are 256-bit random values; the server keeps their SHA-256 with the person and
  expiry, and they are sent inside messages, never in URLs (like link tokens). Signing out or
  removing a person drops their sessions and disconnects them.
- The device flow (`DeviceStart` → show the code → `DevicePoll`) serves `figcraft-cli`, MCP and
  any app that can't open a browser. The `token` flow sends the pasted token for `external`.
- The engine command `account.sign_in` only *requests* the sign-in UI; over the control channel
  it uses the device flow and returns the code instead (programmatic calls never open dialogs).

### Who gets in

`Policy` (from `[auth]`) runs after any provider: allowed emails and domains (verified emails
only), and admins. With `accounts`, a `Hello` needs a signed-in connection and a role on the file:
**owner** (manages members and links), **editor** or **viewer** (as view links today). Admins and
the server key manage the server. People manage their own files through an **account connection**
(`OpenAccount`): list, publish, members, invites, devices and keyrings.

## Sealed files

### What the server keeps doing, and what moves to the apps

The session server isn't a relay: it keeps each open file's document and checks every batch. On a
sealed file the **structure stays visible and the contents are encrypted**:

| Server job | On a sealed file |
|---|---|
| Order batches, sequence numbers, rebroadcast | Unchanged |
| Id spaces (new node, style, comment ids belong to their author) | Unchanged: ids stay visible |
| Tree rules (one parent, pages have none, only containers hold layers, fractional positions, node cap) | Unchanged: `kind`, `parent` and `position` stay visible |
| Value checks (size, transform, opacity) | Done by every app, the same way (below) |
| `Reject` fixes, catch-up, snapshots, compaction | On ciphertext: the last value per slot |
| Styles, variables, collections, images keyed by name or hash | Keys become `HMAC(entry key, name)` |
| Presence, cursor chat | One sealed blob each; only the "spotlight on" flag stays plain |
| Team libraries | Kept as a sealed blob; checked by the apps after opening |
| File names | Sealed; the app decrypts the list |

**Visible to the server on a sealed file**: the number of layers and their tree, each layer's kind,
which property names change and when, value sizes (padded), who is connected and when.

### Keys

```
file key, epoch n (32 random bytes)
  ├─ HKDF "figcraft value"   → XChaCha20-Poly1305 key for values
  ├─ HKDF "figcraft entry"   → HMAC-SHA256 key for entry names
  ├─ HKDF "figcraft presence"→ key for presence and signals
  └─ HKDF "figcraft meta"    → key for the file name and library archives
```

- A **sealed value** is `epoch (u32) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`; its associated data is
  `file id ‖ epoch ‖ the slot` (node and property, document property, or hashed entry), so the
  server can't move a value to another slot. Plaintexts are padded to 64 B, 256 B, 1 KiB, then
  powers of two.
- **Links mode**: the key is in the link after `#k=` (base64url), which browsers and the app never
  send to a server.
- **Accounts mode**: each app install has a **device key** (X25519 for receiving keys, Ed25519 for
  signing), kept in the OS keychain. The file key is wrapped to every member device with HPKE
  (RFC 9180, X25519-HKDF-SHA256 / ChaCha20-Poly1305) and the server stores the wrapped copies
  (`keyring.json`). Adding someone wraps the current and older epochs for their devices; removing
  someone or a device starts a new epoch for new writes and the server disconnects them.
- **Recovery**: a recovery key (24 words) wraps a copy of the person's keyring; a new device is
  approved from an existing one (a 6-digit comparison) or with the recovery key.

### Same checks everywhere

The server can't check values on a sealed file, so every app checks every batch it opens with the
same rules (`Replica::apply` in a lenient mode): a change that doesn't decrypt or breaks a value
rule is skipped, identically on every app, so all copies stay the same even if a buggy or hostile
editor sends garbage. The rule set is versioned with the protocol; apps with another version are
refused at join.

### What sealing doesn't protect against

- A hostile server can drop, delay or roll back edits, refuse service, or hand out a fake device
  key when someone is added (key-change warnings and safety numbers come in the hardening step).
- A viewer working with a compromised server could forge edits until editors sign their batches
  (hardening step), because viewers hold the file key.
- Anyone holding a sealed share link can read the file (that's what the link is); owners can turn
  links off per file.
- Compromised devices; the local-network sessions an app hosts (unchanged, a trusted network).

## Protocol additions

New message variants are appended (old ones keep their wire numbers), so older apps and servers
keep talking to each other on everything they knew.

| Direction | Message | |
|---|---|---|
| C → S | `Info` | What this server accepts |
| S → C | `Info(ServerInfo)` | Auth mode, providers and their flows, e2e mode, protocol |
| C → S | `SignIn(SignIn)` | `Session`, `Code`, `DeviceStart`, `DevicePoll`, `Token`, `SignOut` |
| S → C | `SignedIn(Me)` / `Device(DeviceCode)` / `SignInPending` | |
| C → S | `OpenAccount` then `Account(AccountReq)` | Files, publish, members, invites, devices, keyrings |
| S → C | `Account(AccountReply)` | |
| C ↔ S | `SealedChanges`, `SealedWelcome`, `SealedReject`, `SealedPresence`, `SealedSignal` | The sealed counterparts of the session messages |

## Crates

| Crate | Layer | Holds |
|---|---|---|
| `crates/auth` | L2 | `Identity`, flows, `IdentityProvider`, `Fetch`, `Policy`, config types; the `oidc` and `external` providers behind the `providers` feature (the server enables it) |
| `crates/collab-seal` | L2 | Key derivation, seal and open, entry hashing, padding, key wrapping |
| `crates/collab-opaque` | L2 | `OpaqueReplica` and `OpaqueServer`: the session server for sealed files |

`crates/collab` gains the new message types (data only); `crates/collab-net` runs `Info` and
`SignIn` before a connection's first message (in the connection's own thread, since providers are
slow) and seals and opens around the client; `apps/figcraft-server` keeps people, sessions,
members and keyrings and builds the providers from its config.

## Steps

1. **This document.**
2. `crates/auth`, `Info`, and the server advertising it (no visible change).
3. OpenID Connect provider, accounts on the server (people, sessions, members, roles).
4. Sign-in in the app and `figcraft-cli` (browser, device, token flows), the Share dialog's people.
5. `external` provider and its reference verifier.
6. `crates/collab-seal`.
7. `crates/collab-opaque` and sealed files on the server.
8. Sealing in the app; sealed links.
9. Sealed files with accounts: keyrings, invites, devices, recovery.
10. Edges (sealed team libraries, CLI and MCP) and hardening (editor signatures, key-change
    warnings).
