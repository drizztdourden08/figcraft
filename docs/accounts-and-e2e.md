# Accounts and end-to-end encryption (draft)

Status: milestone M9 ("accounts and teams" in [`ROADMAP.md`](../ROADMAP.md)). **Steps 2 and 3
are built**: `crates/auth` (the sign-in types, the `IdentityProvider` and `Gate` traits, the
`[auth]` and `[e2e]` settings, and with its `providers` feature the `oidc` and `external` providers
and their registry), `Info` and `SignIn`, and accounts on `figcraft-server`: people and sessions,
members and invites per file, roles in sessions, account connections, admins (see
[`server.md`](server.md#accounts-sign-in)). **Step 4 is built** in the engine and the transport: `account.info`, `account.signIn` (browser with PKCE and a loopback redirect, device code with `account.signInPoll`, token), `account.signOut`, `account.status`, `account.files`, and `collab.members`, `collab.invite`, `collab.setRole`, `collab.removeMember` for the file in front; session tokens are kept with the preferences (like owner tokens) and sent before each hello on that server; publishing while signed in makes the file yours, and members join with a link that carries no secret. The app's screens for it come next. **Step 6 is built**: `crates/collab-seal` (file keys
and keyrings, sealing and opening values and changes, entry ids, device keys and HPKE wrapping,
link keys, recovery keys). **Step 7 is built**: sealed files on `figcraft-server` (`[e2e]` accepts
`off`, `optional` and `required`): the session server for sealed files (`OpaqueReplica` and
`OpaqueServer` in `crates/collab`), the sealed session messages, publishing, storing, compacting
and catching up on sealed files (see *Protocol additions* and [`server.md`](server.md#sealed-files)).
The app doesn't seal yet (step 8). Sections say what is built as the implementation lands. Builds on [`collab-protocol.md`](collab-protocol.md)
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

Two settings in `server.toml`, in its `[auth]` and `[e2e]` sections (unlike the server's other
settings these have no command-line flags: they live only in the file); leaving them out keeps
today's server.

| `auth.mode` ↓ / `e2e.mode` → | `off` (default) | `optional` | `required` |
|---|---|---|---|
| `links` (default): share links and join codes | Today's server | Owners may seal a file; its key travels in the link's `#` part (never sent to the server); join codes can't carry a key, so sealed files have none | Every published file is sealed, key in the link |
| `accounts`: signing in is required; people have a role per file | Private server with real sign-in; the server can read files | Owners choose per file; sealed files keep a keyring per device | Every file sealed; keys per account and device |
| `accounts+links`: both; links keep working (a file demanding sign-in even with a link is not built yet) | Teams plus share links | Either, per file | Sealed; a link carries the key (and would check sign-in when the file demands it, once that is built) |

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
preset = "google"                 # fills issuer and label ("google" or "gitlab")
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

`figcraft-server check` validates the combination and builds each provider without the network
(`Registry::check`): an unknown kind or preset, a missing `issuer` or `client_id`, an unreadable
`client_secret_file`, both secret keys, an unknown flow or a `verify_url` that isn't `https://` are
reported there, not at startup. The issuer itself is first contacted when an app asks what the
server accepts.

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
    fn poll_device(&self, device_code: &str) -> Result<Identity, AuthError>;  // AuthError::Pending until the code is entered
    fn verify_token(&self, token: &str) -> Result<Identity, AuthError>;
}

pub trait Fetch: Send + Sync {   // HTTPS, supplied by the server binary
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError>;
    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Vec<u8>, FetchError>;
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, FetchError>;
}
```

A person is `(provider id, subject)`, never an email alone, so two providers can't collide. The
methods a provider doesn't support return `AuthError::Unsupported`. Providers must not use the
network while being built (only when used), so settings can be checked offline.

An email counts for allow-lists, admins and invites only when the provider says it is verified
(`email_verified`). Some issuers never say (Microsoft Entra ID): `trust_email = true` on a provider
counts its emails as verified when the claim is absent (an explicit `false` still counts as
unverified). It is only safe for an issuer that hands out nothing but emails it has checked, such
as a single-tenant Entra ID or a directory you run; anywhere else someone could claim an address
that isn't theirs.

| Kind | Flows | How the server checks |
|---|---|---|
| `oidc` | `browser` (authorization code + PKCE, loopback redirect) by default; `device` (RFC 8628) only when `flows` lists it, and the issuer has a device endpoint | Discovery document → token endpoint → ID token signature against the issuer's keys (cached, refetched when a key id is new), `iss`, `aud`, `exp`, `nbf`, `iat`; `email_verified` (or `trust_email`) for allow-lists |
| `oidc` + `preset = "google"` or `"gitlab"` | The same | The same code; the preset only fills the issuer and the label |
| `external` | `token` | POSTs `{"provider": …, "token": …}` to `verify_url`, expects `{"subject", "email"?, "email_verified"?, "name"?}` (200) or a refusal (401/403 with an optional `{"error"}`); reference verifier in [`examples/auth-verifier/`](../examples/auth-verifier/) |

**Adding a provider**: a config block for any OpenID Connect issuer; an `external` verifier in any
language, with no rebuild; or an `IdentityProvider` implementation in Rust for those who want it in
the binary: register a factory with `figcraft_auth::registry::Registry::register` and start the
server with `figcraft_server::start_with(&config, &registry)` (and check settings with
`Config::check_with(&registry)`); see [`server-accounts.md`](server-accounts.md#choosing-a-provider).

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

**Visible to the server on a sealed file**: the number of layers and their tree, each layer's kind
*tag* (`frame`, `text`, `page`…: the type name only, enough for the page and container rules; the
kind's data, such as a text's contents, a vector's paths or a page's background, is sealed),
which property names change and when, value sizes (padded), who is connected and when. The tree
properties (`parent`, `position`) stay plain; every other node property value is sealed.

### Keys

Built in `crates/collab-seal` (step 6); the byte formats below are what it implements.

```
file key, epoch n = epoch (u32) ‖ key (32 random bytes) ‖ names (32 random bytes, same in every epoch)
  ├─ HKDF(key)   "figcraft value"    → XChaCha20-Poly1305 key for values
  ├─ HKDF(key)   "figcraft presence" → XChaCha20-Poly1305 key for presence and signals
  ├─ HKDF(key)   "figcraft meta"     → XChaCha20-Poly1305 key for the file name and library archives
  └─ HKDF(names) "figcraft entry"    → HMAC-SHA256 key for entry names
```

HKDF is HKDF-SHA256 with no salt and the label as `info`. The **names secret** is made once with the
file and carried into every new epoch, so entry ids stay the same across epochs (the server keys
entries by them; ids that changed on every rotation would orphan every stored entry). The cost:
someone removed from a file can still compute the ids of names they guess, never read new values.

- A **sealed value** is `epoch (u32 LE) ‖ nonce (24) ‖ ciphertext ‖ tag (16)` (XChaCha20-Poly1305,
  random nonce). The plaintext is framed as `length (u32 LE) ‖ bytes ‖ zeros` and padded to 64 B,
  256 B, 1 KiB, then powers of two (up to 64 MiB); the padding must be canonical to open. Its
  associated data is `"figcraft sealed v1" ‖ file id (u32 LE length ‖ UTF-8) ‖ epoch (u32 LE) ‖
  slot`, the slot being a tag byte and its fields: node id (u64 LE) and property name, document
  property name, entry key (kind byte and entry id or number), entry name, presence or signal
  sender (client id, u32 LE), or meta (`"name"`, `"library"`…). So the server can't move a value
  to another node, property, entry, sender or file. Values of changes are the JSON of the original
  value.
- **Entry ids**: `HMAC-SHA256(entry key, name)` as unpadded base64url (43 characters) for style,
  collection and variable ids and image hashes; comment and dev snapshot keys are numbers and stay
  plain. A sealed `Put`/`Remove` also carries the name sealed for its entry, and apps check that it
  hashes to the id.
- **Links mode**: the key is in the link after `#k=`: unpadded base64url of `epoch ‖ key ‖ names`
  (68 bytes, 91 characters), which browsers and the app never send to a server.
- **Accounts mode**: each app install has a **device key** (X25519 for receiving keys, Ed25519 for
  signing), kept in the OS keychain (64 bytes: X25519 private key ‖ Ed25519 seed). The file key is
  wrapped to every member device with HPKE (RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) /
  HKDF-SHA256 / ChaCha20-Poly1305, `info` = `"figcraft file key v1"`, associated data = the file
  id; `enc (32) ‖ ciphertext (84)`) and the server stores the wrapped copies (`keyring.json`).
  Adding someone wraps the current and older epochs for their devices; removing someone or a
  device starts a new epoch for new writes and the server disconnects them.
- **Recovery**: a recovery key wraps a copy of the person's keyring; a new device is approved from
  an existing one (a 6-digit comparison) or with the recovery key. The recovery key is 32 random
  bytes written as RFC 4648 base32 in 11 groups of 5 (`XXXXX-XXXXX-…`, 55 characters: the key then
  2 checksum bytes from SHA-256, so typos are caught) instead of words: no wordlist to license or
  design. The copy is `nonce (24) ‖ ciphertext ‖ tag`, XChaCha20-Poly1305 with
  HKDF(recovery key, `"figcraft recovery"`) and associated data `"figcraft recovery v1" ‖ context`.

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
| C → S | `Admin::PublishSealed`, `AccountReq::PublishSealed`, `…::RenameSealed` | Publish or rename a sealed file |

### Sealed sessions (built, step 7)

The messages, appended to `ClientMsg`, `ServerMsg`, `Admin` and `AccountReq` (postcard numbers
them by position, so nothing before them moved):

| Message | Fields |
|---|---|
| `ClientMsg::SealedChanges` | `base_seq: u64, batch_id: u64, changes: Vec<SealedChange>` (as `Changes`) |
| `ClientMsg::SealedPresence(Sealed)` | the JSON of a `Presence`, sealed for `Slot::Presence { client: <own client id> }` |
| `ClientMsg::SealedSignal(Sealed)` | a chat `Signal`, sealed for `Slot::Signal { client: <own client id> }`; a spotlight stays a plain `Signal` |
| `ServerMsg::SealedWelcome` | `session, client_id, seq, catch_up: SealedCatchUp, processed, peers, access` (as `Welcome`) |
| `ServerMsg::SealedChanges(SealedAccepted)` | `seq, author, batch_id, changes: Vec<SealedChange>` |
| `ServerMsg::SealedReject` | `batch_id, reason, fixes: Vec<SealedChange>` |
| `ServerMsg::SealedPresence` / `SealedSignal` | `client_id: u32, blob: Sealed`, passed on as the sender sent it |
| `Admin::PublishSealed`, `AccountReq::PublishSealed` | `file: String, name: Sealed, snapshot: Vec<SealedChange>` |
| `Admin::RenameSealed`, `AccountReq::RenameSealed` | `file: String, name: Sealed` |

`SealedChange`, `Sealed`, `EntryKey` and `SealedEntry` live in `crates/collab` (`sealed`, data
only; `figcraft-collab-seal` re-exports them and does the cryptography). How an app drives a
sealed file:

- **The file id.** Values are bound to the file id, so the app picks it before publishing: 16
  random lowercase hex digits (the form the server's own ids have), sent as `PublishSealed`'s
  `file`. A taken id is refused ("that file id is taken"): pick another and seal again. Every slot
  below is sealed for that id (`seal(key, file_id, slot, …)`, `seal_change(key, file_id, change)`).
- **Publishing.** `snapshot` is `Replica::snapshot()` with every change sealed (`seal_change`);
  `name` is the file name sealed for `Slot::Meta { what: "name" }`. The server checks the snapshot's
  structure (it must build a file with a page, within the layer cap) and keeps it. Plain publishing
  is refused with `[e2e] mode = "required"`, sealed publishing with `"off"`. Listings
  (`FileInfo::name`, `OwnedFile::name`, report and owner lists) show a sealed file's name as
  `"sealed:" + base64url(sealed name)` (`sealed_name_text`; `parse_sealed_name` reads it back):
  older apps show that text, newer ones open it.
- **Joining.** A sealed file takes only clients whose `Hello::client_version` holds the word
  `sealed` (`message::SEALED`; others are refused with "open it with a FigCraft that knows sealed
  files"). The welcome is `SealedWelcome`; the app opens its catch-up (`open_change` on each
  change) and hands the plain `Welcome` to its `Client`. Likewise `SealedChanges` → `Changes`,
  `SealedReject` → `Reject` (a change that doesn't open is skipped, the same on every app), and
  the other way `Changes` → `SealedChanges` (`seal_change`), `Presence` → `SealedPresence`, chat →
  `SealedSignal`. `crates/collab-seal/src/sim_tests.rs` does exactly this around `Client` and is the
  reference for the app's sealing layer.
- **Mixing them up.** A plain `Changes` to a sealed file gets `Reject` ("this file is sealed…"), a
  `SealedChanges` to a plain file `SealedReject` ("this file isn't sealed…"); plain presence to a
  sealed file or sealed presence to a plain one is answered `Refused`; a plain chat to a sealed file
  and a sealed one to a plain file are dropped.
- **Team libraries** of a sealed file: `LibraryReq::Publish`'s archive is kept as the bytes it came
  as (seal it for `Slot::Meta { what: "library" }`), each publish the next version; the app checks
  it after opening it.

What the server checks on a sealed batch (`OpaqueReplica::apply`, the rules of `Replica::apply`
that need no values): a created node doesn't exist yet and its id is in the author's space (or was
deleted: undo), a changed one exists; pages and only pages have no parent; no node becomes or stops
being a page (`SetKind`'s tag); only container tags hold layers; positions are valid fractional
keys; no layer goes inside itself; a deletion takes the subtree; the file keeps a page; the layer
cap; `Set` never writes `Kind`, `Parent` or `Position` and `SetTree` only those two; named entries
carry their sealed name; comment ids belong to their author's space (as on plain files; hashed
style, variable and collection ids can't be checked, dev snapshots and images aren't on plain files
either). Value rules (sizes, transforms, opacity) are the apps'. The snapshot it sends is the nodes
in tree order, the document properties, then each keyed list as its readers rebuild it (a whole
list if one was set, the entries there when its order was last set, the order, the entries added
since, removals from the whole list), so a client that joins later opens the same document as one
that saw every batch. `Reject` fixes are the current sealed values of what the batch touched.

## Crates

| Crate | Layer | Holds |
|---|---|---|
| `crates/auth` | L2 | `Identity`, flows, `IdentityProvider`, `Fetch`, `Policy`, config types; the `oidc` and `external` providers behind the `providers` feature (the server enables it) |
| `crates/collab-seal` | L2 | Key derivation, seal and open, entry hashing, padding, key wrapping |

`crates/collab` gains the new message types and the sealed files' data (`sealed`: `Sealed`,
`SealedChange`, `EntryKey`…), and its session server became generic over the synced state
(`SessionServer<S: Synced>`): `Server` is `SessionServer<Replica>` as before, `OpaqueServer` is
`SessionServer<OpaqueReplica>` (the structure of a sealed file, its values sealed), and
`FileServer` is either, what the hub runs per open file. (The draft planned a crate of its own,
`collab-opaque`; sharing the session code kept ordering, id spaces, the log, the journal, presence
and signals one implementation.)

`crates/collab-net` runs `Info` and
`SignIn` before a connection's first message (in the connection's own thread, since providers are
slow) and seals and opens around the client; `apps/figcraft-server` keeps people, sessions,
members and keyrings and builds the providers from its config.

## Steps

1. **This document.**
2. `crates/auth`, `Info`, and the server advertising it (no visible change).
3. OpenID Connect provider, accounts on the server (people, sessions, members, roles).
4. Sign-in in the app and `figcraft-cli` (browser, device, token flows), the Share dialog's people.
5. `external` provider and its reference verifier (built: the provider with step 3, the example
   verifier in `examples/auth-verifier/`).
6. `crates/collab-seal`.
7. **Built**: `OpaqueReplica` and `OpaqueServer` (in `crates/collab`) and sealed files on the server.
8. Sealing in the app; sealed links.
9. Sealed files with accounts: keyrings, invites, devices, recovery.
10. Edges (sealed team libraries, CLI and MCP) and hardening (editor signatures, key-change
    warnings).
