# Accounts and end-to-end encryption (draft)

Status: milestone M9 ("accounts and teams" in [`ROADMAP.md`](../ROADMAP.md)). **Steps 2 and 3
are built**: `crates/auth` (the sign-in types, the `IdentityProvider` and `Gate` traits, the
`[auth]` and `[e2e]` settings, and with its `providers` feature the `oidc` and `external` providers
and their registry), `Info` and `SignIn`, and accounts on `figcraft-server`: people and sessions,
members and invites per file, roles in sessions, account connections, admins (see
[`server.md`](server.md#accounts-sign-in)). **Step 4 is built** in the engine and the transport: `account.info`, `account.signIn` (browser with PKCE and a loopback redirect, device code with `account.signInPoll`, token), `account.signOut`, `account.status`, `account.files`, and `collab.members`, `collab.invite`, `collab.setRole`, `collab.removeMember` for the file in front; session tokens are kept with the preferences (like owner tokens) and sent before each hello on that server; publishing while signed in makes the file yours, and members join with a link that carries no secret. The app's screens are built too: Preferences ▸ Servers lists the remote servers you use (`servers.add`, `servers.remove`, `servers.move`, `servers.list`); the home screen has a page for each, where you sign in (a cached sign-in is checked silently with `account.check`; the browser flow, a device code, or a token field, one per provider), see your files there and their people, put an open file there, and (admins) use the server's admin tools (`admin.people`, `admin.files`, `admin.fileMembers`, `admin.setFileRole`, `admin.addFileMember`, `admin.removePerson`, `admin.endSessions`, `admin.status`); the Share popover shows a file's people. A session the server ends (`SIGNED_OUT`) forgets the sign-in and asks for it again. **Step 6 is built**: `crates/collab-seal` (file keys
and keyrings, sealing and opening values and changes, entry ids, device keys and HPKE wrapping,
link keys, recovery keys). **Step 7 is built**: sealed files on `figcraft-server` (`[e2e]` accepts
`off`, `optional` and `required`): the session server for sealed files (`OpaqueReplica` and
`OpaqueServer` in `crates/collab`), the sealed session messages, publishing, storing, compacting
and catching up on sealed files (see *Protocol additions* and [`server.md`](server.md#sealed-files)).
**Step 8 is built**: sealing in the app (see *Sealing in the app*): `collab.publish {sealed}` and
`collab.share {sealed}` publish a sealed file (with the server's key, as anyone may on an open
server, or as yours when signed in), its links carry the key after `#k=`, the transport seals and
opens around the sync client, and the publisher's app keeps the key with its preferences. **Step 9
is built**: sealed files with accounts (see *Sealed files with accounts*): device keys in the OS
keychain, devices registered per account, each sealed file's key wrapped to every member device in
the server's `keyring.json`, members and your other devices joining with links that carry no key,
new epochs when someone is taken out or a device revoked, and recovery keys. **Step 10 is built**
(hardening, see *Same checks everywhere*, *Editor signatures*, *Safety numbers* and *Edges*): every
app checks a sealed file's values with the same versioned rules and resets what breaks them
instead of failing the session, the server refuses apps with other rules, batches can carry their
device's signature and apps check it against the editors they know (`EditorKeys`),
`account.safetyNumber`, sealed team libraries, and agents joining sealed files by link. **Step 11
is built** (signatures switched on, see *Editor signatures*): on a server with accounts the apps of
a sealed file's owners and editors sign every batch, the server lists their devices
(`AccountReq::EditorKeys`) and marks the file as requiring signatures, every app refuses a batch
that isn't signed by one of those devices, and safety numbers cover other people, with a warning
when their devices change. **Step 12 is built** (server side, protocol and engine; the app's
screens come next): **basic accounts** (`kind = "password"`: usernames and Argon2id password hashes
the server keeps, admins adding people and resetting passwords, people changing theirs, optional
self sign-up, lockouts against guessing, passwords only over TLS), the server's **name** (`About`),
**folders**, **recent files** and **previews** of server files (see *Basic accounts, folders and
previews*). Sections say what is built as the implementation lands. Builds on
[`collab-protocol.md`](collab-protocol.md)
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
| `password` (built into the server, step 12) | `password`, and `signUp` with `allow_signup` | Its own usernames: Argon2id hashes in `accounts/passwords.json`, compared in constant time; wrong passwords lock the username and the address out for a while (see *Basic accounts, folders and previews*) |
| `oidc` | `browser` (authorization code + PKCE, loopback redirect) by default; `device` (RFC 8628) only when `flows` lists it, and the issuer has a device endpoint; `redirect` (the same, for the browser app a server hosts: the page goes to the issuer and comes back to its own address with the code) when `web_redirect_uris` lists pages, exchanged with `web_client_id` when set; a code is exchanged only for the loopback page or a listed page (exact match) | Discovery document → token endpoint → ID token signature against the issuer's keys (cached, refetched when a key id is new), `iss`, `aud`, `exp`, `nbf`, `iat`; `email_verified` (or `trust_email`) for allow-lists |
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

### Same checks everywhere (built, step 10)

The server can't check values on a sealed file, so every app checks every batch it opens with the
same rules, and all copies stay the same even if a buggy or hostile editor sends garbage. The
rules are `figcraft_collab::rules` (`Replica::apply` in `Mode::Sealed`, which the sync client uses
when it joined with `Client::join_sealed`; the engine does for every session whose link carries a
key). **Rules version 1** (`rules1`), one change at a time, in batch order:

1. A node property that doesn't read as its type, or breaks a value rule (the ones a plain file's
   server checks: width and height finite, 0 to 10⁹; transform coefficients finite, within ±10⁹;
   opacity finite, 0 to 1), takes **a new rectangle's value**, whatever the node's kind (opacity 1,
   size 0, no transform, a rectangle's fills…).
2. A node kind that doesn't read becomes the plain kind of its type name (a polygon of 3 sides, an
   empty text, a union…; the type name was already checked against the plain tag the server saw).
3. A document property that doesn't read takes a new document's value; an entry (style, variable,
   comment, image…) whose value doesn't read is removed.
4. Anything else that can't apply (a node that doesn't exist or already does, a layer inside one
   that can't hold layers, a page with a parent, a bad position key…) is skipped. The server
   already refuses those batches by their visible structure.

Nothing fails the session; a batch is no longer all-or-nothing. The sync client counts what it
reset or skipped and says so (`Notice::Checked`: how many values, never which or what).

**Why reset, not skip.** The draft said a bad change would be skipped (the old value kept). That
can't keep copies the same: the server keeps only the latest sealed value of each property, so an
app that joins later (from the server's snapshot) sees the bad value without the history and has
no old value to keep. Resetting to a fixed value gives the same result either way, and the
fallback is a rectangle's rather than the node's own kind's because a kind can change after a bad
value was written (a later joiner sees the value with the current kind). For the same reason the
sealed server's snapshot now creates a node whose kind changed with the kind it was created with,
then sets the current one (`OpaqueReplica`): a new node's unwritten properties start from its
kind's defaults, and a late joiner must start from the same ones as the apps that saw it created
(this was a step 7 bug that an honest kind change, such as flattening a rectangle, could hit). The
property test `every_app_comes_to_the_same_document_whatever_a_hostile_editor_sends`
(`crates/collab-seal`) checks byte-identical documents across apps that saw every batch and one
that joins at the end, with hostile values in a third of the batches.

**Known difference.** An entry whose value doesn't read is removed; if it is put again later it
goes to the end of its list in the apps that saw it removed, where an app that joins later finds it
where it first was: the same entries, in another order, until the list's order is next set.

**Versioned.** Apps announce their rules version in `Hello::client_version` (the word `rules1`,
`message::sealed_rules`); a sealed file refuses a hello without the server's version
(`server::OTHER_RULES`: "this FigCraft checks them differently (update FigCraft…)"), so apps from
before step 10 (which fail the session on a bad value instead) and apps with later rules can't
share a file with different results. Plain files don't look at the word. Changing the rules means
a new `SEALED_RULES` and, as with the protocol, updating servers and apps together.

### Editor signatures (built, steps 10 and 11)

Viewers hold the file key too, so a viewer working with a compromised server could seal changes
and have the server pass them on as an editor's. Editors therefore sign their batches:

- **Signing.** With a device key (`GuestConfig::sealing.signer`), the sealing layer appends the
  device's Ed25519 signature to every batch it sends: `SealedChange::Signature(BatchSignature
  {device, epoch, base_seq, signature})`, the last change of the batch (appended to the
  `SealedChange` enum, so nothing before it moved), over `"figcraft batch v1" ‖ file id (u32 LE
  length ‖ UTF-8) ‖ epoch (u32 LE) ‖ base_seq (u64 LE) ‖ batch_id (u64 LE) ‖ device (32) ‖ the
  batch's other changes (postcard)` (`figcraft_collab_seal::sign_batch`, `batch_message`). Being a
  change of the batch, it travels everywhere the batch does: live, in a reconnect's catch-up, in
  the server's log and journal. The server never keeps it in the file (it isn't in snapshots or
  fixes).
- **Checking.** Every batch that arrives is checked before it opens (`check_batch_at` against
  `GuestConfig::sealing.editors`, an `EditorKeys`): a signature that doesn't hold (changed bytes,
  another file or batch), an unsigned batch where editors must sign (`EditorKeys::required_at`, by
  the batch's sequence number), or a device that isn't an editor's **ends the session** with the
  reason (`BatchRefused`: "…wasn't signed by an editor…", "…signed by a device that isn't one of
  its editors' (yet)…", "…has a signature that doesn't hold…"). Ending rather than skipping: two
  apps' lists of editors can differ for a moment, and skipping on one and not the other would leave
  their copies different. A device the list doesn't know is fetched for once first
  (`EditorKeys::refresh`: an editor added a second ago), then refused.

**Who signs, and the editors' list (step 11).** On a server with accounts:

- `AccountReq::EditorKeys { file }` → `AccountReply::EditorKeys { signed_from: Option<u64>, editors:
  Vec<EditorDevice { account, device, public, recovery }> }`: every registered device of the
  file's owners and editors (revoked ones are gone from the registry, so they are left out; the
  recovery device is listed like the others, so the numbers below match). Any member may ask
  (viewers check signatures too); others, and plain files, get `Failed`.
- **The capability.** Only servers from step 11 answer `EditorKeys` (a step 9 or 10 server can't
  read the request and drops the connection), and those read signed batches. So the transport
  asks it before a sealed session connects (`join::prepare_signing`, for the join of a member's
  link and the join after a sealed publish, signed in, with this device registered there) and signs
  **only when the answer lists this device**; without an answer it sends unsigned batches and takes
  any intact signature or none, exactly as before. An app therefore never sends a signed batch to
  a server that can't read it.
- **The device key** comes from the engine: `LiveLink::device_key(server, Some(DeviceKeys))`,
  handed to the link with the sign-ins (`share_sign_ins`) and whenever the device registers (or is
  found registered) with a server (`device_id`). `collab.publish` signed in registers the device
  first, so a sealed file's first session signs. `NetLink` keeps the keys per server and builds a
  `MemberEditors` (`crates/collab-net/src/editors.rs`) for each join on a server where you are
  signed in.
- **Fetched again** when people or roles change (`collab.invite`, `collab.setRole`,
  `collab.removeMember` → `LiveLink::editors_changed(server)`), at every key sync (`account.syncKeys`,
  in the background every minute), and once for an unknown signer before its batch is refused.
  Each answer goes to the engine as `Event::Editors` (safety numbers, below).

**Signatures required: the rule.** The server marks a sealed file `signed_from = <its latest
sequence number>` (`meta.json`) the first time `EditorKeys` is asked for it (only apps that sign
ask) **while every owner and editor has a registered device** (a recovery device doesn't count).
For a file published by such an app that is at once, at sequence 0. From then on:

1. Every app requires every batch numbered above `signed_from` to be signed by a listed device;
   batches before it (made by apps that didn't sign) are taken as they are.
2. The server refuses an unsigned batch to that file before the session takes it
   (`hub::UNSIGNED`: "this encrypted file takes only changes signed by its editors' devices: update
   FigCraft…"), so an app from before step 11 can't end everyone else's session; it can still
   view the file.
3. Only members with the owner or editor role may edit it: a share link (on `accounts+links`) or
   an admin who isn't in the file joins view-only. Their batches couldn't be signed by an editor's
   device, so the apps would refuse them anyway.

The mark is never taken back (a later editor's app registers its device when it first joins).

**Links-mode sealed files stay unsigned.** Without accounts there is no registry of who edits:
whoever holds an edit link (`#k=`) edits, and there is no identity to bind a device key to. Such
sessions keep `AnyEditor` (intact signatures or none are taken) and send unsigned batches; the
same goes for a share link to a sealed file on an `accounts+links` server joined without being a
member (the app can't ask the server for the editors).

**What is enforced now.** Against a viewer (or anyone holding the key who isn't an editor's
device) working with a compromised server: their forged batches, live and in a reconnect's
catch-up, end every member app's session with the reason, signed with their own device or
unsigned. A revoked device's batches are refused once the apps fetched the editors again (the
next sync, or at once for a device they no longer list). **Not enforced**: the snapshot a joining
app opens (see *What sealing doesn't protect against*), and links-mode files.

The end-to-end tests are `apps/figcraft-server/src/signatures_tests.rs` (a real server with a fake
identity provider: owner and editor sign, an app that doesn't sign is refused by the server, a
share link only views, an editor added later is taken after the refresh, a revoked device's batch
ends the sessions that see it, and a viewer's forged batches, signed or not, are refused by the
apps when a server patched in the test passes them on); `sealing_tests.rs` (`crates/collab-net`)
covers `MemberEditors`.

### Safety numbers (built, step 10)

`figcraft_collab_seal::safety_number(&[DevicePublic])`: 12 decimal digits in three groups of four
(`3271 4339 5047`), from SHA-256 of `"figcraft safety number v1"`, the number of keys (u32 LE)
and each device's public keys (agreement ‖ signing), sorted, duplicates once. Two people compare
the number for one person's devices out of band (in person, on a call): if a server slipped in a
device of its own, the numbers differ.

`account.safetyNumber {server?, account?}` → `{server, account, you, safetyNumber, devices,
changed}`: the number of the devices the server lists for someone: you (`AccountReq::Devices`, the
recovery device included; the same on each of your devices) or, step 11, someone who shares a file
with you (`AccountReq::DevicesOf { account }` → `AccountReply::Devices`; the server refuses others).
Both people see the same number for the same devices.

**Key-change warnings (step 11).** The engine remembers the number it last saw for each (server,
account) in the preferences (`device.seen`: `[{server, account, number}]`, at most 1000), from
`account.safetyNumber` and from each editors' list a session fetched (`Event::Editors`: one number
per owner or editor from their listed devices). The first number seen is trusted; a different one
later is a **key change**: `account.status` lists it (`keyChanges: [{server, account, was, now}]`)
and the app's message says "The devices of someone in an encrypted file changed…: compare safety
numbers". Looking at that person's number (`account.safetyNumber {account}`) clears it
(`changed: true` that once). The list of changes lasts for the run; the numbers last.

### Edges (built, step 10)

- **Sealed team libraries.** `library.publishToServer` and `library.add` / updates of a sealed
  file go through the link's key (`#k=`): the archive is sealed for `Slot::Meta { what: "library"
  }` on its way to the server and opened on its way back (`sealing::library_out`, `library_in`, in
  `manage::library`); the server keeps the sealed bytes as they come (step 7), and an archive that
  doesn't open, or comes unencrypted for a link with a key, is refused (`LIBRARY_WONT_OPEN`).
- **Agents and the command line.** The MCP server (`crates/mcp`, what `figcraft-cli mcp` runs)
  joins with the engine's own transport, so `collab.join {link}` with a sealed link (`#k=` and all)
  works there as in the app: `sealed_team_libraries_and_agents_work_by_the_link`
  (`apps/figcraft-server`) has an agent join, read and edit a sealed file. `figcraft-cli`'s other
  subcommands don't join sessions.

### What sealing doesn't protect against

- A hostile server can drop, delay, reorder or roll back edits, replay an editor's signed batch
  later, refuse service, or hand out a fake device key when someone is added (or add one to your
  account). Safety numbers let people catch that by comparing out of band (`account.safetyNumber`,
  yours or anyone's you share a file with), and apps say when someone's devices changed since they
  last saw them; the first devices an app sees of someone are trusted until compared.
- **Forged edits.** Viewers hold the file key, so a viewer working with a compromised server can
  seal changes. Editor signatures stop forged *batches* (live and in catch-ups) on servers with
  accounts (see *Editor signatures*); links-mode files have no list of editors, so there a viewer
  working with the server can still forge. And **a snapshot isn't signed**: an app that
  joins (or rejoins after a long time away) opens the server's merged copy, and a compromised
  server working with a viewer can put forged values there. Signing each sealed value instead of
  each batch would close that; it isn't built.
- A hostile **editor** (who may edit anyway) can write anything the file can hold; the value rules
  only keep every copy the same and within what the plain server would take, and entries they
  break can end up in another order between apps (see *Same checks everywhere*). An editor (or a
  server) can also end everyone's session with a batch whose signature doesn't hold, once
  signatures are required.
- Anyone holding a sealed share link can read the file (that's what the link is); owners can turn
  links off per file. A view link's holder can't edit through an honest server, but holds the key.
- What the server sees on a sealed file (*What the server keeps doing*): the tree, kind tags,
  which properties change and when, sizes, who is connected.
- Compromised devices; the local-network sessions an app hosts (unchanged, a trusted network).

## Protocol additions

New message variants are appended (old ones keep their wire numbers), so older apps and servers
keep talking to each other on everything they knew.

| Direction | Message | |
|---|---|---|
| C → S | `Info` | What this server accepts |
| S → C | `Info(ServerInfo)` | Auth mode, providers and their flows, e2e mode, protocol (only the flows older apps read: `Password` and `SignUp` are left out) |
| C → S | `About` (step 12) | What the server says about itself |
| S → C | `About(ServerAbout)` | Its name, the whole `ServerInfo` (every flow but `Redirect`), its version; older servers refuse `About`: ask `Info` |
| C → S | `AboutAll` (hosted web app) | `About` with every flow, also `Flow::Redirect` (the browser build asks it; older servers refuse it: ask `About`) |
| C → S | `SignIn(SignIn)` | `Session`, `Code`, `DeviceStart`, `DevicePoll`, `Token`, `SignOut` |
| S → C | `SignedIn(Me)` / `Device(DeviceCode)` / `SignInPending` | |
| C → S | `OpenAccount` then `Account(AccountReq)` | Files, publish, members, invites, devices, keyrings, recovery (step 9: see *Sealed files with accounts*) |
| S → C | `Account(AccountReply)` | |
| C → S | `SignIn::Password`, `SignIn::SignUp`, `AccountReq::ChangePassword`, `Admin::CreateUser`/`ResetPassword`/`RemoveUser`/`Users` | Basic accounts (step 12) |
| C → S | `AccountReq::Folders`/`CreateFolder`/`RenameFolder`/`RemoveFolder`/`MoveFile`/`Browse`/`SetThumbnail`/`GetThumbnail` | Folders, recent files and previews (step 12) |
| C ↔ S | `SealedChanges`, `SealedWelcome`, `SealedReject`, `SealedPresence`, `SealedSignal` | The sealed counterparts of the session messages |
| C ↔ S | `SealedChange::Signature` (the last change of a sealed batch) | An editor device's signature of the batch (step 10) |
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

### Sealing in the app (built, step 8)

- **Where it happens.** In the transport (`crates/collab-net`, `sealing.rs`), shared by the native
  guest and the browser driver: what the engine's sync client sends is sealed on its way out
  (`Changes` → `SealedChanges`, `Presence` → `SealedPresence` with the app's client id once the
  welcome said it, a chat `Signal` → `SealedSignal`; a spotlight stays plain) and what arrives is
  opened (`SealedWelcome`, `SealedChanges`, `SealedReject` → `Welcome`, `Changes`, `Reject`;
  `SealedPresence` and `SealedSignal` → plain ones with the sender's id). The engine only ever sees
  plain messages. `message::client_version()` announces `sealed`.
- **Skipping what doesn't open.** A change that doesn't open (a wrong key, changed bytes, an entry
  name that doesn't hash to its id) is left out of its batch and the rest is applied. The server
  orders every batch and sends everyone the same bytes, and opening is deterministic (the same
  keyring, file id and slot open a value or don't), so every app leaves out exactly the same
  changes, in the same place: their copies stay the same. Presence or a chat that doesn't open is
  dropped. A welcome whose document opens to nothing means the key is wrong: the join ends ("The
  link's key doesn't open this file").
- **Mismatches.** Without a key, a sealed welcome ends the join ("join it with its whole link,
  including the key after #k="); join codes can't carry the key, so the app makes none for sealed
  files (their share links only). With a key, a plain welcome or plain changes end the join (a
  server that hands out a file meant to be sealed in the clear isn't trusted with it), and plain
  presence and chat are dropped.
- **Links mode.** The key travels in the link's fragment:
  `figcraft://join?server=…&file=…&token=…#k=…` (a member's link on a server with accounts:
  `…&file=…#k=…`). `Invite` parses it into `key`; it is never in the WebSocket request, a hello, an
  error or `Debug`.
- **Publishing.** `collab.publish {server, sealed?}` (and `collab.share {sealed?}` online): `true`
  seals (refused before anything is sent when the server's `Info` says `e2e` is `off`, or the
  server is older than accounts), `false` doesn't, and without it the file is sealed when the
  server says `required`. The app makes a `FileKey`, picks a 16-hex-digit file id, seals
  `Replica::snapshot()` and the name for it, and publishes with `Admin::PublishSealed` (server key,
  or open hosting) or `AccountReq::PublishSealed` (signed in), with a new id when the server says
  the id is taken; then it joins the file sealed. `Published`'s links (and the links
  `collab.share` makes) end with `#k=…`.
- **Keys kept by the publisher.** The engine keeps each published
  sealed file's key with the preferences (`Prefs::file_keys`: server, file id, the `k=…` fragment;
  passwords like owner tokens: on this computer only, in no command result other than the share
  links, not in `Debug`). Joining a link without a fragment adds the kept key, so the owner opens
  their files from `account.files` (`figcraft://join?server=…&file=…`) on this computer.
- **Names.** `account.files` and `collab.files` open a sealed file's listed name
  (`parse_sealed_name`) with the kept key or the record's link and say `sealed: true`; without a
  key the name is "Encrypted file". `collab.manageFile {action: "rename"}` seals the new name
  (`RenameSealed`); `createLink` adds the key to the new link. `collab.peers` says `sealed: true`
  for a sealed session.
- **Left for later.** (Keys for members and your other devices: step 9, below. A hostile editor's
  value that breaks a value rule no longer fails the session, and sealed team libraries work: step
  10.)

### Sealed files with accounts (built, step 9)

On a server with accounts and sealed files, nobody needs a link with `#k=`: the key moves between
a person's devices and to the members of a file through the server, wrapped so the server can't
open it.

**Device keys** (`crates/engine/src/devices.rs`). Each install has one `DeviceKeys`, made the first
time it is needed (registering, joining a sealed file, publishing one). Its 64-byte secret is kept
in the OS keychain (`crates/collab-net/src/keychain.rs`, the `keyring` crate: the Windows Credential
Manager, the macOS keychain, the Secret Service on Linux and the BSDs; service `FigCraft`, user
`device-key`), which the desktop app installs (`session.keys.keychain`). Where there is none (the
browser build, `figcraft-cli` and the MCP server, another OS, no Secret Service running, a keychain
that refuses: logged), the secret is kept with the preferences (`device.secret`, base64url):
**weaker**, as anyone who can read the preferences file has it. `account.devices` says which
(`keyStore`). The public keys are registered with each server (`RegisterDevice`), which gives the
device an id there (`d` and 16 hex digits); the preferences keep `device.registered`
(`[{server, device, public}]`, the X25519 key it was registered with: other keys register again)
and `device.name` (default "FigCraft on <computer name>").

**Requests**, appended to `AccountReq` and `AccountReply` (everything before them keeps its
number); the server answers `Failed` to all but `Keyring` when `[e2e] mode` is `"off"`:

| Request | Answer | |
|---|---|---|
| `RegisterDevice { name, public: DevicePublic, recovery }` | `Device { id }` | The same public keys again: the same id (the name updated). At most 10 devices per person; keys registered to someone else are refused |
| `Devices` | `Devices(Vec<DeviceInfo>)` | `{id, name, public, created, seen, recovery}` |
| `RevokeDevice { device }` | `Done` | Its copies go from every sealed file you are in, and those files want a new epoch |
| `Keyring { file }` | `Keyring { sealed, epochs, wrapped: Vec<KeyWrap> }` | Members (and admins): whether the file is sealed, every epoch it has, and the copies wrapped to your devices (`{epoch, device, wrapped}`) |
| `PutKeys { file, epoch, rotate, wrapped: Vec<(device, Wrapped)> }` | `Done` | Copies for member devices: owners and editors wrap for anyone in the file, everyone for their own devices, and only for an epoch one of their devices holds; a device that has a copy keeps it. `rotate`: owners start epoch `epoch` (the newest + 1, or any for a file with no keyring yet), refused when it exists ("another owner started it") |
| `PendingKeys` | `PendingKeys(Vec<PendingFile>)` | Per sealed file you are in: `{file, epoch (newest, or none), rotate, wanted: [{epoch, device, public}]}`: the member devices that lack a copy you may make of an epoch you hold, and for owners of a file that wants a new epoch (or has no keyring) every member device with the next epoch |
| `PutRecovery { device, sealed }` / `GetRecovery` | `Done` / `Recovery(Option<RecoveryCopy>)` | Your recovery copy (`{device, sealed, created}`), for your recovery device |

`DevicePublic` and `Wrapped` moved to `figcraft_collab::sealed` (data only, as `Sealed`);
`figcraft-collab-seal` re-exports them. Removing a member (or someone leaving, or an admin taking a
person off the server) drops their devices' copies of a sealed file and marks it `rotate`.

**Files on the server** (all JSON, written atomically):

```text
<data>/accounts/devices.json   [{"id": "d0123456789abcdef", "account": "a…", "name": "FigCraft on LAPTOP-7",
                                 "public": {"agreement": "<base64url 32 B>", "signing": "<base64url 32 B>"},
                                 "created": 1760000000, "seen": 1760000000, "recovery": true (only when)}]
<data>/accounts/recovery.json  [{"account": "a…", "device": "d…", "sealed": "<base64url>", "created": …}]
<data>/files/<id>/keyring.json {"rotate": true (only when),
                                "epochs": {"0": {"d0123456789abcdef": {"enc": "<base64url 32 B>",
                                                                       "ciphertext": "<base64url 84 B>"}}}}
```

At most 1024 epochs per file and 5000 copies per request (and per `PendingKeys` answer).

**Publishing sealed, signed in.** As in step 8 (`AccountReq::PublishSealed`); once the file is
there the app syncs keys in the background: the file has no keyring yet, so the server lists every
member device (yours) and the app wraps the key it just made for them with `PutKeys { rotate: true
}` (epoch 0).

**Joining with a member's link** (no `#k=`, no token: `account.files`, `collab.openFile`, a link an
owner sent). Signed in, the app asks `Keyring { file }` first: a plain file joins as before; a
sealed one opens the copies wrapped to this device (registering it first) and joins with the keys
added to the link it hands the transport (`#k=…&k=…`, every epoch). A copy that doesn't open, or
whose key says another epoch, is skipped. Without every epoch of the file (a new device, a member
just invited), the join doesn't start: the session shows `status: failed`, `reason` `WAITING_FOR_ACCESS`
("Waiting for access: … its key hasn't been shared with this device yet…") and
`waitingForAccess: true` (`collab.peers`), and the next key sync (`account.syncKeys`, in the
background every minute) joins it by itself once an owner's or editor's app has wrapped for it, if
its tab is in front (or join again). A server older than keyrings: the join goes on as in step 8.

**Syncing keys** (`account.syncKeys {server? | all?}`; after a sealed publish, `collab.invite` and
`collab.removeMember`, after a removal elsewhere is noticed, and every minute in the background
for every server you are signed in to): registers this device, asks `PendingKeys`, and for each
file wraps the epochs this device holds for the devices that want them ("the next owner or editor
app online wraps the key"). For a file that wants a new epoch an owner's app makes it
(`FileKey::rotate`: a new key, the same names secret), wraps it for every member device left with
`PutKeys { rotate: true }`, keeps it, and hands it to its open sessions of the file
(`LiveLink::rekey`: the transport's keys are shared with the session's invite, `collab_net::invite::Keys`,
so the next writes are sealed with the newest epoch). It also refreshes the keys of every sealed
session open on that server and retries the joins waiting for access. A background run that
starts again with the server's answers makes the same new key (kept until it is on the server),
not another.

**Others' apps follow a new epoch.** A change sealed with an epoch newer than every key a session
holds ends that session (`NEW_EPOCH`, "This file's key changed…: getting the new key") instead of
being skipped (an app skipping what everyone else opens would drift apart); the app fetches the
keyring and joins again by itself. If the server has no such epoch, the change was damaged (a
hostile editor): the session stays failed with `NO_SUCH_EPOCH` (signed batches, step 10, tell such
an editor apart once the app requires signatures). Someone taken out is disconnected by the server and can't join again; the keys they kept
open nothing written after.

**Recovery.** `account.recoveryKey {server?, replace?}` makes a **recovery device**: keys of its
own, registered as one of your devices with `recovery: true`, so file keys are wrapped to it like to
any other device (it syncs at once, then whenever an owner or editor syncs). Its secret is sealed
with a new `RecoveryKey` (associated data `"figcraft recovery v1" ‖ "figcraft recovery device|" ‖
account id`) and kept on the server (`PutRecovery`). The command's result carries the recovery key
(`XXXXX-…`, 11 groups of 5) **only when it makes one**: the one exception to "no secret in a
result", like an owner token shown once; the person writes it down, and neither the app nor the
server keeps it. Asked again it says `created: false`; `replace: true` makes a new one and revokes
the old recovery device (its files start a new epoch). `account.recover {server?, recoveryKey}` on
a new device opens the copy, checks that the recovery device is still registered with those keys,
registers this device, unwraps every file key wrapped to the recovery device and wraps it for this
one (`PutKeys`, own device). **Not built**: approving a new device from an existing one with a
6-digit comparison (the second device waits for an owner or editor app instead, or uses the recovery
key).

**Commands** (additive; `crates/engine/src/devices.rs`):

| Command | Result |
|---|---|
| `account.devices {server?, name?}` | `{server, device, keyStore: keychain \| preferences, devices: [{id, name, created, seen, recovery, thisDevice}]}` |
| `account.revokeDevice {server?, device}` | `{revoked, thisDevice, rotated: [file]}` |
| `account.recoveryKey {server?, replace?}` | `{server, created: true, device, recoveryKey, wrapped}` or `{server, created: false, device, made}` |
| `account.recover {server?, recoveryKey}` | `{server, device, recovered, files: [file]}` |
| `account.syncKeys {server? \| all?}` | `{server, wrapped, rotated, refreshed, joined, errors}` (`all`: `{servers: […]}`) |
| `account.safetyNumber {server?, account?}` (steps 10, 11) | `{server, account, you, safetyNumber, devices, changed}` |

**What the UI should show.** In the account panel: your devices (`account.devices`, this one
marked, the recovery device as "Recovery key"), each with Revoke; a warning when `keyStore` is
`preferences` ("this device's key is kept with FigCraft's settings, not the system keychain");
"Make a recovery key" (`account.recoveryKey`), showing the key once with "write it down: it is the
only way back in if you lose every device" and a confirmation before closing; "Use a recovery key"
(`account.recover`) on a device with no access. In the file: while `waitingForAccess`, a waiting
state instead of the error colour ("Waiting for access: an owner or editor needs to open FigCraft",
with Try again = `collab.join` again), which turns into the file on its own. Nothing to show for
syncing (it is silent; its errors are logged).

**Limits.** A revoked device's sessions aren't ended by the server (sessions are per person, not
per device): sign it out too. A hostile server can still hand out a fake device key when someone
is added (safety numbers let people check, and apps warn when someone's devices change). Until a member's app has synced, the writes of
members who haven't picked up a new epoch are sealed with the old one (readable by the person
taken out, should they get the server's data).

### Basic accounts, folders and previews (built, step 12)

**Three kinds of server**, as apps show them (`ServerInfo::access()`, `account.info`'s `access`):
**open** (`auth.mode = "links"`, also spelled `"open"`: nobody signs in, a share link or a join code
is the access: every server before accounts), **basic** (usernames and passwords the server keeps)
and **SSO** (an identity provider: Google, Keycloak, an `external` verifier…), or basic and SSO
together. No new mode: basic accounts are a provider kind, so `accounts` and `accounts+links` work
with them as with any provider.

**Basic accounts** (`[[auth.provider]] kind = "password"`, at most one per server; it takes only
`id`, `label` and `allow_signup`). The server builds it itself (its usernames live in the data
directory), so it isn't in the `Registry`. Any provider may offer the password flow: the trait
gained `verify_password(username, password)` and `sign_up(username, password, email, name)`, both
`Unsupported` by default, so a kind of your own (an LDAP directory, say) offers `Flow::Password` and
gets the same lockouts.

- **Wire** (appended): `Flow::Password { label }`, `Flow::SignUp`; `SignIn::Password { provider,
  username, password }`, `SignIn::SignUp { provider, username, password, email?, name }`; `Debug`
  of `SignIn` leaves every secret out (the token, code, verifier and password). Apps from before
  them can't decode those flows, so the server's answer to `Info` leaves them out
  (`ServerInfo::for_older_apps`; the provider stays listed with no flow, which older apps report as
  not usable from them) and only `About` carries them.
- **Identity**: `(provider id, username)`; the username is lowercase, 1–64 letters, digits, `.`,
  `-`, `_` or `@`. An email an admin gave counts as verified (allow-lists, admins and invites go by
  it); one typed when signing up doesn't, so a server whose allow-lists aren't empty refuses
  sign-ups (an admin adds those people).
- **Hashes**: Argon2id (RustCrypto's `argon2`), 19 MiB, 2 passes, 1 lane (OWASP's recommendation),
  a 128-bit salt, kept as a PHC-style string that records its parameters; compared in constant
  time; an unknown username is checked against a dummy hash so it takes as long.
- **Guessing**: 5 wrong passwords in a row lock a username out for 15 minutes, 20 from one address
  (an IPv6 /64) lock the address out; an address tries at most 10 a minute and signs up at most 5
  times an hour. In memory, like join codes' counters. A wrong username and a wrong password say the
  same.
- **Rules**: 10 to 256 characters, no control characters, not the username. Generated passwords
  (an admin adding someone without one, or resetting) are 20 characters from a look-alike-free
  alphabet (about 100 bits), shown once and marked temporary until changed.
- **Only over a private channel**: the hub tells the gate where a step came from
  (`Gate::sign_in_from(req, Origin { ip, private })`, `private` when the connection is from the
  server's own machine or through `trusted_proxy`, which terminates TLS); the server refuses a
  password on any other connection, since it speaks plain `ws://` itself. The app refuses to send
  one to a `ws://` address on another machine (`manage::PASSWORD_IN_CLEAR`).
- **Management**: `Admin::CreateUser { username, email?, name, password? }` (a password made when
  none is given) and `Admin::ResetPassword { username }` answer `AdminReply::User { username,
  password? }` (shown once; a reset ends the person's sessions and lifts their lockout);
  `Admin::RemoveUser` ends their sessions and the password (their account and files stay until
  `Admin::RemovePerson`, which also takes the username); `Admin::Users` lists `UserInfo`.
  `AccountReq::ChangePassword { old, new }` (a wrong `old` counts like a wrong sign-in). Passwords
  travel as `Secret`, whose `Debug` shows nothing. CLI: `figcraft-server users [list|add|reset|remove]`.
- **Engine**: `account.signIn {username, password}` (the `password` flow; never echoed),
  `account.signUp`, `account.changePassword`.

**The server's name**: `name = "…"` in `server.toml` (at most 80 characters), in `ServerAbout`
(`ClientMsg::About` → `ServerMsg::About`, appended; `ServerInfo` itself is unchanged so older apps
decode `Info` as before). Apps show the name people gave a server first, then this, then its
address. `account.info` returns it as `name`.

**Folders**: a file has **one** folder (`meta.json`'s `folder`, names joined by `/`, at most 8 deep,
64 characters a name, 256 in all), the same for everyone in it; owners and editors move it
(`MoveFile`). Folders aren't objects of their own: a folder exists while a file is in it (or
below), and a person sees the folders of the files they're in with their parents. An empty folder
someone made (`CreateFolder`) is theirs (`folders.json`): others see it once a file they're in is
put there. `RenameFolder` moves the files in it that you may edit (and your own empty folders);
`RemoveFolder` removes your empty folders, only when no file you're in is in it. Folder names are
plain text on the server, also for sealed files.

**Recent files**: when someone signed in joins a file, the server notes when (`recents.json`, the
newest 100 per person, written at most once a minute per file and person). `AccountReq::Browse`
answers `AccountReply::Browse { files: [FileEntry { info, role, folder, sealed, thumbnail: when it
was set?, opened: when you last opened it? }], folders }`; `AccountReq::Files` stays as it was.

**Previews**: `AccountReq::SetThumbnail { file, image }` (owners and editors; at most 256 KiB): a
PNG for a plain file, and for a sealed file the PNG sealed for slot `Meta { what: "thumbnail" }`
with the file's key: the server keeps it as it comes (`thumbnail.bin`), checking only that it is a
PNG (plain) or a sealed value (sealed). `GetThumbnail` (everyone in the file) answers
`AccountReply::Thumbnail { image, set }`. The app renders the first page at 256 pixels on its
longest side and sends it after publishing to a server it is signed in to, and every two minutes
for a file it edits there when the document changed (`account.uploadThumbnail` sends one now);
`account.thumbnail` gives it back as base64 PNG (opened with the key kept here for a sealed file,
else no picture). `account.browse`, `account.folders`, `account.createFolder`,
`account.renameFolder`, `account.removeFolder` and `account.moveFile` are the rest.

## Crates

| Crate | Layer | Holds |
|---|---|---|
| `crates/auth` | L2 | `Identity`, flows, `IdentityProvider`, `Fetch`, `Policy`, config types; the `oidc` and `external` providers behind the `providers` feature (the server enables it) |
| `crates/collab-seal` | L2 | Key derivation, seal and open, entry hashing, padding, key wrapping, keyrings in link fragments (`ring_fragment`) |

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
4. Sign-in in the app and `figcraft-cli` (browser, device, token flows), the Share dialog's people. *(Built: see the status above.)*
5. `external` provider and its reference verifier (built: the provider with step 3, the example
   verifier in `examples/auth-verifier/`).
6. `crates/collab-seal`.
7. **Built**: `OpaqueReplica` and `OpaqueServer` (in `crates/collab`) and sealed files on the server.
8. **Built**: sealing in the app; sealed links.
9. **Built**: sealed files with accounts: keyrings, invites, devices, recovery (device approval
   with a 6-digit comparison not yet).
10. **Built**: edges (sealed team libraries, CLI and MCP) and hardening (the same versioned value
    rules in every app, editor signatures behind `EditorKeys`, safety numbers).
11. **Built**: signatures switched on for sealed files on servers with accounts (`EditorKeys`,
    signing and checking in the app, files that require signatures), other people's safety
    numbers and key-change warnings.
12. **Built**: basic accounts (usernames and passwords), the server's name, folders, recent files
    and previews (server, protocol and engine; the app's screens next).
