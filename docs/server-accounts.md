# Setting up a server with accounts

This guide takes a running `figcraft-server` (see [`server.md`](server.md)) and turns on
**accounts**: people sign in with an identity provider (Google, your company's Keycloak or Entra ID,
GitLab, a verifier of your own…) and each file has members with a role. The design behind it is in
[`accounts-and-e2e.md`](accounts-and-e2e.md); this page is for the operator.

- [What accounts give you](#what-accounts-give-you)
- [Before you start](#before-you-start)
- [Choosing a provider](#choosing-a-provider)
- [Step by step](#step-by-step): [Google](#google), [Keycloak](#keycloak),
  [other OpenID Connect issuers](#other-openid-connect-issuers),
  [an external verifier](#an-external-verifier)
- [The settings](#the-settings)
- [Who may sign in](#who-may-sign-in)
- [Day to day](#day-to-day)
- [Data and backups](#data-and-backups)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)

## What accounts give you

`auth.mode` in `server.toml` says how people get into files:

| Mode | How people get in |
|---|---|
| `links` (default) | Share links and join codes, as described in [`server.md`](server.md). No sign-in. |
| `accounts` | Signing in is required. A person opens a file only when they are one of its members (or an admin). Share links and join codes don't work. |
| `accounts+links` | Both: members sign in, and a file's owners can still make share links and join codes; someone with a link gets in without signing in. |

Each member of a file has a **role**:

- **owner**: edits, invites people, changes their roles, removes them, renames or removes the file,
  and (with `accounts+links`) makes and revokes its share links. A file always keeps at least one
  owner. Whoever publishes a file is its owner.
- **editor**: edits.
- **viewer**: views; the server refuses their changes, like a view link's.

**Admins** (`admins = [...]`, by email) manage the server the way the server key does, from the
app, without the key. They also open every file (to edit) and manage any file's members as if they
owned it.

What stays the same: the server key still manages the server (`figcraft-server key`, `files`,
`links`, `reports`, `block-ip` and the other commands work as before), the plugin directory and
team libraries work as before, and files are stored unencrypted on the server unless they are
sealed (`[e2e]`, see [`server.md`](server.md#sealed-files)). The desktop app's own sessions
(hosting from the app, on the local network) don't change.

A file published with the server key has no members. With `accounts` only admins can open it until
an admin invites its owner; with `accounts+links` its links keep working. Files published before
you turned accounts on are in the same position.

`open_publish` (a server open to the public) can't be combined with accounts: `check` refuses it.

## Before you start

- A server running as in [`server.md`](server.md), behind a TLS reverse proxy (Caddy or nginx), with
  `public_url` set to the address people use (`wss://figcraft.example.com/`). `install.sh` sets all
  of this up; its settings are in `/etc/figcraft-server/server.toml` and its data in
  `/var/lib/figcraft-server`. Use `install.sh --private` (or set `open_publish = false`): a public
  server can't have accounts.
- **The server must be able to reach the provider over HTTPS.** It fetches the issuer's discovery
  document and keys, and exchanges sign-in codes, itself. The systemd unit shipped in
  `packaging/server/figcraft-server.service` allows network only to this machine
  (`IPAddressAllow=localhost`, `IPAddressDeny=any`) as long as there are no accounts. **After
  setting `auth.mode`, run `install.sh` again** (with the same options): it sees accounts in
  `server.toml` and writes the drop-in
  `/etc/systemd/system/figcraft-server.service.d/outbound.conf`, which clears both settings and
  restarts the server (it removes the drop-in again if you turn accounts off). Without
  `install.sh`, write the same drop-in yourself:

  ```sh
  sudo systemctl edit figcraft-server
  ```

  ```ini
  [Service]
  IPAddressAllow=
  IPAddressDeny=
  ```

  (an empty value clears the list). Any outbound firewall must let the server reach the issuer on
  port 443. A sign-in that fails with `Operation not permitted` in the log means the limit is still
  in place.
- The server checks the provider's certificate against Mozilla's list of root authorities built
  into it, so an issuer (or verifier) with a certificate from a public authority such as Let's
  Encrypt just works. For an issuer behind a **private authority** (a company CA), give the server
  that authority's certificate as a PEM file in `FIGCRAFT_CA_FILE`, as for the app; it is trusted
  in addition to the built-in list:

  ```sh
  sudo install -m 644 company-ca.pem /etc/figcraft-server/ca.pem
  sudo systemctl edit figcraft-server     # add the two lines below
  ```

  ```ini
  [Service]
  Environment=FIGCRAFT_CA_FILE=/etc/figcraft-server/ca.pem
  ```

  (In Docker: `-e FIGCRAFT_CA_FILE=/ca.pem -v /etc/figcraft-server/ca.pem:/ca.pem:ro`.) A file the
  server can't read, or one without a certificate, stops it at startup with the reason. A verifier
  on the same machine can use plain `http://127.0.0.1:…` instead.
- The server's clock must be right (`timedatectl` shows whether it is synchronised): sign-ins are
  checked against their expiry with 120 seconds of leeway.

## Choosing a provider

A **provider** says who someone is; the server then decides whether they may sign in and what
they may open. A person is the pair *(provider id, the provider's id for them)*, never an email
alone: the same email through two providers is two accounts. You can configure up to 32 providers;
apps show them all.

| You have | Use | Kind |
|---|---|---|
| Google Workspace or Google accounts | Google's OpenID Connect | `oidc` with `preset = "google"` |
| GitLab.com accounts | GitLab's OpenID Connect | `oidc` with `preset = "gitlab"` |
| Keycloak, Authentik, Microsoft Entra ID, Okta, Auth0, Zitadel, a self-hosted GitLab… | Any OpenID Connect issuer | `oidc` with `issuer = "https://…"` |
| LDAP, an in-house SSO, API keys, anything else | A small web service you run that says who a token is | `external` with `verify_url` |
| Something that must live inside the server binary | Your own Rust code | a kind you register |

**OpenID Connect** (`oidc`) is the usual choice. Apps sign in through the system browser: the app
opens the issuer's sign-in page with PKCE and a **loopback redirect**
(`http://127.0.0.1:<a free port>/`, a port the app picks each time), receives the code there and
hands it to the server; the server exchanges it, checks the ID token (its signature against the
issuer's published keys, issuer, audience, expiry) and keeps the client secret, which never leaves
the server. So you register a **desktop (native) application** with the issuer, one that allows a
loopback redirect on any port. The device flow (a code typed on another device, for
`figcraft-cli` and agents) is offered only when `flows` lists `"device"`, and needs the issuer's
device endpoint.

**External verifier** (`external`): people paste a token (a password, an API key, a one-time code
from your SSO); the server POSTs it to your `verify_url` and your service answers who it is. Any
language, no rebuild. See [An external verifier](#an-external-verifier).

**A kind of your own**: a build of the server can add a provider kind written in Rust. Implement
`figcraft_auth::IdentityProvider`, register a factory for it, and start the server with
`figcraft_server::start_with` instead of `figcraft_server::start`:

```rust
use std::path::Path;

use figcraft_auth::registry::Registry;
use figcraft_auth::{AuthError, Flow, Identity, IdentityProvider, ProviderInfo};

struct Directory { id: String, url: String }

impl IdentityProvider for Directory {
    fn info(&self) -> ProviderInfo {
        ProviderInfo { id: self.id.clone(), label: "Directory".into(), flows: vec![Flow::Token { label: "Directory password".into() }] }
    }
    fn verify_token(&self, _token: &str) -> Result<Identity, AuthError> {
        // Ask your directory at self.url who the token is.
        Err(AuthError::Refused("not implemented".into()))
    }
}

fn main() -> Result<(), String> {
    let mut registry = Registry::builtin(); // keeps "oidc" and "external"
    registry.register("directory", |cfg, _fetch| Ok(Box::new(Directory { id: cfg.id.clone(), url: cfg.verify_url.clone() })));
    let cfg = figcraft_server::config::Config::load(Path::new("/etc/figcraft-server/server.toml"))?;
    let _running = figcraft_server::start_with(&cfg, &registry)?;
    // ...serve until told to stop, as apps/figcraft-server/src/main.rs does.
    Ok(())
}
```

`kind = "directory"` in `[[auth.provider]]` then builds it. A factory gets that provider's settings
(the same keys as below: unknown keys are still errors, so reuse `verify_url`, `issuer`,
`client_id` and the others) and the server's HTTPS client. Methods it doesn't implement answer
`AuthError::Unsupported`. A factory must not use the network while building (only when the
provider is used): settings are checked by building every provider with a client that refuses all
requests (`Registry::check`, which `Config::check_with(&registry)` runs).

## Step by step

Each recipe ends with a `[[auth.provider]]` block. Put it in `/etc/figcraft-server/server.toml`
with an `[auth]` section (see [The settings](#the-settings)), then check and restart:

```sh
sudo -u figcraft figcraft-server --config /etc/figcraft-server/server.toml check
sudo systemctl restart figcraft-server
journalctl -u figcraft-server -n 20
```

The first time you turn accounts on, run `install.sh` again instead of the restart (or add the
drop-in by hand), so the server may reach the provider: see [Before you start](#before-you-start).

Keep secrets out of `server.toml` (which is readable by everyone on the machine): write them to a
file only the server can read and name it with `client_secret_file`:

```sh
sudo install -m 600 -o figcraft -g figcraft /dev/null /etc/figcraft-server/google.secret
sudoedit /etc/figcraft-server/google.secret      # paste the secret, save
```

### Google

1. In the [Google Cloud console](https://console.cloud.google.com/), pick or create a project.
2. **APIs & Services ▸ OAuth consent screen**: set the app name, a support email and your
   developer contact. Choose **Internal** if everyone is in your Google Workspace organisation
   (only its accounts can sign in), else **External**. An external app that isn't verified by
   Google lets in only the **test users** you list there (up to 100), and shows people a warning
   page; that is fine for a team. The scopes needed (`openid`, `email`, `profile`) don't need
   Google's verification.
3. **APIs & Services ▸ Credentials ▸ Create credentials ▸ OAuth client ID**, application type
   **Desktop app**. Desktop clients accept a loopback redirect on any port, which is what the app
   uses (`http://127.0.0.1:<port>/`); there are no redirect URIs to enter. A *Web application*
   client would refuse it (`redirect_uri_mismatch`).
4. Copy the **client ID** into `server.toml` and the **client secret** into
   `/etc/figcraft-server/google.secret` (as above). Google requires the secret even for desktop
   clients; the server sends it, the apps never see it.

```toml
[[auth.provider]]
id = "google"
kind = "oidc"
preset = "google"                 # issuer https://accounts.google.com, label "Google"
client_id = "1234-abc.apps.googleusercontent.com"
client_secret_file = "/etc/figcraft-server/google.secret"
flows = ["browser"]               # the default; see below
params = [["prompt", "select_account"]]   # optional: let people pick among their Google accounts
```

**The device flow with Google.** Google offers the device flow only to clients of type **TVs and
Limited Input devices**, and one `[[auth.provider]]` has one client. So with a Desktop app client
keep `flows = ["browser"]` (the default). To offer the device flow too, create a second client of
that type and a second provider with it and `flows = ["device"]`. Mind that it is a separate
provider id, so a person who signs in through both gets two accounts with separate memberships
(invites by email go to whichever account signed in first).

### Keycloak

1. Create (or pick) a **realm**, for example `design`. Its issuer is
   `https://sso.example.com/realms/design` (older Keycloak versions, before 17, put `/auth` before
   `/realms`). Open `<issuer>/.well-known/openid-configuration` in a browser to be sure.
2. **Clients ▸ Create client**: type **OpenID Connect**, client ID `figcraft`.
3. **Capability config**: **Standard flow** on (the authorization code flow). Then either
   - **Client authentication off**: a *public* client, no secret (leave `client_secret` and
     `client_secret_file` out); or
   - **Client authentication on**: a *confidential* client; copy the secret from the client's
     **Credentials** tab into a secret file. Either works, since the server is the one exchanging
     the code; a confidential client also means a stolen code is useless without the secret.

   Turn on **OAuth 2.0 Device Authorization Grant** if you want the device flow.
4. **Login settings**: valid redirect URIs `http://127.0.0.1/*` (the app's loopback redirect;
   Keycloak lets a loopback redirect use any port). Under **Advanced ▸ Proof Key for Code
   Exchange Code Challenge Method** choose `S256` to require PKCE.
5. Make sure the realm's users have an email that Keycloak marks verified (**Users ▸ Email
   verified**, or **Realm settings ▸ Login ▸ Verify email**), if you use allow-lists or admins.

```toml
[[auth.provider]]
id = "company"
kind = "oidc"
label = "Company sign-in"
issuer = "https://sso.example.com/realms/design"
client_id = "figcraft"
client_secret_file = "/etc/figcraft-server/company.secret"   # leave out for a public client
flows = ["browser", "device"]     # "device" only with the grant turned on
```

### Other OpenID Connect issuers

Every issuer works the same way: register a native (desktop, public) application that uses the
authorization code flow with PKCE and accepts a loopback redirect on any port
(`http://127.0.0.1/`; RFC 8252), note its client ID (and secret, if it has one), and give the
server the issuer URL: the address whose `/.well-known/openid-configuration` describes it, which
must name the same issuer. The ID token must carry `email` and `email_verified` for allow-lists and
admins to work (or see `trust_email` below). Notes per issuer:

- **Authentik**: an *OAuth2/OpenID Provider* with client type *Public* (or *Confidential* with a
  secret) and an application using it. The issuer is
  `https://authentik.example.com/application/o/<application slug>/`.
- **Microsoft Entra ID**: an app registration with a **Mobile and desktop applications** platform
  and the redirect URI `http://localhost` (Entra ignores the port on loopback redirects), and
  **Allow public client flows** on for the device flow. Use **your tenant's issuer**,
  `https://login.microsoftonline.com/<tenant id>/v2.0`. The multi-tenant `common` and
  `organizations` endpoints don't work: their tokens' issuer names each person's own tenant, so it
  never matches the discovery document's. Entra's ID tokens don't include `email_verified`, so by
  default the server treats their emails as unverified: allow-lists, `admins` and invites don't
  match anyone. With a **single-tenant** app on your own tenant, set `trust_email = true` on the
  provider: its emails then count as verified. Only do that when every account in the tenant is
  yours (Entra lets an account's email be set to an address that wasn't checked, so on a tenant you
  don't fully control someone could claim another person's address and pass the allow-lists or
  become an admin). Either way, also limit who signs in in Entra itself (**Assignment required** on
  its enterprise application). Ask for the `email` claim if your tokens lack it (**Token
  configuration ▸ Add optional claim ▸ ID ▸ email**).
- **Okta**: an *OIDC* app integration of type *Native Application* with *Authorization Code* (and
  *Device Authorization* if wanted), *Require PKCE*, and a loopback sign-in redirect URI. The issuer
  is your authorization server: `https://<org>.okta.com/oauth2/default` (or
  `https://<org>.okta.com` for the org server).
- **Auth0**: a *Native* application with `http://127.0.0.1` in *Allowed Callback URLs*, and the
  *Device Code* grant under *Advanced ▸ Grant Types* if wanted. The issuer is
  `https://<tenant>.auth0.com/` (or your custom domain).
- **GitLab.com**: **User settings ▸ Applications** (or a group's or instance's applications), not
  confidential, scopes `openid`, `email` and `profile`, redirect URI `http://127.0.0.1/`; use
  `preset = "gitlab"`. A self-hosted GitLab is the same with `issuer = "https://gitlab.example.com"`
  and no preset.
- **Zitadel** and others: a native application with PKCE; the issuer is the instance's address.

Check the redirect rules of the issuer you pick: one that insists on an exact port can't be used
with the browser flow, since the app's port changes each time (the device flow still works).

```toml
[[auth.provider]]
id = "entra"
kind = "oidc"
label = "Microsoft"
issuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
flows = ["browser", "device"]
trust_email = true                # single-tenant only: Entra sends no email_verified
```

### An external verifier

With `kind = "external"`, people paste a token in the app and the server asks your verifier who it
is:

```text
POST <verify_url>          Content-Type: application/json
{"provider": "<the provider's id>", "token": "<what the person pasted>"}

200 {"subject": "a stable id", "email": "ann@example.com", "email_verified": true, "name": "Ann"}
    (only "subject" is required)
401 or 403 {"error": "why, shown to the person"}       (the "error" is optional)
anything else, or no answer in 15 seconds: the verifier is unavailable
```

- `subject` must never change for a person and never be reused: memberships hang on it.
- `email` counts for allow-lists, admins and invites only with `"email_verified": true` (or, when
  your verifier only ever answers with checked emails, set `trust_email = true` on the provider:
  an answer without `email_verified` then counts as verified).
- The server sends tokens of up to 8 KiB, reads answers of up to 1 MiB, and shows people at most 200
  characters of `error`.
- `verify_url` is `https://…`, or `http://127.0.0.1:…`, `http://localhost:…` or `http://[::1]:…`
  for a verifier on the same machine (allowed by the shipped systemd unit as is).

An **example** verifier (Python 3, standard library only) is in
[`examples/auth-verifier/`](../examples/auth-verifier/): it knows a fixed list of tokens by their
SHA-256, a starting point to replace with a question to your own directory, not something to run as
is. Its README shows how to make tokens and try it by hand.

```toml
[[auth.provider]]
id = "tokens"
kind = "external"
label = "Company token"           # what the app shows (default: the id)
verify_url = "http://127.0.0.1:8787/verify"
```

Run it as a user of its own (a systemd unit like the server's), listening on the loopback interface
only. A verifier on another machine must be behind HTTPS.

## The settings

Everything for accounts in `server.toml`, with each key's default. Unknown keys are errors, as in
the rest of the file. The server reads it when it starts: restart after a change.

```toml
# The server as in server.md: listen on the loopback interface behind the proxy.
listen = "127.0.0.1:47900"
data = "/var/lib/figcraft-server"
public_url = "wss://figcraft.example.com/"
trusted_proxy = "127.0.0.1"
open_publish = false                # must be false with accounts

[auth]
mode = "accounts"                   # "links" (default) | "accounts" | "accounts+links"
admins = ["you@example.com"]        # default []: verified emails that manage the server without the key
allow_emails = []                   # default []: verified emails that may sign in
allow_domains = ["example.com"]     # default []: domains whose verified emails may sign in
                                    # (both lists empty: anyone a provider vouches for)
session_days = 30                   # default 30: a sign-in lasts this long without being used (0.01 to 3650)

# One block per provider (at least one with accounts, at most 32).
[[auth.provider]]
id = "google"                       # required: 1-32 letters, digits, - or _; unique; never rename it
kind = "oidc"                       # required: "oidc", "external", or a kind your build registered
label = "Google"                    # default: the preset's label, else the id
# oidc only:
preset = "google"                   # "google" or "gitlab": fills issuer and label
issuer = ""                         # required without a preset: https://… (http:// only on 127.0.0.1 or localhost)
client_id = "1234-abc.apps.googleusercontent.com"   # required
client_secret_file = "/etc/figcraft-server/google.secret"  # or client_secret = "…" (not both; neither: a public client)
scopes = ["openid", "email", "profile"]   # the default; must include "openid"
params = [["prompt", "select_account"]]   # default none: extra parameters for the sign-in page
flows = ["browser"]                 # default ["browser"]; "device" adds the device flow
trust_email = false                 # default false: count emails as verified when the issuer doesn't say (see below)

[[auth.provider]]
id = "tokens"
kind = "external"
label = "Company token"
verify_url = "http://127.0.0.1:8787/verify"   # external only, required: https://, or http:// on this machine
trust_email = false                 # as above, for answers without "email_verified"

[e2e]
mode = "off"                        # "off" | "optional" | "required" (see server.md › Sealed files)
```

Which keys each kind reads: `oidc` reads `label`, `preset`, `issuer`, `client_id`,
`client_secret` or `client_secret_file`, `scopes`, `params`, `flows` and `trust_email`; `external`
reads `label`, `verify_url` and `trust_email`. Keys a kind doesn't read are ignored. A kind of your
own reads what its factory reads. These settings exist only in the file: unlike the server's other
settings they have no command-line flags.

**`trust_email`** makes an email from that provider count as verified when the provider doesn't
say (no `email_verified` claim or field); an explicit `false` still counts as unverified. Turn it on
only for a provider that hands out nothing but emails it has checked: a single-tenant Microsoft
Entra ID whose accounts are all yours, or a verifier backed by your own directory. With any other
provider, someone could sign in with an address that isn't theirs and so pass the allow-lists,
receive invites meant for that address, or become an admin.

`figcraft-server check` reports:

- a `mode` other than the three above, `session_days` outside 0.01 to 3650, more than 32
  providers, an accounts mode with no provider, an id that isn't 1-32 letters, digits, `-` or `_`,
  two providers with one id, a provider without a `kind`, an entry of `admins` or `allow_emails`
  that isn't an email address;
- `open_publish` with an accounts mode;
- an `[e2e]` mode other than `"off"`, `"optional"` or `"required"`;
- each provider, built without the network: an unknown `kind` or `preset`, a missing `issuer` or
  `client_id`, an `issuer` that isn't `https://`, a secret file it can't read, both
  `client_secret` and `client_secret_file`, an unknown flow, `scopes` without `openid`, or a
  `verify_url` that isn't `https://` (or `http://` on this machine).

Run `check` as the `figcraft` user (as above), so it reads the secret files with the server's
rights. The issuer itself is first contacted when an app asks what the server accepts, not by
`check` or at startup; see [Troubleshooting](#troubleshooting). (A server build with kinds of its
own checks them with `Config::check_with(&registry)`; the stock `figcraft-server check` knows only
`oidc` and `external`.)

## Who may sign in

After a provider has said who someone is, the server decides whether they may sign in:

- **Admins** always may (their email must be verified).
- With `allow_emails` and `allow_domains` both empty, **anyone the provider vouches for** may. With
  Google that is anyone with a Google account (or, with an *Internal* consent screen, anyone in your
  Workspace); with your own issuer it is everyone it knows. Leave the lists empty only when the
  provider already limits who gets through.
- Otherwise someone may sign in when their **verified** email is in `allow_emails` or its domain is
  in `allow_domains`. Domains match exactly (`example.com` doesn't let in `eu.example.com`; list
  both), a leading `@` is ignored, and case doesn't matter. An email the provider didn't verify
  counts for nothing.

People who are refused see why in the app: `ann@other.com isn't allowed on this server: ask its
operator`, or, when their sign-in gave no verified email, `this server lets in only some email
addresses, and your sign-in didn't give a verified one`.

Being allowed to sign in doesn't open any file: with `accounts`, a person sees only the files they
are a member of (or invited to) and those they publish.

**Sessions.** Signing in gives the app a session token of the server's own; the app uses it from
then on, without the provider. A session lasts `session_days` from its last use (so a person who
uses FigCraft every week stays signed in) and a person keeps at most 20 (the oldest end first).
Every use checks the allow-lists again: narrow them and restart, and people no longer allowed are
refused on their next connection, with the same message as at sign-in. Shortening `session_days` applies to new sign-ins; existing sessions keep the expiry
they had.

## Day to day

People sign in from the app: the app's sign-in (when they connect to the server, or from its
settings) lists the server's providers; **Sign in** opens the provider's page in the system
browser, and the app comes back signed in. Where an app can't open a browser (`figcraft-cli`,
agents through MCP), the device flow shows a code to type on another device; an `external`
provider asks for the token. *The sign-in in the app and the CLI is being built (step 4 of
[`accounts-and-e2e.md`](accounts-and-e2e.md#steps)); the server side described here is done.*

- **Publishing** a file to the server while signed in makes the publisher its **owner**; no server
  key is needed. A person owns at most 1,000 files on one server. With `accounts` the file gets no
  share links; with `accounts+links` it gets an edit and a view link as before.
- **Inviting**: an owner invites people by email with a role. Someone who has already signed in to
  the server becomes a member at once; anyone else is kept as an invite and becomes a member the
  first time they sign in with that (verified) email and open the file or list their files. A file
  has at most 500 members and invites together.
- **Roles** are changed by owners; the last owner can't be made editor or viewer (make someone
  else owner first).
- **Removing people**: an owner removes a member (they are disconnected from the file at once) or
  withdraws an invite; anyone can leave a file; the last owner can't leave or be removed. To keep
  someone out of the whole server, take them off the allow-lists (there is no per-person ban yet).
- **Admins** see and manage every file, including those published with the server key: an admin
  invites the right person as owner to hand such a file over.
- **accounts+links**: owners make, list and revoke a file's share links and join codes from their
  account, and anyone with a link gets in without signing in, as on a server without accounts.

## Data and backups

Accounts add to the data directory ([`server.md`](server.md#the-data-directory)):

```text
<data>/accounts/people.json    everyone who has signed in: the server's id for them, the provider
                               id and the provider's id for them (subject), their verified email,
                               their name, when they first and last signed in
<data>/accounts/sessions.json  their sessions: the SHA-256 of each session token, whose it is,
                               when it was made and when it ends
<data>/files/<id>/meta.json    gains "members" (account id and role: owner, editor or viewer) and
                               "invited" (email and role)
```

With sealed files (`[e2e] mode = "optional"` or `"required"`) the apps also keep keys here, all of
it public keys or ciphertext the server can't open
([`accounts-and-e2e.md`](accounts-and-e2e.md#sealed-files-with-accounts-built-step-9)):

```text
<data>/accounts/devices.json   each person's devices: an id (d + 16 hex digits), the account, the
                               name the app gave it ("FigCraft on LAPTOP-7"), its two public keys
                               (X25519, Ed25519; base64url), when it was registered and last seen,
                               and "recovery": true for the device a recovery key stands for. At
                               most 10 per person
<data>/accounts/recovery.json  each person's recovery copy: their recovery device's secret sealed
                               with a recovery key only they have (written down; never sent here)
<data>/files/<id>/keyring.json a sealed file's key, wrapped (HPKE) to each member device, by
                               epoch, and "rotate": true while it waits for a new epoch (someone
                               was taken out, or a device revoked, and no owner's app has been
                               online since)
```

A sealed file's `meta.json` also gets `"signed_from": <sequence number>` once its changes must
be signed by its editors' devices (the first time an app that signs opens it while every owner and
editor has registered a device; see
[`accounts-and-e2e.md`](accounts-and-e2e.md#editor-signatures-built-steps-10-and-11)). From then on
the server refuses unsigned changes to it (apps older than signed changes can view it, not edit:
update them together with the server), and share links to it only view. Taking the field out by
hand turns the requirement off until an app opens the file again.

Session tokens (256 random bits) are kept only as hashes: a copy of the data directory doesn't let
anyone sign in as someone. Emails and names are personal data: treat the directory accordingly.
Wrapped keys and recovery copies don't open without a device's private key (kept on that device,
in its OS keychain) or a person's recovery key: a copy of the data directory still doesn't let
anyone read a sealed file.

- **Backups**: the nightly backup timer (`figcraft-backup.timer`, [Backups](server.md#backups))
  copies the whole data directory, so accounts, sessions and memberships are in it, and with sealed
  files the devices, recovery copies and wrapped keys too (still unreadable: see above). Keep them:
  a backup without `keyring.json` restores sealed files nobody can open until an owner's app wraps
  the keys again (it does by itself if it still holds them). Settings and
  secret files live in `/etc/figcraft-server/`, outside it: keep a copy of `server.toml` with your
  other configuration, and of the secrets somewhere safe (or make new ones at the provider when you
  restore).
- **Restoring** an older copy brings back the people, sessions and memberships of that day (and the
  devices and keyrings: a device registered or an epoch started since is missing until the apps
  register and wrap again, which they do by themselves).
- **Ending every session** (after a leak, say): stop the server, delete
  `<data>/accounts/sessions.json`, start it. Everyone signs in again; memberships stay.
- **Moving to another machine**: stop the server, copy the data directory and
  `/etc/figcraft-server/` (with the secret files, owned by `figcraft` and mode 600), and start it
  there. Provider registrations don't name your server (the redirect goes to each person's own
  machine), so a new host name needs no change at the provider; set the new `public_url`. Keep each
  provider's `id`: accounts are tied to it, and a renamed id makes everyone a new person with no
  memberships.

## Security notes

- **Secrets**: `server.toml` is readable by everyone on the machine (`install.sh` makes it mode
  644); put client secrets in files owned by `figcraft` with mode 600 and name them with
  `client_secret_file`. In Docker, mount the secret file read-only and readable by the container's
  user (uid 65532).
- **Rotating a secret**: make a new one at the provider, write it to the secret file, restart the
  server, then delete the old one at the provider. Sessions don't depend on it: nobody is signed
  out.
- **Who gets in** is the provider's decision plus the allow-lists. Keep the lists as narrow as the
  team, prefer an issuer that only knows your people, and remember that with both lists empty
  anyone with an account at that provider can sign in (and then publish files to your server).
- **Admins** can open and manage every file and the server: list only the people who would hold the
  server key anyway. Admin rights follow the email, so they are only as safe as that email account
  and the provider's verification of it.
- **Not end-to-end encrypted by default**: accounts decide who gets in; on the server, plain files
  are stored unencrypted, readable by the operator and anyone who can read the data directory.
  Sealed files (`[e2e] mode = "optional"` or `"required"`, see
  [`server.md`](server.md#sealed-files)) are not. Tell the people using your server which it is.
- **Tokens never in logs**: the log records sign-ins as `event=signed_in provider=… account=…` and
  refusals as `event=sign_in_refused provider=… reason=policy`, plus invites taken and files
  published by account id. Codes, ID tokens, session tokens and secrets are never logged, and travel
  inside messages, never in URLs (the proxy's access logs don't see them).
- **The provider's answers are checked**: ID tokens must be signed by the issuer's published keys
  (RS256/384/512, ES256/384 or EdDSA), name the issuer and your client, and be within their times;
  the app's redirect must be a loopback address.

## Troubleshooting

**The provider is missing from the app, or offers no browser sign-in; the log says
`provider google: the sign-in service couldn't be reached: …`.** The server couldn't fetch
`<issuer>/.well-known/openid-configuration`. From the server, try
`curl -sS https://accounts.google.com/.well-known/openid-configuration | head -c 200`. If that
works but the server still fails with `Operation not permitted` (the log says the system refused
the connection), the systemd unit's network limit is still in place: run `install.sh` again, or add
the drop-in (see [Before you start](#before-you-start)). Otherwise check DNS, any outbound
firewall, and the issuer's certificate: one from a private authority needs `FIGCRAFT_CA_FILE`
(`invalid peer certificate: UnknownIssuer` in the log). A wrong `issuer` gives `HTTP 404`. The
server tries again on the next request.

**`… names another issuer (…)`**: the discovery document's `issuer` differs from the one you
configured. Use exactly the issuer it names (a trailing `/` doesn't matter; `/realms/…`, a tenant id
or `/oauth2/default` do).

**`the sign-in couldn't be checked: it comes from another issuer`**: the ID token names another
issuer than the discovery document; with Entra ID this is the multi-tenant `common` or
`organizations` endpoint: use your tenant's issuer.

**`it was made for another application`**: the token's audience isn't `client_id`. Check you
copied the right client ID (a second client at the same issuer, for example).

**`it isn't valid yet (is the server's clock right?)` or `it has expired: sign in again`**: the
server's clock is off by more than two minutes. Turn on time synchronisation
(`timedatectl set-ntp true`).

**The provider's page says `redirect_uri_mismatch` (or "invalid redirect URI")**: the client isn't
a desktop/native one, or doesn't allow a loopback redirect on any port. For Google, make a
**Desktop app** client; for Keycloak, add `http://127.0.0.1/*`; for others, see
[Other OpenID Connect issuers](#other-openid-connect-issuers).

**`the sign-in was refused (invalid_client): try again`**: the secret is wrong or missing (Google
needs it), or a public client was sent one it doesn't expect. **`(invalid_grant)`**: the code was
already used or expired, or the redirect didn't match: sign in again.

**`the issuer sent no ID token (is "openid" in the scopes?)`**: add `"openid"` to `scopes` (the
default has it).

**`… isn't allowed on this server: ask its operator`**: the person's verified email isn't in
`allow_emails` and its domain isn't in `allow_domains`. Add them and restart. **`… your sign-in
didn't give a verified one`**: the provider sent no verified email (Entra ID never says: see
`trust_email` in [The settings](#the-settings); in Keycloak, mark the email verified).

**People were signed out after you changed the settings**: every use of a session checks the
allow-lists again, so narrowing them ends the sessions of people no longer on them. Their files
and memberships are kept; they get back in once allowed again.

**`this server has no sign-in called "…"`**: the app asked for a provider id that is no longer
configured (renamed or removed). Restore it, or have people sign in again with another.

**`check` (or the server) refuses the settings**: the message says why, for example
``provider "google": can't read `client_secret_file` /etc/figcraft-server/google.secret: Permission
denied`` (make it owned by `figcraft`, and run `check` as `figcraft`), `unknown preset` or
`unknown kind`. **The server doesn't start** with ``can't read the certificates in
FIGCRAFT_CA_FILE``: the file named there is missing, unreadable by `figcraft`, or not a PEM
certificate. `journalctl -u figcraft-server -n 20` shows the reason.

**`you aren't in this file: ask its owner to invite you`**: the person is signed in but not a
member. An owner (or an admin) invites them; with `accounts+links`, a share link also works.
