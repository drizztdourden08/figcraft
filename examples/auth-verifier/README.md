# Example: an `external` verifier

**An example, not a product.** `verify.py` is a reference verifier for `figcraft-server`'s
`external` identity provider (see [`docs/server-accounts.md`](../../docs/server-accounts.md#an-external-verifier)):
people paste a token in the app, the server POSTs it here, and this answers who it is. It knows a
fixed list of tokens by their SHA-256. Use it to see the contract work end to end, then replace
`lookup()` with a question to your own directory, SSO or database (or write the same small service
in any language).

```sh
# Make a token for someone and its hash.
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'    # give this to the person
printf %s 'THE-TOKEN' | sha256sum                                # put this in tokens.json

cp tokens.example.json tokens.json        # then replace the zeros with the hash
python3 verify.py --port 8787 --tokens tokens.json
```

and in `server.toml`:

```toml
[[auth.provider]]
id = "tokens"
kind = "external"
label = "Company token"
verify_url = "http://127.0.0.1:8787/verify"
```

Try it by hand:

```sh
curl -s -X POST http://127.0.0.1:8787/verify -H 'Content-Type: application/json' \
  -d '{"provider": "tokens", "token": "THE-TOKEN"}'
```

Notes:

- `subject` must never change for a person and never be reused: memberships hang on it.
- An `email` counts for allow-lists, admins and invites only with `"email_verified": true` (or
  when the provider is configured with `trust_email = true`).
- It listens on the loopback interface only and logs no requests (they hold tokens). Run it as a
  user of its own; a verifier on another machine must be behind HTTPS.
- Python 3.8 or later, standard library only. Licensed like the rest of FigCraft (MIT OR
  Apache-2.0).
