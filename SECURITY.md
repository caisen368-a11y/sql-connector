# Security

## Reporting

Treat credential disclosure, authorization bypass, cross-session cancellation,
unbounded result handling, and native-query policy bypass as security issues.
Report them privately to the distributor of the desktop Agent; this repository
does not define a public disclosure address.

## Deployment requirements

- Launch MCP over local stdio. Do not expose it as an unauthenticated TCP or
  HTTP service.
- Restrict the data directory to the current OS user. It contains profiles and
  audit metadata, though not credential values.
- Store credentials only through the trusted control path. macOS Keychain and
  Windows Credential Manager are the supported production backends.
- Use least-privilege database accounts and keep profile policies read-only
  until a specific workflow requires writes.
- Protect the Agent's Ed25519 signing key separately from the MCP process. A
  grant is an authorization decision, not user authentication.
- Keep TLS enabled with server-certificate verification. Custom roots and
  client identities belong in the credential store, not profile URLs.
- Database HTTP clients ignore process-wide proxy environment variables in v1
  so credentials cannot be silently forwarded to an ambient desktop proxy.
- Never include secrets or full database results in diagnostic reports.

## Untrusted data

Catalog names, rows, documents, search hits, metrics labels, log events, and
database error text can contain prompt injection. The desktop Agent must mark
all connector output as untrusted data, exclude it from instruction channels,
and apply the profile's egress decision before sending content to a cloud model.

## Unsupported authentication

The initial release does not use cloud-provider identity/default credential
chains, OAuth SSO, Kerberos, SSH tunnels, or browser login flows. Adding any of
these changes the threat model and requires a new security review.
