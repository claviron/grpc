# mTLS Enrollment

Status: version 1, implemented by the `enroll` feature.

Enrollment issues a client certificate to a device that holds its own key. The
client proves who it is with a credential it chooses; the server answers with
a certificate for the key the client signed a request with, its root, and the
address of the management endpoint the certificate opens. The private key
never leaves the device. It is, for client certificates, what ACME is for
server certificates: a token credential plays the part of ACME's external
account binding.

## Session

Enrollment is an ALPN session profile, `claviron-mtls-enroll/1`. A host offers
it by listing the id under `tls.alpn` with its parameters:

```yaml
grpc.example.com:
  tls:
    client_auth: required          # ordinary connections keep mutual TLS
    alpn:
      claviron-mtls-enroll/1:
        validity_days: 30          # how long an issued certificate is valid
        permissions: [deploy.release]   # with authorization: the most a
                                         # certificate enrolled here is granted
```

`permissions` bounds what a certificate enrolled on the host may be granted
beside its account's own; unwritten, nothing. Each name must be defined in the
server's catalog, or the host's preparation is refused.

A client offering the id gets a handshake that asks for no client
certificate and reaches enrollment alone; an ordinary connection to the same
host never reaches it. The connection preface decides the HTTP version: a
tool that enrolls and exits sends one HTTP/1.1 request, an application keeping
the connection speaks HTTP/2. The host's admission the profile inherits
applies: trusted proxy identity, deny list and ACL, quotas, access log and
metrics. The client verifies the enrollment host against the roots it already
trusts, the system's or ones it was given.

## Exchange

One path, `/.well-known/claviron/mtls-enroll`.

`HEAD` probes. It answers `204` when a management address can be named and
`503` otherwise; both carry `Claviron-Mtls-Enroll: 1`.

`POST` enrolls, with `Content-Type: application/json`. A request with an
`Origin` header is refused: browsers cannot offer the ALPN id, and nothing
else on this path is for them.

```json
{
  "credential": {"password": {"username": "ada", "password": "…"}},
  "device": "laptop-cli",
  "permissions": ["deploy.release"],
  "csr_der": "MIH…"
}
```

| Field | Meaning |
| --- | --- |
| `credential` | What the client presents, by kind: `{"password": {"username", "password"}}` or `{"token": "…"}`. The server's application accepts the kinds it supports. |
| `device` | The client's label for this device: one DNS label, 1 to 63 lowercase letters, digits and hyphens, not starting or ending with a hyphen. Clients derive `<short-hostname>-<client>`, such as `laptop-cli` or `laptop-app`. A label proves nothing; it names. |
| `permissions` | Optional, only on a server built with `authorization`: permission names from the server's catalog, asked for this certificate beside the account's own. A request must stay within the host's `permissions`; asking grants nothing, the guard decides within the same bound. A server that cannot grant permissions refuses a request naming them. |
| `csr_der` | A PKCS#10 request, base64 DER, signed with the device key. Its subject and attributes are ignored: the server takes its public key. |

Unknown fields are refused. A `201` answers:

```json
{
  "server_name": "edge-1",
  "management_address": "https://admin.example.com",
  "certificate_chain_pem": "-----BEGIN CERTIFICATE-----…",
  "authority_certificate_pem": "-----BEGIN CERTIFICATE-----…"
}
```

`server_name` is the server's own name, the one its management API reports;
a client names the profile it keeps for this server after it. The chain holds
the client's certificate and any intermediates; the authority is the root. The client checks that the certificate is for its key and chains
to the root, then trusts that root for the management address.

| Status | Meaning |
| --- | --- |
| `201` | Issued, or the device's certificate returned again for the same key. |
| `400` | Malformed: a field, the device label, the request's signature, or a permission the server does not define. |
| `401`, `403` | The credential does not verify, the account may not enroll, or the request asks for a permission the host does not grant. The server's log says which. |
| `409` | The certificate's name is taken by another key: revoke that device's certificate, or choose another label. |
| `415` | Not JSON. |
| `503` | No signer, no management address, the application's policy or record unavailable. |

Every answer carries `Cache-Control: no-store`.

## Identity

A certificate names one credential and carries identity only.

```text
CN   the credential's name, unique among the store's certificates:
     ada.laptop-cli, ada.iphone-app
URI  the account, the same in every certificate it holds: urn:uuid:…
```

- The application's guard names the certificate, usually
  `<account>.<device>`, and gives the account's stable subject URI. The
  client chooses neither.
- The common name is the handle every consumer uses for this credential:
  admission, a VPN address, revocation. An account enrolls several devices;
  each is revoked alone.
- A mutable attribute such as a username is not a reason to reject a
  certificate whose URI still names the account. The application's admission
  finds the account
  by its URI and checks that the presented certificate is one of the
  account's issued, enabled and unrevoked certificates.
- No permission is signed into a certificate. What the account may do is
  decided when a connection is admitted, from the application's current
  state. Permissions granted to one certificate are stored by the application
  against that certificate, recorded when enrollment reports it issued, and
  added to the account's own for connections presenting it.

## Idempotence

Enrolling again with the same key returns the certificate already issued for
it, with `201`, while it is enabled, unrevoked and unexpired. The application
is told again, so a record it failed to write the first time is written now.
Another key for a taken name is `409`; enrollment never replaces a
credential by itself, since that would let whoever knows the password take
over a device's name.

## Versions

The ALPN id carries the protocol's version. A change a version-1 client
cannot read takes a new id, offered beside the old one while clients move.
