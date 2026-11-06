# claviron-grpc

Typed, mTLS-secured administration for
[Claviron](https://crates.io/crates/claviron). Serve management RPCs on Edge
vhosts over HTTP/2 or HTTP/3.

Generated protobuf messages, service definitions, and client stubs are available
without enabling the management server. Clients own their channel and TLS setup.

## Management surfaces

The base server exposes server identity/reload/shutdown, live hosting and aliases,
services, embedded applications, linked applications, and reflection.
Optional features add workers, tasks, DNS, registrar-held domains, ACME, local
certificate issuance, certificate transfer, and a protected metrics endpoint.

These APIs use the runtime's existing authoritative state. gRPC does not launch
linked runner processes, maintain another worker table, or duplicate service
lifecycle controllers.

## Features

Default features are empty.

| Feature | Adds |
| --- | --- |
| `server` | Provider and management serving on Edge vhosts. |
| `registration` | HTTPS enrollment of device-owned mTLS keys through an application guard. |
| `workers` | Worker inspection, lifecycle commands, rolling restart, and fleet resize; includes `server`. |
| `tasks` | Task-management routes when combined with `server`, plus Claviron's task capability. |
| `acme` | ACME persistence dependency and ACME RPCs when combined with `server`. |
| `dns` | DNS management routes and service dependency; includes `server`, not a DNS listener or PostgreSQL selection. |
| `domains` | Registrar/domain management routes with GoDaddy and Namecheap integrations; includes `server`. |
| `mtls-manager` | Direct Rust API for local CA, server, and client certificate issuance/renewal; includes `server`. |
| `mtls` | `mtls-manager` plus its RPC routes. |
| `certificate-manager` | Direct Rust API for certificate import/export; includes `server`. |
| `certificates` | `certificate-manager` plus certificate-transfer RPC routes. |
| `metrics` | Protected HTTP `GET /metrics` alongside management; includes `server`. |

The application registers backing providers separately. For example, DNS RPCs
need a configured DNS provider and its explicit PostgreSQL feature; selecting
the gRPC `dns` feature alone does not supply that deployment.

## Register with an application

```toml
[dependencies]
claviron = { version = "0.2.0-alpha.25", default-features = false, features = ["edge", "tls", "postgres"] }
claviron-grpc = { version = "0.2.0-alpha.25.1", features = ["server", "workers", "mtls", "certificates"] }
```

```rust
fn configure(state: &claviron::runtime::AppState)
    -> claviron::runtime::registry::Result<()>
{
    claviron_grpc::register(state)
}
```

Database-backed operations require the configured hosting store and schema.
Protobuf generation uses `protoc` at build time, including protocol-only builds.
The [proto directory](proto) contains the source contracts.

## gRPC access policy

All server builds expose `claviron_grpc::access::GrpcAccessPolicy` independently
of user or role management. Bind an application-owned
policy with `registry.bind_dyn`. No `validate_user` switch or separate
application model is installed. Without a policy, existing mTLS admission stays
in effect. A registered policy is consulted once when the first management RPC
establishes the connection's session. Its actor or denial is retained until
disconnect; errors never fall back to certificate-only admission.

Each denied connection emits one WARN event with the service, the parsed
`client_cn` when exactly one is present, and the safe admission reason.
Each successful policy grant emits one INFO event with the same peer fields.
Repeated RPCs on that connection return the retained denial
without another lookup or log. Infrastructure failures emit ERROR. Reconnecting
performs a new admission.

The accepting transport validates the certificate before providing its exact
public leaf DER, structured CNs and URI SAN candidates in `PeerIdentity`.
Management is a native backend selected for the configured TLS/QUIC hosts.
An accept layer prepares its access session in `ConnState`; requests borrow
that connection through `HostContext`. The backend declares no identity export
to request extensions. Its prepared scope supplies the HTTP head deadline.
The policy receives only the verified `claviron::ssl::peer::PeerIdentity`;
there is no client-selected service or target. Edge H2 and H3 use the same session
admission, including reflection and capability discovery. Concurrent RPCs share
the same pending decision. Cancelling one RPC does not restart validation.

`Ok(None)` grants peer-only access. `Ok(Some(actor))` also supplies the host's
`AnyAuthenticated` subject to user-management handlers. These handlers require
that actor and the matching operation admission; mTLS alone cannot synthesize a
user. The policy owns lookup, active-state checks, role interpretation and
binding to a stable application subject at session establishment. Managers still
enforce current resource permissions per operation; session admission is not a
blanket RPC grant. Changes to service admission take effect on reconnect.
CN-only credentials need no invented identifier, and multiple URI candidates
are retained for explicit host selection.
The issuer DN is display metadata, not a trust-anchor identity; the host owns
trust-domain restrictions through its configured TLS trust and access policy.
No permission claims are inferred from certificate names or URI contents.

## User-management protocol

[users.proto](proto/users.proto) defines schema discovery, user/role/permission
record management, and direct assignment operations. Application-defined JSON
fields and optional UI metadata use the shared
[management.proto](proto/management.proto) envelope. Public references and
revision tokens are opaque; no common users table or fixed profile fields are
required. Validation and management scope belong to the downstream application.
The native contracts are `claviron::auth::users::UserManager` for user CRUD and
`claviron::auth::authorization::RolePermissionManager` for role/permission CRUD
and assignments. Their `users` and `authorization` features are independent.

Enable `users` for user CRUD, `authorization` for role/permission CRUD and
direct assignments, or both. Each enables `server` and its matching Claviron
capability. One `UserManagement` service dispatches to the corresponding manager
bound in the application registry. A missing manager or disabled resource returns
`UNIMPLEMENTED`; `server` alone installs neither capability. Protocol types and
client stubs remain available without these features.
The base server's hosting services still require the host's choice of a
Claviron database backend; these management features do not select one.

Bind the application's existing `UserManager` and/or `RolePermissionManager`
with `registry.bind_dyn`. User-management calls require an application actor
returned by the host's `claviron_grpc::access::GrpcAccessPolicy`.
Managers recheck current authority, scope, validation and revisions on every call.

Declare work bounds in `grpc.yaml`, for example:

```yaml
user_management:
  max_page_size: 100
  max_document_bytes: 16384
  max_assignment_members: 256
```

These are explicit example values, not defaults. List, JSON mutation and
assignment replacement calls require the applicable bounds before delegation.
Reload updates these bounds without replacing the manager. Tonic's default
inbound message-size bound also applies. JSON decoding preserves exact integer
values and rejects non-object documents. No database or GUI is installed here.

`GetAssignmentSchema` discovers pivot operations through `RolePermissionManager`
independently of user CRUD schemas; its revision does not replace a user schema
revision. `GetAssignments` and `ReplaceAssignments` use the same provider even
when user CRUD is disabled.

### Schema contract

Schemas come from the selected application manager, with separate projections:

- `record_schema_json` describes authorized output fields.
- `create.data_schema_json` describes the complete creation object. Required
  fields use `required`; accepted choices use `enum` or `const`. A default does
  not satisfy a requirement for an explicitly submitted choice. Account types
  and other domain fields are application-defined, not fixed gRPC fields.
- `update.data_schema_json` describes editable values. Updates are sparse:
  validate supplied fields and the resulting record without requiring unchanged
  fields to be submitted again.

Data schemas explicitly declare JSON Schema 2020-12 through `$schema`. The
provider declares its unknown-field policy and enforces the same constraints
when writing. Optional `ui_schema_json` uses JSON Forms UI Schema; its controls
refer to data properties. Layout, visibility and read-only hints grant no write
authority. Clients reject unsupported forms rather than silently dropping rules.

Field, constraint, UI or operation changes require a new schema revision.
Validation remains server-side and returns JSON-Pointer field violations through
the mutation-result envelope. No schema is inferred from database columns.

A server adapter routes user records to UserManager and role/permission records
to RolePermissionManager. Every assignment operation belongs to RolePermissionManager,
including user-role and user-permission pivots. Its `assignment_schema` discovers
relationship capabilities independently of a user's CRUD form. A deployment may
provide either manager; omitted capabilities must not load or require the other.

## Vhost configuration

`grpc.yaml` is read from the application's Claviron configuration directory:

```yaml
vhosts: [management]
```

`management` is a canonical vhost key. Its existing Edge policy must allow
HTTP/2 or HTTP/3, provide a server certificate, and require trusted client certificates
with `tls.client_auth.mode: required`. Public hostnames belong to that host's
aliases. The management binding is exclusive, not merged into an application
router. Plaintext, unverified clients and HTTP/1 requests cannot enter RPC handling.
Set listener selection in the vhost and listener settings in `http.yaml`.
Use the vhost's `requests.head_timeout` to bound the time to the response head,
including access policy and RPC execution. Edge's request-body and response-body
policies apply separately. H3 requires Claviron's `http3` feature and a client
that supports gRPC over H3.

## Client enrollment

Build with `registration` and register a `RegistrationGuard` with
`server::management::registration::register_guard`. The guard verifies credentials and grants
`grpc.access` by returning a `GrpcUser`. A guard can issue a CN-only identity
or attach a stable subject URI. The latter includes the signed `grpc.access`
grant. The role and permission manager remains optional.

```yaml
vhosts: [management]
registration: [enrollment]
registration_validity_days: 30
```

The enrollment vhost needs HTTPS without mandatory client authentication.
Management requires mTLS. Select the default issuer with `certstore.authority`.
The registration provider prepares its signer at boot. A DB authority uses
the selected Hosting issuer. A file authority uses the CertStore CA pair
and its chain through the root. For an explicit file pair, set `cert_path`,
`key_path`, and, if needed, `ca_path` inside `authority`. Hosting retains the
public CA hierarchy and issued client certificates. An explicit issuer in a
management issuance RPC selects a Hosting signing key.

The management vhost must trust this issuer for client authentication.
Its server certificate must also chain to the returned root. Use Edge's
request policy and quota for the enrollment host.

An unauthenticated `HEAD /.well-known/claviron/grpc-registration` checks
the registration route and management address selection. It returns 204
when a management address is available or 503 otherwise. Both responses
carry `Claviron-Registration: 1`.

Send `POST /.well-known/claviron/grpc-registration` with JSON fields
`username`, `password`, and `csr_der` (base64 PKCS#10 DER). HTTP 201 returns
`management_address`, `certificate_chain_pem` (the client leaf and any
intermediates), and `authority_certificate_pem` (the root CA). The address
uses the first concrete SNI served over TLS/H2 from the configured `vhosts`
in order, trying each canonical name before its aliases. Port 443 takes
precedence when available for that name. The client obtains the root over
system-verified enrollment HTTPS and uses it to verify the management endpoint.
The signer uses the CSR's verified public key and
takes the certificate identity from the guard. The private key stays on the
device. Hosting keeps the public certificate for revocation. Retrying with
the same authorized identity and key returns the existing active certificate.
A different key for an occupied CN returns HTTP 409.

## Lifecycle and trust boundaries

Fleet commands generally acknowledge submission, not completion. Clients observe
later worker/service/application snapshots and generations to confirm the result.
`RunTask` instead waits for one local task occurrence; a task execution budget
and a gRPC transport deadline are separate controls.

A management connection cannot stop or restart the Edge listener carrying it.
Direct `MtlsManager` and `CertificateManager` calls use the same issuance/store
logic without requiring a network request; the calling application must enforce
its own identity, ownership, and private-key export permissions.

`CertAuthority` supplies public trust only. Local issuance explicitly acquires
a `CertSigner` for the selected authority; reading trust does not load its CA key.

`MtlsManager.RevokeCertificate` revokes any stored certificate by its common
name, regardless of issuer. It writes `revoked_at` and `enabled=false` atomically
through `HostingStore`, retains the first timestamp and publishes the normal
certificate-change notification. Responses and inventory report revocation
separately from enabled state. Re-enabling or renewing cannot clear revocation.
The client-auth snapshot indexes revoked client certificates only; disabled
server certificates are removed from the SNI resolver. Existing connections
stay open. This local decision does not contact an external ACME authority or
retroactively replace pinned CA trust.

Local issuance, certificate import/export, and ACME issuance are separate
operations. Import does not silently issue a replacement certificate or alter
runtime trust. Creating or renewing a CA does not automatically replace the
trust material pinned by already running listeners.

Client issuance accepts an optional `subject_uri`, stored in a URI SAN separately
from the CN and DNS/IP aliases. Responses report URI identities parsed from the
signed certificate. Export and same-key renewal preserve them. The application
GrpcAccessPolicy owns user binding and authorization; the issuer infers neither.


### Certificate permissions

Client issuance accepts an optional `CertificatePermissions` message. Management
clients select permission records through the existing authorization list API.
With `authorization` enabled and a `RolePermissionManager` bound, issuance and
renewal revalidate each selected reference through that manager using the admitted
application actor. There is no separate certificate permission list to maintain.
User/role assignments are not changed.

A custom issuer without a management provider can supply explicit
`PermissionCatalog` definitions through `MtlsManager::with_permissions` or the
runtime registry. Selected permissions fail closed without a definition source.
Omission keeps an unscoped credential, while an explicitly empty message signs an
empty scope. Responses read the declaration from the signed certificate. The host
continues to own issuance authorization, delegation and service access policy.
