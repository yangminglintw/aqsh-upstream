# Authentication

aqsh supports two explicit authentication modes. Existing deployments keep
`AQSH_AUTH_MODE=trusted-header` by default. In that mode, an authenticating proxy
must be the only caller able to reach the API; aqsh trusts its configured identity
and groups headers. `AQSH_REQUIRE_IDENTITY` retains its existing behavior.

## Native Kubernetes authentication

Run the API with `AQSH_MODE=api`, `AQSH_AUTH_MODE=kubernetes`, and
`AQSH_AUTH_CONFIG=/etc/aqsh/auth.yaml`:

```yaml
audiences: [aqsh]
request_timeout: 5s
clusters:
  production-a:
    api_server: https://kubernetes.default.svc
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
```

`production-a` is a stable, operator-assigned trust domain. The configuration is
loaded at startup; changes require an API restart. Unknown fields, invalid HTTPS
endpoints, missing audiences, and unreadable credentials cause startup to fail.
Omitting `ca_file` uses system roots. TLS verification cannot be disabled.

The caller sends `Authorization: Bearer <token>` issued for an audience in the
configured list. aqsh submits a TokenReview with those audiences to the configured
API server using its **reviewer** credential. The reviewer needs
`create` on `tokenreviews.authentication.k8s.io`. Its token must target the
Kubernetes API audience, which may differ from the caller's `aqsh` audience.
The response must authenticate the caller, include a username and UID, and return
an audience intersecting the request. Failed authentication returns 401; an
unavailable reviewer/API returns 503. There is no fallback to forwarded headers.
Requests have a bounded timeout and do not follow redirects.

All API endpoints require authentication except exact `GET /health` and
`GET /metrics`. Limit access to these operational endpoints at the gateway or
network boundary. The coverage debug endpoint also requires authentication.

The middleware discards forwarded identity, groups and cluster headers, strips the
bearer token, and passes a verified `Principal` through request context. Existing
`allowed_users`, `allowed_groups`, `${identity}`, `${groups}`, `AQSH_IDENTITY`, and
`AQSH_GROUPS` keep their existing username/group semantics. Native submissions
add a `principal` object to the queue payload with provider, cluster, username,
UID and groups. Group names must be representable as CSV without commas, line
breaks or surrounding whitespace; ambiguous names fail authentication. Bearer and reviewer tokens are never queued or passed to scripts.

This integration authenticates requests. It preserves the existing execution
read policy: authenticated callers who know an execution ID can read its status,
result and logs. It does not add owner-only reads or tenant isolation. Do not
use this mode as an execution isolation boundary between mutually untrusted users.

## Separate API and worker credentials

Native authentication rejects `AQSH_MODE=both`. Deploy a separate worker Pod
using `AQSH_MODE=worker`, with the same Redis/task configuration but without the
auth configuration, reviewer token mounts, or TokenReview/credential-management
RBAC. Workers ignore the API authentication configuration.

Runbooks execute shell commands with access to their process environment and
filesystem. Separate containers in a shared Pod are insufficient if they share
reviewer token volumes or the same service account. Use separate Pods and service
accounts, and grant workers only the database/cluster permissions their tasks need.

Projected reviewer tokens are read from `token_file` for every TokenReview so
kubelet rotation is picked up without restarting the API. Mounted CA bundles are
also checked for every outbound request. Changed bundles create a fresh TLS
transport; unreadable or invalid bundles fail the request instead of retaining
stale trust. Mount rotating files as directories rather than Kubernetes `subPath`
mounts, which do not receive Secret/ConfigMap updates.

## Migrating from kube-auth-proxy

1. Create a dedicated API service account with TokenReview permission and mount
   the auth configuration and reviewer CA/token only in the API Pod.
2. Run a separate worker Pod and verify its task permissions and queue settings.
3. Point the gateway/Service directly at the native API port. Preserve the
   caller's Authorization header; do not substitute the gateway's identity.
4. Verify allowed and denied task submissions before removing aqsh's proxy
   sidecar. Keep standalone auth services used by other applications.

To roll back, restore the authenticating proxy route and explicitly select
`trusted-header`. Ensure that callers cannot directly reach the header-trusting
backend. This is a configuration migration; existing task definitions and shell
scripts do not need to change.

## Federated Kubernetes authentication

Configure multiple trusted clusters in the same file. Each cluster requires an
explicit `jwks_url` on the same HTTPS origin as its `api_server`, plus its own
reviewer credential and CA. No token-supplied issuer/discovery URL is fetched.

```yaml
audiences: [aqsh]
request_timeout: 5s
cache_ttl: 0s
cache_size: 1000
clusters:
  production-a:
    api_server: https://api-a.example.com
    jwks_url: https://api-a.example.com/openid/v1/jwks
    ca_file: /etc/aqsh/auth/ca/a.pem
    token_file: /etc/aqsh/auth/tokens/a
  production-b:
    api_server: https://api-b.example.com
    jwks_url: https://api-b.example.com/openid/v1/jwks
    ca_file: /etc/aqsh/auth/ca/b.pem
    token_file: /etc/aqsh/auth/tokens/b
```

aqsh verifies the JWT against each configured cluster's JWKS to choose a unique
source, checks `exp`/`nbf` when present, then sends the caller token **only** to
that source's TokenReview API. TokenReview supplies the authoritative username,
UID and groups. Matching JWKS signatures alone never authenticate a caller.
Different clusters can use the same issuer or key ID; cluster identity comes from
the configured trust domain and verified key. Shared signing keys across trusted
clusters make routing ambiguous and are rejected before forwarding the token.
Supported algorithms are RS256, ES256, ES384, ES512 and EdDSA.

The reviewer also needs read access to `/openid/v1/jwks`. JWKS keys are cached per
cluster for five minutes, with refresh on signature/key misses throttled to once
per five seconds. A failed JWKS request returns 503 and is retried after a five
second cooldown. An unavailable cluster can prevent unique routing and cause
503 for other clusters too. The timeout bounds the complete authentication
request, including routing and TokenReview.

TokenReview caching is disabled by default. Optional `cache_ttl` accepts at most
one minute; `cache_size` bounds retained entries (default 1000, maximum 10000).
Only successful reviews are cached, keyed by cluster, SHA-256 token hash and the
full configured audience set. Entries cannot outlive a JWT's `exp`. Enabling this
cache delays observation of revoked tokens/deleted bound objects by up to the TTL;
leave it disabled when every request needs an online revocation check.

Trust only clusters whose authenticated users may access this aqsh instance.
Existing task ACLs match raw usernames/groups, so identically named service
accounts in different trusted clusters match the same ACL. Execution reads also
retain their existing shared policy. The recorded cluster/UID are identity
metadata, not per-cluster task authorization or execution isolation.

## Optional managed reviewer renewal

Mounted/projected credentials need no Secret writes or TokenRequest permission.
For a remote reviewer that cannot use kubelet-managed rotation, explicitly enable
`renewal` on that cluster:

```yaml
renewal_interval: 1m
clusters:
  production-b:
    api_server: https://api-b.example.com
    jwks_url: https://api-b.example.com/openid/v1/jwks
    ca_file: /etc/aqsh/auth/ca/b.pem
    token_file: /etc/aqsh/auth/tokens/bootstrap-b
    renewal:
      namespace: aqsh-auth
      service_account: aqsh-reviewer
      audiences: [https://kubernetes.default.svc.cluster.local]
      token_duration: 1h
      renew_before: 10m
```

This is a fragment to combine with the audience/cluster configuration above.
Set reviewer audiences to values accepted by that cluster's Kubernetes API;
they are independent of the caller audiences. The reviewer needs `create` on the
configured `serviceaccounts/token` subresource in its namespace, in addition to
TokenReview/JWKS permissions. The namespace and service account are explicit
configuration, not derived from unverified token claims.

The API checks token expiry once per interval (default one minute) and requests
an unbound replacement before expiry. It reads the current credential for every
outbound request, so long-lived TokenReview/JWKS clients use renewed tokens.
If renewal fails, it retries with the current bootstrap file when that differs
from the managed token, then retries on the next interval. Expired credentials
are not used as an offline authentication fallback. Mount a renewable bootstrap
credential for recovery; aqsh cannot recover if all reviewer credentials expire
or lose their required RBAC. Renewal stops with the API context.

For restart persistence, opt into an **existing**, dedicated Secret:

```yaml
persistence:
  api_server: https://kubernetes.default.svc
  ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  namespace: aqsh-auth
  secret: aqsh-reviewer-tokens
```

Only the API service account needs `get` and `patch` on this named Secret. aqsh
does not create Secrets, list/watch them, or replace unrelated keys. The Secret
must already exist, even if empty. Managed cluster IDs use lowercase letters,
digits, dots or hyphens (maximum 63 characters); tokens are stored under
`<cluster-id>-token`. On startup, aqsh loads only configured managed entries,
skipping expired, wrong-subject and Pod-bound tokens. A failed Secret read stops
API startup. Successful renewal patches its own key before adopting the new
credential. A failed write retains the previous snapshot and retries later.

Use one active API replica for each managed reviewer Secret. Renewal has no
distributed lease; multiple independent managers can overwrite the same key.
Mounted-only mode supports multiple API replicas without this restriction.

This mode gives the API reusable reviewer credentials; protect its Secret, RBAC,
configuration and network access accordingly. Keep all of them out of worker Pods.
See the [separate API/worker example](../examples/kubernetes-auth/README.md).

## Migrating from kube-federated-auth

The native API talks directly to each trusted Kubernetes API. It does not expose
a public TokenReview forwarding endpoint, `/clusters` endpoint, or a second
metrics listener. Existing aqsh `/health` and `/metrics` remain available.

Map each old `clusters.<id>.ca_cert` to `ca_file` and `token_path` to `token_file`.
Keep cluster IDs stable. Set an explicit `jwks_url` for every federated cluster
and configure caller audiences explicitly. If reusing a persisted Secret, match
its existing `<cluster-id>-token` keys and enable renewal for those entries.
Old `authorized_clients` entries identified the intermediate proxy service;
they are not task-user authorization and must not be copied as task ACLs.
Review `allowed_users`/`allowed_groups` for the callers in all trusted clusters.

After validating the direct API route and separating worker credentials, remove
aqsh's dependency on the standalone federation service. Keep it deployed if other
applications still use it. OAuth/MCP support and owner-only execution reads are
separate changes.

Kubernetes references: [service account token lifecycle](https://kubernetes.io/docs/concepts/security/service-accounts/)
and [TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/).
