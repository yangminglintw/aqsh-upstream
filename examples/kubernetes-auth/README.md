# Native authentication with separate API and worker Pods

`aqsh.yaml` is an alternative deployment example, not part of the default
Skaffold manifests. It expects namespace `aqsh`, Redis at `redis:6379`, and the
existing `aqsh-tasks-config` and `aqsh-task-scripts` ConfigMaps from `k8s/aqsh.yaml`.
Do not keep the original combined aqsh Deployment serving the same Service during
migration. Adjust task ConfigMaps, queue names, resources and worker permissions
to your deployment.

Build an image that contains native authentication and make it available to your
cluster before applying this example:

```sh
docker build -t aqsh:auth-integration .
kubectl --context "$AQSH_CONTEXT" --namespace aqsh apply -f examples/kubernetes-auth/aqsh.yaml
```

The API service account has TokenReview/JWKS permission. The worker has its own
service account and no mounted service account token in this hello-world example.
Grant production workers only the task permissions they need. Native mode never
loads the API's auth configuration in a worker process.

The gateway should route the caller's bearer token directly to Service `aqsh`
port 8080. Caller tokens must target audience `aqsh`; the API's projected reviewer
token targets the Kubernetes API audience. Preserve separate identities for the
reviewer and each caller.

To add a remote cluster, mount its CA and reviewer credential only in the API Pod
and extend `auth.yaml` as described in [authentication](../../docs/authentication.md).
Remote clusters need reviewer RBAC and reachable Kubernetes APIs, not another
aqsh/auth service. Managed renewal and Secret persistence are optional and are not
enabled by this example.

This example authenticates callers; it does not add execution owner isolation or
per-cluster task ACLs. Confirm those policies before accepting mutually untrusted
callers. It also does not configure a public ingress or deploy Redis.
