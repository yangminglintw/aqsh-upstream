# Source provenance

Ported from [rophy/kube-federated-auth](https://github.com/rophy/kube-federated-auth/tree/918c9a8614e9a79b9229d06503313b1cebbca78a/internal)
at commit `918c9a8614e9a79b9229d06503313b1cebbca78a`.

The original packages, tests and MIT license are retained. Imports point to aqsh.
The TokenReview handler exposes the existing review flow to an in-process caller;
no additional HTTP service is needed. An empty credential Secret name disables
Secret persistence. Token-file whitespace is trimmed before constructing HTTP
headers, and forwarded TokenReviews use the request context. Other embedding
changes are documented beside their code.
