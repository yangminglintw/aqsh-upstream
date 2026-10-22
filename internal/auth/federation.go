package auth

import (
	"context"
	"fmt"

	proxy "github.com/rophy/aqsh/internal/kubeauthproxy"
	fedconfig "github.com/rophy/aqsh/internal/kubefederatedauth/config"
	"github.com/rophy/aqsh/internal/kubefederatedauth/credentials"
	"github.com/rophy/aqsh/internal/kubefederatedauth/handler"
	"github.com/rophy/aqsh/internal/kubefederatedauth/oidc"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// federatedReviewer connects the ported handler to the proxy's existing reviewer
// interface. Routing, JWKS, caching and credentials stay in the original packages.
type federatedReviewer struct {
	config    *fedconfig.Config
	store     *credentials.Store
	verifier  *oidc.VerifierManager
	handler   *handler.TokenReviewHandler
	audiences []string
}

func newFederatedReviewer(cfg Config) (*federatedReviewer, error) {
	fc, err := fedconfig.Load(cfg.FederationConfig)
	if err != nil {
		return nil, fmt.Errorf("loading federated-auth config: %w", err)
	}
	if len(fc.AuthorizedClients) != 0 {
		return nil, fmt.Errorf("authorized_clients applies to the standalone TokenReview HTTP service; use aqsh task ACLs for API callers")
	}
	store, err := credentials.NewStore(fc, cfg.SecretName)
	if err != nil {
		return nil, err
	}
	verifier := oidc.NewVerifierManager(fc, store)
	return &federatedReviewer{config: fc, store: store, verifier: verifier,
		handler:   handler.NewTokenReviewHandler(verifier, fc, store, verifier),
		audiences: append([]string(nil), cfg.Audiences...)}, nil
}

func (f *federatedReviewer) Review(ctx context.Context, token string) (*proxy.TokenReviewResponse, error) {
	tr, err := f.handler.Review(ctx, &authv1.TokenReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"},
		Spec:     authv1.TokenReviewSpec{Token: token, Audiences: f.audiences},
	})
	if err != nil {
		return nil, err
	}
	extra := make(map[string][]string, len(tr.Status.User.Extra))
	for key, value := range tr.Status.User.Extra {
		extra[key] = append([]string(nil), value...)
	}
	return &proxy.TokenReviewResponse{Status: proxy.TokenReviewStatus{
		Authenticated: tr.Status.Authenticated, Audiences: tr.Status.Audiences, Error: tr.Status.Error,
		User: proxy.UserInfo{Username: tr.Status.User.Username, UID: tr.Status.User.UID,
			Groups: tr.Status.User.Groups, Extra: extra},
	}}, nil
}

// InvalidateVerifier refreshes both consumers of renewed reviewer credentials.
// The credential store already invokes this hook after each successful renewal.
func (f *federatedReviewer) InvalidateVerifier(cluster string) {
	f.verifier.InvalidateVerifier(cluster)
	f.handler.InvalidateClient(cluster)
}
