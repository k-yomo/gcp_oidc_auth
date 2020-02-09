package gcpauth

import (
	"context"
	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
)

const (
	googleRootCertURL = "https://www.googleapis.com/oauth2/v3/certs"
	oidcTokenIssueURL = "https://accounts.google.com"
)

// verifier is oidc.IDTokenVerifier
// to cache remote key set, verifier is hold statically in-memory
var verifier *oidc.IDTokenVerifier

// Config is the configuration for VerifyIDToken.
type Config struct {
	// Expected audience of the token.
	// If not provided, skipAudienceCheck must be set explicitly
	aud string
	// If true, no audience check performed. Must be true if aud field is empty.
	skipAudienceCheck bool
}

func VerifyIDToken(ctx context.Context, serviceAccountEmail, oidcToken string, config *Config) error {
	idToken, err := verifyGoogleIDToken(ctx, oidcToken, config)
	if err != nil {
		return err
	}
	var idTokenClaims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&idTokenClaims); err != nil {
		return errors.Wrap(err, "decode idToken claims")
	}
	if !idTokenClaims.EmailVerified {
		return errors.Errorf("issuer email %s is not verified", idTokenClaims.Email)
	}
	if idTokenClaims.Email != serviceAccountEmail {
		return errors.Errorf("unexpected issuer email '%s'", idTokenClaims.Email)
	}
	return nil
}

func verifyGoogleIDToken(ctx context.Context, token string, config *Config) (*oidc.IDToken, error) {
	if verifier == nil {
		keySet := oidc.NewRemoteKeySet(ctx, googleRootCertURL)
		config := &oidc.Config{ClientID: config.aud, SkipClientIDCheck: config.skipAudienceCheck}
		verifier = oidc.NewVerifier(oidcTokenIssueURL, keySet, config)
	}
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, "verify idToken")
	}
	return idToken, nil
}
