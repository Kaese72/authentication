package restmodels

import "time"

type LoginRequest struct {
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
}

type LoginResponse struct {
	UseToken string `json:"use-token"`
}

// ImpersonateResponse is the REST shape returned by POST
// .../internal/impersonate/{id}: a short-lived use token for the target
// user, carrying that user's own real permissions. Returned only to a
// caller already authenticated as a trusted Kubernetes ServiceAccount (see
// huemie-lib/k8sauth) -- there is no refresh cookie, since the token is
// meant to be used once, immediately, and discarded.
type ImpersonateResponse struct {
	UseToken  string    `json:"use-token"`
	ExpiresAt time.Time `json:"expiresAt"`
}
