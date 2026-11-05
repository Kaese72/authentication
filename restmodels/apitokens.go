package restmodels

import "time"

// CreateAPITokenRequest provisions an API token for the calling user.
// Resources is the token's scope, which may not exceed the caller's own
// permissions; resources left out get no access. API tokens can never carry
// the admin flag.
type CreateAPITokenRequest struct {
	Name      string                        `json:"name" minLength:"1" maxLength:"100"`
	Resources map[string]ResourcePermission `json:"resources"`
	// ExpiresInDays, if set, makes the token stop working that many days
	// from now. Left out, the token never expires.
	ExpiresInDays *int `json:"expiresInDays,omitempty" minimum:"1" maximum:"3650"`
}

// APITokenResponse describes an API token without revealing it.
type APITokenResponse struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Prefix is the token's non-secret beginning, to help tell tokens
	// apart.
	Prefix string `json:"prefix"`
	// Resources is the token's scope as created. What it grants at any
	// moment is this narrowed to its owner's current permissions.
	Resources  map[string]ResourcePermission `json:"resources"`
	CreatedAt  time.Time                     `json:"createdAt"`
	ExpiresAt  *time.Time                    `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time                    `json:"lastUsedAt,omitempty"`
}

// CreateAPITokenResponse is the only time the token itself is ever returned.
type CreateAPITokenResponse struct {
	Token    string           `json:"token"`
	APIToken APITokenResponse `json:"apiToken"`
}

// IntrospectAPITokenRequest is the body of the internal introspection
// endpoint; see usertoken.IntrospectRequest, which it must match.
type IntrospectAPITokenRequest struct {
	Token string `json:"token"`
}

// IntrospectAPITokenResponse is the internal introspection endpoint's answer
// for a valid token; see usertoken.IntrospectResponse, which it must match.
// Permissions is in the use token hp claim's shape.
type IntrospectAPITokenResponse struct {
	UserID      int64          `json:"userId"`
	Permissions map[string]any `json:"permissions"`
	ExpiresAt   *time.Time     `json:"expiresAt,omitempty"`
}
