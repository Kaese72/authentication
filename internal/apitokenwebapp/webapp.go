// Package apitokenwebapp lets users provision, list and revoke their own API
// tokens, and answers other services' introspection calls for them.
//
// The rules, all enforced here:
//   - Creating a token requires a session that began with a local username
//     and password login. A cloud session is re-checked against the cloud on
//     every refresh; letting it mint a token that never is would let a
//     revoked cloud user keep access.
//   - Listing and deleting tokens work from any session, cloud included:
//     neither creates lasting access.
//   - The authentication service itself never accepts API tokens (main.go
//     uses usertoken.Middleware, which refuses them), so a token can never
//     be used to manage tokens, users or passwords.
//   - A token's scope may not exceed its owner's permissions at creation,
//     never includes admin, and is intersected with the owner's current
//     permissions on every introspection.
package apitokenwebapp

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/Kaese72/authentication/usertoken"
	"github.com/danielgtaylor/huma/v2"
)

// maxTokensPerUser bounds how many API tokens one user may hold at once.
const maxTokensPerUser = 50

// lastUsedResolution is how stale a token's lastUsedAt may get before an
// introspection updates it, so a busy token does not write on every call.
const lastUsedResolution = time.Minute

type webApp struct {
	persistence persistence.APITokenPersistenceDB
	now         func() time.Time
}

func NewWebApp(p persistence.APITokenPersistenceDB) webApp {
	return webApp{persistence: p, now: time.Now}
}

func toResourcePermissions(p usertoken.Permissions) map[string]restmodels.ResourcePermission {
	resources := make(map[string]restmodels.ResourcePermission, len(usertoken.KnownResources))
	for _, resource := range usertoken.KnownResources {
		resources[resource] = restmodels.ResourcePermission{View: p.HasView(resource), Modify: p.HasModify(resource)}
	}
	return resources
}

func toAPITokenResponse(t persistence.APIToken) restmodels.APITokenResponse {
	return restmodels.APITokenResponse{
		ID:         t.ID,
		Name:       t.Name,
		Prefix:     usertoken.APITokenPrefix + t.PublicID,
		Resources:  toResourcePermissions(t.Permissions),
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
	}
}

func isKnownResource(code string) bool {
	for _, resource := range usertoken.KnownResources {
		if resource == code {
			return true
		}
	}
	return false
}

// callerID returns the authenticated caller's user ID, as placed in the
// context by usertoken.Middleware.
func callerID(ctx context.Context) (int64, error) {
	id, ok := usertoken.UserID(ctx)
	if !ok {
		return 0, huma.Error401Unauthorized("authentication required")
	}
	return id, nil
}

// CreateMyAPIToken provisions an API token for the caller and returns it -
// the only time it is ever revealed.
func (app webApp) CreateMyAPIToken(ctx context.Context, input *struct {
	Body restmodels.CreateAPITokenRequest
}) (*struct {
	Body restmodels.CreateAPITokenResponse
}, error) {
	id, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	// Defense in depth: this service refuses API tokens outright, but an
	// API-token session must never be able to mint more of them either.
	if method, _ := usertoken.LoginMethodFromContext(ctx); method != usertoken.LoginMethodLocal {
		return nil, huma.Error403Forbidden("creating an API token requires logging in locally with a username and password")
	}

	name := strings.TrimSpace(input.Body.Name)
	if name == "" {
		return nil, huma.Error400BadRequest("name must not be blank")
	}
	grants := map[string]usertoken.ResourceGrant{}
	for resource, rp := range input.Body.Resources {
		if !isKnownResource(resource) {
			return nil, huma.Error400BadRequest("unknown resource: " + resource)
		}
		var grant usertoken.ResourceGrant
		if rp.View {
			grant.View = "*"
		}
		if rp.Modify {
			grant.Modify = "*"
		}
		grants[resource] = grant
	}
	scope := usertoken.NewPermissions(grants)
	if len(scope.Resources()) == 0 {
		return nil, huma.Error400BadRequest("an API token must grant access to at least one resource")
	}

	// Checked against the stored user, not the use token's claims, which
	// can be minutes stale.
	user, err := app.persistence.GetUserByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, huma.Error401Unauthorized("user no longer exists")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	if user.PasswordHash == "" {
		return nil, huma.Error403Forbidden("creating an API token requires logging in locally with a username and password")
	}
	if !user.Permissions.Covers(scope) {
		return nil, huma.Error403Forbidden("an API token cannot grant more than your own permissions")
	}

	existing, err := app.persistence.ListAPITokens(ctx, id)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list API tokens")
	}
	if len(existing) >= maxTokensPerUser {
		return nil, huma.Error409Conflict("too many API tokens; delete one first")
	}

	token, publicID, secretHash, err := usertoken.GenerateAPIToken()
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate API token")
	}
	now := app.now().UTC().Truncate(time.Second)
	stored := persistence.APIToken{
		UserID:      id,
		PublicID:    publicID,
		SecretHash:  secretHash,
		Name:        name,
		Permissions: scope,
		CreatedAt:   now,
	}
	if input.Body.ExpiresInDays != nil {
		expiresAt := now.AddDate(0, 0, *input.Body.ExpiresInDays)
		stored.ExpiresAt = &expiresAt
	}
	stored.ID, err = app.persistence.CreateAPIToken(ctx, stored)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to store API token")
	}
	logging.Info("created API token", ctx, map[string]interface{}{"userId": id, "apiTokenId": stored.ID})
	return &struct {
		Body restmodels.CreateAPITokenResponse
	}{Body: restmodels.CreateAPITokenResponse{Token: token, APIToken: toAPITokenResponse(stored)}}, nil
}

// ListMyAPITokens lists the caller's API tokens, without revealing them.
func (app webApp) ListMyAPITokens(ctx context.Context, input *struct{}) (*struct {
	Body []restmodels.APITokenResponse
}, error) {
	id, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	tokens, err := app.persistence.ListAPITokens(ctx, id)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list API tokens")
	}
	resp := make([]restmodels.APITokenResponse, len(tokens))
	for i, t := range tokens {
		resp[i] = toAPITokenResponse(t)
	}
	return &struct {
		Body []restmodels.APITokenResponse
	}{Body: resp}, nil
}

// DeleteMyAPIToken revokes one of the caller's API tokens. Allowed from any
// session, cloud included: revoking never creates access.
func (app webApp) DeleteMyAPIToken(ctx context.Context, input *struct {
	TokenID int64 `path:"tokenId"`
}) (*struct{}, error) {
	id, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	err = app.persistence.DeleteAPIToken(ctx, id, input.TokenID)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("API token not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to delete API token")
	}
	logging.Info("deleted API token", ctx, map[string]interface{}{"userId": id, "apiTokenId": input.TokenID})
	return &struct{}{}, nil
}

// invalidToken is the introspection endpoint's answer for any token it does
// not accept. Every reason gets the same answer, so the endpoint reveals
// nothing about which tokens exist. The header tells usertoken.Introspector
// this 401 is about the API token, not about the calling service's own
// ServiceAccount credentials.
func invalidToken() error {
	return huma.ErrorWithHeaders(
		huma.Error401Unauthorized("invalid API token"),
		http.Header{usertoken.IntrospectInvalidHeader: []string{"1"}},
	)
}

// Introspect looks an API token up for another service, which presents it on
// a caller's behalf. Only reachable on the internal listener, by
// allow-listed ServiceAccounts (see main.go).
func (app webApp) Introspect(ctx context.Context, input *struct {
	Body restmodels.IntrospectAPITokenRequest
}) (*struct {
	Body restmodels.IntrospectAPITokenResponse
}, error) {
	publicID, secretHash, ok := usertoken.ParseAPIToken(input.Body.Token)
	if !ok {
		return nil, invalidToken()
	}
	token, err := app.persistence.GetAPITokenByPublicID(ctx, publicID)
	if err == sql.ErrNoRows {
		return nil, invalidToken()
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up API token")
	}
	if subtle.ConstantTimeCompare(token.SecretHash, secretHash) != 1 {
		return nil, invalidToken()
	}
	now := app.now()
	if token.ExpiresAt != nil && !now.Before(*token.ExpiresAt) {
		return nil, invalidToken()
	}
	user, err := app.persistence.GetUserByID(ctx, token.UserID)
	if err == sql.ErrNoRows {
		return nil, invalidToken()
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	// Tokens can only be created by users with a local password, but should
	// one ever be left on an account without one, it must not work.
	if user.PasswordHash == "" {
		return nil, invalidToken()
	}

	if token.LastUsedAt == nil || now.Sub(*token.LastUsedAt) >= lastUsedResolution {
		if err := app.persistence.TouchAPIToken(ctx, token.ID, now); err != nil {
			// Bookkeeping only: never fail the request over it.
			logging.ErrorErr(err, ctx)
		}
	}

	effective := user.Permissions.Intersect(token.Permissions)
	raw, err := permissionsToRaw(effective)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to encode permissions")
	}
	return &struct {
		Body restmodels.IntrospectAPITokenResponse
	}{Body: restmodels.IntrospectAPITokenResponse{
		UserID:      user.ID,
		Permissions: raw,
		ExpiresAt:   token.ExpiresAt,
	}}, nil
}

// permissionsToRaw renders p in the hp claim's JSON shape, via its own
// MarshalJSON so the shape is defined in exactly one place.
func permissionsToRaw(p usertoken.Permissions) (map[string]any, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	raw := map[string]any{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
