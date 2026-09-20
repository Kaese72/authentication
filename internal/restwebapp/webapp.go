package restwebapp

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/Kaese72/authentication/internal/cloudclient"
	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"golang.org/x/crypto/bcrypt"
)

const refreshCookieName = "refresh-token"
const refreshCookiePath = "/authentication-service/v0/authentication/login"

type webApp struct {
	persistence        persistence.AuthPersistenceDB
	privateKey         *rsa.PrivateKey
	refreshSecret      string
	useTokenExpiry     time.Duration
	refreshTokenExpiry time.Duration
	cloud              cloudclient.Client
	cloudStateExpiry   time.Duration
	cloudAccessGrace   time.Duration
}

func NewWebApp(p persistence.AuthPersistenceDB, privateKey *rsa.PrivateKey, refreshSecret string, useTokenExpiry time.Duration, refreshTokenExpiry time.Duration, cloud cloudclient.Client, cloudStateExpiry time.Duration, cloudAccessGrace time.Duration) webApp {
	return webApp{
		persistence:        p,
		privateKey:         privateKey,
		refreshSecret:      refreshSecret,
		useTokenExpiry:     useTokenExpiry,
		refreshTokenExpiry: refreshTokenExpiry,
		cloud:              cloud,
		cloudStateExpiry:   cloudStateExpiry,
		cloudAccessGrace:   cloudAccessGrace,
	}
}

func (app webApp) buildRefreshCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   true,
		MaxAge:   int(app.refreshTokenExpiry.Seconds()),
		SameSite: http.SameSiteStrictMode,
	}
}

type loginResult struct {
	SetCookie string `header:"Set-Cookie"`
	Body      restmodels.LoginResponse
}

// issueLogin issues a use/refresh token pair for the user. cloudVerifiedAt is
// when their cloud access was last confirmed (zero for non-cloud users) and is
// carried in the refresh token so the next refresh knows how stale it is.
func (app webApp) issueLogin(ctx context.Context, id int64, cloudVerifiedAt time.Time) (*loginResult, error) {
	useToken, err := generateUseToken(app.privateKey, id, app.useTokenExpiry)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("token generation failed")
	}
	refreshToken, err := generateRefreshToken(app.refreshSecret, id, app.refreshTokenExpiry, cloudVerifiedAt)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("token generation failed")
	}
	return &loginResult{
		SetCookie: app.buildRefreshCookie(refreshToken).String(),
		Body:      restmodels.LoginResponse{UseToken: useToken},
	}, nil
}

// recheckCloudAccess asks the cloud whether a cloud user still has access to
// this appliance, and returns the time to record as their last successful
// check. An explicit "no" - or the appliance no longer being enrolled - ends
// the session. If the cloud simply cannot be reached the session is kept
// alive, but only within cloudAccessGrace of the last successful check, so an
// internet outage does not lock cloud users out of an appliance that is
// meant to work offline, yet a revocation cannot be dodged forever by
// blocking the cloud.
func (app webApp) recheckCloudAccess(ctx context.Context, cloudUserID int64, lastVerified time.Time) (time.Time, error) {
	allowed, err := app.cloud.CheckAccess(ctx, cloudUserID)
	if err == nil {
		if allowed {
			return time.Now(), nil
		}
		return time.Time{}, huma.Error401Unauthorized("cloud access has been revoked")
	}
	if errors.Is(err, cloudclient.ErrNotEnrolled) || errors.Is(err, cloudclient.ErrNotConfigured) || errors.Is(err, cloudclient.ErrRefused) {
		return time.Time{}, huma.Error401Unauthorized("cloud login is no longer available")
	}
	logging.ErrorErr(err, ctx)
	if !lastVerified.IsZero() && time.Since(lastVerified) < app.cloudAccessGrace {
		logging.Info("cloud unreachable; keeping cloud user session alive within grace period", ctx)
		return lastVerified, nil
	}
	return time.Time{}, huma.Error401Unauthorized("unable to verify cloud access")
}

func (app webApp) Login(ctx context.Context, input *struct {
	CookieHeader string `header:"Cookie"`
	Body         *restmodels.LoginRequest
}) (*loginResult, error) {
	// Try refresh cookie first
	fakeReq := &http.Request{Header: http.Header{"Cookie": []string{input.CookieHeader}}}
	if cookie, err := fakeReq.Cookie(refreshCookieName); err == nil {
		id, cloudVerifiedAt, err := validateRefreshToken(app.refreshSecret, cookie.Value)
		if err == nil {
			user, err := app.persistence.GetUserByID(ctx, id)
			if err == nil {
				if user.CloudUserID != nil {
					cloudVerifiedAt, err = app.recheckCloudAccess(ctx, *user.CloudUserID, cloudVerifiedAt)
					if err != nil {
						return nil, err
					}
				}
				return app.issueLogin(ctx, user.ID, cloudVerifiedAt)
			}
			if err != sql.ErrNoRows {
				logging.ErrorErr(err, ctx)
				return nil, huma.Error500InternalServerError("failed to look up user")
			}
			// The user no longer exists: the refresh token is dead, fall
			// through to credentials.
		}
	}

	// Fall back to username/password
	var username, password string
	if input.Body != nil && input.Body.Username != nil {
		username = *input.Body.Username
	}
	if input.Body != nil && input.Body.Password != nil {
		password = *input.Body.Password
	}
	if username == "" || password == "" {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	user, err := app.persistence.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	// Cloud users have no local password and must log in through the cloud,
	// where their access can be re-checked.
	if user.PasswordHash == "" {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	return app.issueLogin(ctx, user.ID, time.Time{})
}
