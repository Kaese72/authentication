package restwebapp

import (
	"context"
	"crypto/rsa"
	"net/http"
	"time"

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
}

func NewWebApp(p persistence.AuthPersistenceDB, privateKey *rsa.PrivateKey, refreshSecret string, useTokenExpiry time.Duration, refreshTokenExpiry time.Duration) webApp {
	return webApp{
		persistence:        p,
		privateKey:         privateKey,
		refreshSecret:      refreshSecret,
		useTokenExpiry:     useTokenExpiry,
		refreshTokenExpiry: refreshTokenExpiry,
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

func (app webApp) issueTokenPair(id int64) (useToken string, refreshToken string, err error) {
	useToken, err = generateUseToken(app.privateKey, id, app.useTokenExpiry)
	if err != nil {
		return
	}
	refreshToken, err = generateRefreshToken(app.refreshSecret, id, app.refreshTokenExpiry)
	return
}

func (app webApp) Login(ctx context.Context, input *struct {
	CookieHeader string               `header:"Cookie"`
	Body         *restmodels.LoginRequest
}) (*struct {
	SetCookie string `header:"Set-Cookie"`
	Body      restmodels.LoginResponse
}, error) {
	// Try refresh cookie first
	fakeReq := &http.Request{Header: http.Header{"Cookie": []string{input.CookieHeader}}}
	if cookie, err := fakeReq.Cookie(refreshCookieName); err == nil {
		id, err := validateRefreshToken(app.refreshSecret, cookie.Value)
		if err == nil {
			useToken, refreshToken, err := app.issueTokenPair(id)
			if err != nil {
				logging.ErrorErr(err, ctx)
				return nil, huma.Error500InternalServerError("token generation failed")
			}
			return &struct {
				SetCookie string `header:"Set-Cookie"`
				Body      restmodels.LoginResponse
			}{
				SetCookie: app.buildRefreshCookie(refreshToken).String(),
				Body:      restmodels.LoginResponse{UseToken: useToken},
			}, nil
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}

	useToken, refreshToken, err := app.issueTokenPair(user.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("token generation failed")
	}
	return &struct {
		SetCookie string `header:"Set-Cookie"`
		Body      restmodels.LoginResponse
	}{
		SetCookie: app.buildRefreshCookie(refreshToken).String(),
		Body:      restmodels.LoginResponse{UseToken: useToken},
	}, nil
}
