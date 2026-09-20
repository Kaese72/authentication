// Package cloudclient talks to the appliance's cloud-connect-client service,
// which holds the appliance's cloud credentials and is therefore the only
// thing on the appliance that talks to the cloud. The authentication service
// uses it to offer "log in with Humi Cloud" and to re-check a cloud user's
// access when their session is refreshed.
package cloudclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ErrNotConfigured is returned by every call when no cloud-connect-client URL
// is configured, i.e. cloud login is switched off.
var ErrNotConfigured = errors.New("cloud login is not configured")

// ErrRefused means the cloud (via cloud-connect-client) understood the
// request and refused it - e.g. a login code that is invalid, expired, or
// belongs to a user who no longer has access. It is distinct from any other
// error, which means no answer could be obtained.
var ErrRefused = errors.New("cloud login refused")

// ErrNotEnrolled means the appliance has not been enrolled with the cloud, so
// there is nothing to log in against.
var ErrNotEnrolled = errors.New("appliance is not enrolled with the cloud")

type CloudUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
}

type Client interface {
	// Available reports whether cloud login can currently be offered.
	Available(ctx context.Context) (bool, error)
	// Start returns the cloud URL to send the browser to.
	Start(ctx context.Context, state string, returnTo string) (string, error)
	// Redeem exchanges the login code the browser returned with for the
	// cloud user it was issued to.
	Redeem(ctx context.Context, code string) (CloudUser, error)
	// CheckAccess reports whether cloudUserID still has access to this
	// appliance. An error means no answer could be obtained (as opposed to
	// "no").
	CheckAccess(ctx context.Context, cloudUserID int64) (bool, error)
}

type httpClient struct {
	baseURL      string
	serviceToken string
	httpClient   *http.Client
}

// New returns a Client for the cloud-connect-client at baseURL. An empty
// baseURL yields a Client whose every call fails with ErrNotConfigured (and
// whose Available is simply false).
func New(baseURL string, serviceToken string) Client {
	if baseURL == "" {
		return disabled{}
	}
	return httpClient{baseURL: baseURL, serviceToken: serviceToken, httpClient: &http.Client{Timeout: 15 * time.Second}}
}

type disabled struct{}

func (disabled) Available(context.Context) (bool, error) { return false, nil }
func (disabled) Start(context.Context, string, string) (string, error) {
	return "", ErrNotConfigured
}
func (disabled) Redeem(context.Context, string) (CloudUser, error) {
	return CloudUser{}, ErrNotConfigured
}
func (disabled) CheckAccess(context.Context, int64) (bool, error) {
	return false, ErrNotConfigured
}

func (c httpClient) do(ctx context.Context, method string, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/cloud-connect-client/v0/internal/cloud-login"+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.serviceToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return json.Unmarshal(respBody, out)
	case resp.StatusCode == http.StatusConflict:
		return ErrNotEnrolled
	case resp.StatusCode == http.StatusForbidden:
		return ErrRefused
	default:
		return fmt.Errorf("cloud-connect-client request failed with status %d: %s", resp.StatusCode, string(respBody))
	}
}

func (c httpClient) Available(ctx context.Context) (bool, error) {
	var out struct {
		Available bool `json:"available"`
	}
	if err := c.do(ctx, http.MethodGet, "/status", nil, &out); err != nil {
		return false, err
	}
	return out.Available, nil
}

func (c httpClient) Start(ctx context.Context, state string, returnTo string) (string, error) {
	var out struct {
		CloudURL string `json:"cloudUrl"`
	}
	if err := c.do(ctx, http.MethodPost, "/start", map[string]string{"state": state, "returnTo": returnTo}, &out); err != nil {
		return "", err
	}
	return out.CloudURL, nil
}

func (c httpClient) Redeem(ctx context.Context, code string) (CloudUser, error) {
	var out CloudUser
	err := c.do(ctx, http.MethodPost, "/redeem", map[string]string{"code": code}, &out)
	return out, err
}

func (c httpClient) CheckAccess(ctx context.Context, cloudUserID int64) (bool, error) {
	var out struct {
		Allowed bool `json:"allowed"`
	}
	if err := c.do(ctx, http.MethodGet, "/access/"+strconv.FormatInt(cloudUserID, 10), nil, &out); err != nil {
		return false, err
	}
	return out.Allowed, nil
}
