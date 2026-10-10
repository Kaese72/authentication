package config

import (
	"context"
	"os"
	"strings"

	"github.com/Kaese72/authentication/internal/logging"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type DatabaseConfig struct {
	Host     string `json:"host" mapstructure:"host"`
	Port     int    `json:"port" mapstructure:"port"`
	User     string `json:"user" mapstructure:"user"`
	Password string `json:"password" mapstructure:"password"`
	Database string `json:"database" mapstructure:"database"`
}

func (conf DatabaseConfig) Validate() error {
	if conf.Host == "" {
		return errors.New("must supply database host")
	}
	return nil
}

type AuthConfig struct {
	RSAPrivateKeyPath      string `json:"rsa-private-key-path" mapstructure:"rsa-private-key-path"`
	RefreshSecret          string `json:"refresh-secret" mapstructure:"refresh-secret"`
	UseTokenExpiryMinutes  int    `json:"use-token-expiry-minutes" mapstructure:"use-token-expiry-minutes"`
	RefreshTokenExpiryDays int    `json:"refresh-token-expiry-days" mapstructure:"refresh-token-expiry-days"`
}

func (conf AuthConfig) Validate() error {
	if conf.RSAPrivateKeyPath == "" {
		return errors.New("must supply auth rsa-private-key-path")
	}
	if conf.RefreshSecret == "" {
		return errors.New("must supply auth refresh-secret")
	}
	return nil
}

// CloudConfig configures "log in with Humi Cloud". It is optional: with no
// ConnectClientURL, the feature is off and the login page does not offer it.
type CloudConfig struct {
	// ConnectClientURL is the base URL of this appliance's
	// cloud-connect-client service, e.g. http://cloud-connect-client:8080.
	ConnectClientURL string `json:"connect-client-url" mapstructure:"connect-client-url"`
	// ServiceAccountTokenPath is this pod's own projected, audience-bound
	// Kubernetes ServiceAccount token, presented to cloud-connect-client's
	// internal listener -- verified there via the TokenReview API
	// (huemie-lib/k8sauth), the same mechanism the chatbot service uses
	// against this service's own internal listener.
	ServiceAccountTokenPath string `json:"service-account-token-path" mapstructure:"service-account-token-path"`
	// StateExpiryMinutes bounds how long a browser has to complete the
	// cloud leg of a login before coming back.
	StateExpiryMinutes int `json:"state-expiry-minutes" mapstructure:"state-expiry-minutes"`
	// AccessGraceHours is how long a cloud user's session may keep being
	// refreshed when the cloud cannot be reached to re-check their access,
	// measured from the last successful check. The appliance is meant to
	// keep working through an internet outage; an explicit "no access" from
	// the cloud always ends the session immediately regardless.
	AccessGraceHours int `json:"access-grace-hours" mapstructure:"access-grace-hours"`
}

func (conf CloudConfig) Validate() error {
	if conf.ConnectClientURL != "" && conf.ServiceAccountTokenPath == "" {
		return errors.New("must supply cloud service-account-token-path when cloud connect-client-url is set")
	}
	return nil
}

// InternalConfig configures the internal listener used only by other
// services acting as a trusted Kubernetes ServiceAccount (e.g. the chatbot
// minting an impersonation token) -- never by an ordinary human use token.
// See huemie-lib/k8sauth.RequireServiceAccount, which this listener's
// middleware is built from.
type InternalConfig struct {
	// ListenAddr is the internal listener's bind address, separate from the
	// public API's.
	ListenAddr string `json:"listen-addr" mapstructure:"listen-addr"`
	// TokenAudience is the audience a caller's ServiceAccount token must have
	// been issued for.
	TokenAudience string `json:"token-audience" mapstructure:"token-audience"`
	// ImpersonationTokenExpirySeconds bounds the lifetime of a token minted
	// by POST .../internal/impersonate/{id}. Short, since a caller fetches
	// one fresh immediately before using it and never holds it.
	ImpersonationTokenExpirySeconds int `json:"impersonation-token-expiry-seconds" mapstructure:"impersonation-token-expiry-seconds"`
}

func (conf InternalConfig) Validate() error {
	if conf.ListenAddr == "" {
		return errors.New("must supply internal listen-addr")
	}
	if conf.TokenAudience == "" {
		return errors.New("must supply internal token-audience")
	}
	return nil
}

// DebugConfig holds settings that exist only to make local development
// possible and must never be set in a real deployment -- kept under its own
// `debug.*` path specifically so that is obvious. None of it is validated as
// required; every field's zero value means "use the real, production
// behavior".
type DebugConfig struct {
	// Namespace overrides huemie-lib/k8sauth.CurrentNamespace() for the
	// internal listener's ServiceAccount check. Only needed when running
	// outside a pod (so there is no real
	// /var/run/secrets/kubernetes.io/serviceaccount/namespace file to read)
	// -- e.g. a local dev cluster where this process runs on the host
	// rather than in-cluster. Left empty, the real namespace is read as
	// normal.
	Namespace string `json:"namespace" mapstructure:"namespace"`
}

// KubernetesConfig configures this process's own Kubernetes clientset, used
// by huemie-lib/k8sauth to verify the ServiceAccount tokens presented to the
// internal listener.
type KubernetesConfig struct {
	// ApiserverProxyURL, if set, routes TokenReview calls through an HTTP
	// CONNECT proxy dedicated to reaching the apiserver -- see
	// huemie-lib/k8sauth.NewInClusterClientset for why this must be supplied
	// explicitly rather than via a generic HTTPS_PROXY env var: this process
	// also calls out to the cloud (CloudConfig.ConnectClientURL and beyond),
	// and a blanket HTTPS_PROXY would silently route that traffic through the
	// same apiserver-only proxy too, which refuses to CONNECT anywhere else.
	ApiserverProxyURL string `json:"apiserver-proxy-url" mapstructure:"apiserver-proxy-url"`
}

type Config struct {
	Database   DatabaseConfig   `json:"database" mapstructure:"database"`
	Auth       AuthConfig       `json:"auth" mapstructure:"auth"`
	Cloud      CloudConfig      `json:"cloud" mapstructure:"cloud"`
	Internal   InternalConfig   `json:"internal" mapstructure:"internal"`
	Kubernetes KubernetesConfig `json:"kubernetes" mapstructure:"kubernetes"`
	Debug      DebugConfig      `json:"debug" mapstructure:"debug"`
}

func (conf Config) Validate() error {
	if err := conf.Database.Validate(); err != nil {
		return err
	}
	if err := conf.Auth.Validate(); err != nil {
		return err
	}
	if err := conf.Cloud.Validate(); err != nil {
		return err
	}
	if err := conf.Internal.Validate(); err != nil {
		return err
	}
	return nil
}

var Loaded Config

func init() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	viper.BindEnv("database.host")
	viper.BindEnv("database.port")
	viper.BindEnv("database.user")
	viper.BindEnv("database.password")
	viper.BindEnv("database.database")
	viper.SetDefault("database.port", 3306)
	viper.SetDefault("database.database", "authentication")

	viper.BindEnv("auth.rsa-private-key-path")
	viper.BindEnv("auth.refresh-secret")
	viper.BindEnv("auth.use-token-expiry-minutes")
	viper.SetDefault("auth.use-token-expiry-minutes", 10)
	viper.BindEnv("auth.refresh-token-expiry-days")
	viper.SetDefault("auth.refresh-token-expiry-days", 7)

	viper.BindEnv("cloud.connect-client-url")
	viper.BindEnv("cloud.service-account-token-path")
	viper.SetDefault("cloud.service-account-token-path", "/var/run/secrets/tokens/cloud-connect-client-internal")
	viper.BindEnv("cloud.state-expiry-minutes")
	viper.SetDefault("cloud.state-expiry-minutes", 5)
	viper.BindEnv("cloud.access-grace-hours")
	viper.SetDefault("cloud.access-grace-hours", 24)

	viper.BindEnv("logging.stdout")
	viper.SetDefault("logging.stdout", true)
	viper.BindEnv("logging.http.url")

	viper.BindEnv("internal.listen-addr")
	viper.SetDefault("internal.listen-addr", ":8081")
	viper.BindEnv("internal.token-audience")
	viper.SetDefault("internal.token-audience", "humi-authentication-internal")
	viper.BindEnv("internal.impersonation-token-expiry-seconds")
	viper.SetDefault("internal.impersonation-token-expiry-seconds", 60)

	viper.BindEnv("kubernetes.apiserver-proxy-url")

	// Local-development-only overrides. Never set these in a real
	// deployment -- see DebugConfig.
	viper.BindEnv("debug.namespace")

	err := viper.Unmarshal(&Loaded)
	if err != nil {
		logging.Error(err.Error(), context.TODO())
		os.Exit(1)
	}
}
