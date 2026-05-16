package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/Kaese72/authentication/internal/config"
	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence/mariadb"
	"github.com/Kaese72/authentication/internal/restwebapp"
	"github.com/Kaese72/authentication/internal/setupwebapp"
	"github.com/Kaese72/authentication/internal/userwebapp"
	"github.com/Kaese72/huemie-lib/middleware"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humamux"
	"github.com/gorilla/mux"

	_ "go.elastic.co/apm/module/apmsql/mysql"
)

func main() {
	if err := config.Loaded.Validate(); err != nil {
		logging.Error(err.Error(), context.TODO())
		os.Exit(1)
	}

	dbPersistence, err := mariadb.NewMariadbPersistence(config.Loaded.Database)
	if err != nil {
		logging.Error(err.Error(), context.Background())
		os.Exit(1)
	}

	keyBytes, err := os.ReadFile(config.Loaded.Auth.RSAPrivateKeyPath)
	if err != nil {
		logging.Error("failed to read RSA private key: "+err.Error(), context.Background())
		os.Exit(1)
	}
	privateKey, err := restwebapp.ParseRSAPrivateKey(keyBytes)
	if err != nil {
		logging.Error("failed to parse RSA private key: "+err.Error(), context.Background())
		os.Exit(1)
	}

	useTokenExpiry := time.Duration(config.Loaded.Auth.UseTokenExpiryMinutes) * time.Minute
	refreshTokenExpiry := time.Duration(config.Loaded.Auth.RefreshTokenExpiryDays) * 24 * time.Hour

	webapp := restwebapp.NewWebApp(dbPersistence, privateKey, config.Loaded.Auth.RefreshSecret, useTokenExpiry, refreshTokenExpiry)
	setupWebapp := setupwebapp.NewWebApp(dbPersistence)
	userWebapp := userwebapp.NewWebApp(dbPersistence)

	router := mux.NewRouter()
	router.Use(middleware.UseTokenMiddleware(
		&privateKey.PublicKey,
		"/authentication-service/v0/authentication/login",
		"/authentication-service/v0/setup/",
		"/authentication-service/docs",
		"/authentication-service/openapi",
	))
	humaConfig := huma.DefaultConfig("authentication", "1.0.0")
	humaConfig.OpenAPIPath = "/authentication-service/openapi"
	humaConfig.DocsPath = "/authentication-service/docs"
	api := humamux.New(router, humaConfig)

	huma.Post(api, "/authentication-service/v0/authentication/login", webapp.Login)

	huma.Get(api, "/authentication-service/v0/setup/status", setupWebapp.SetupStatus)
	huma.Post(api, "/authentication-service/v0/setup/user", setupWebapp.SetupUser)

	huma.Get(api, "/authentication-service/v0/users", userWebapp.ListUsers)
	huma.Post(api, "/authentication-service/v0/users", userWebapp.CreateUser)
	huma.Get(api, "/authentication-service/v0/users/{username}", userWebapp.GetUser)
	huma.Delete(api, "/authentication-service/v0/users/{username}", userWebapp.DeleteUser)

	if err := http.ListenAndServe(":8080", router); err != nil {
		logging.Error(err.Error(), context.TODO())
	}
}
