package restwebapp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/Kaese72/authentication/usertoken"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func generateUseToken(privateKey *rsa.PrivateKey, id int64, expiry time.Duration, permissions usertoken.Permissions) (string, error) {
	return usertoken.Sign(privateKey, id, expiry, permissions)
}

// claimCloudVerified is the refresh-token claim holding the unix time the
// user's cloud access was last successfully confirmed. Only cloud users'
// refresh tokens carry it.
const claimCloudVerified = "cv"

func generateRefreshToken(secret string, id int64, expiry time.Duration, cloudVerifiedAt time.Time) (string, error) {
	claims := jwt.MapClaims{
		"id":  id,
		"exp": time.Now().Add(expiry).Unix(),
		"iat": time.Now().Unix(),
	}
	if !cloudVerifiedAt.IsZero() {
		claims[claimCloudVerified] = cloudVerifiedAt.Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func claimsToID(claims jwt.MapClaims) (id int64, err error) {
	idFloat, ok := claims["id"].(float64)
	if !ok {
		return 0, errors.New("invalid id claim")
	}
	return int64(idFloat), nil
}

func ValidateUseToken(publicKey *rsa.PublicKey, tokenString string) (id int64, permissions usertoken.Permissions, err error) {
	return usertoken.Verify(publicKey, tokenString)
}

// validateRefreshToken verifies a refresh token and returns the user id it
// was issued for and, for cloud users, when their cloud access was last
// confirmed (zero if the token carries no such claim).
func validateRefreshToken(secret string, tokenString string) (id int64, cloudVerifiedAt time.Time, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return 0, time.Time{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, time.Time{}, errors.New("invalid token")
	}
	id, err = claimsToID(claims)
	if err != nil {
		return 0, time.Time{}, err
	}
	if cv, ok := claims[claimCloudVerified].(float64); ok {
		cloudVerifiedAt = time.Unix(int64(cv), 0)
	}
	return id, cloudVerifiedAt, nil
}
