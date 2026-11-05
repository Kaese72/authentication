package usertoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// APITokenPrefix starts every API token, so Middleware can tell one apart
// from a use token (a JWT) without trying to parse it, and so a leaked one is
// easy to recognize in logs and by secret scanners.
//
// An API token is APITokenPrefix + publicID + "_" + secret, where publicID
// (16 hex characters) identifies the token's row in the authentication
// service and secret (64 hex characters, 256 random bits) is only ever
// stored there as its SHA-256 hash. The hash is deliberately a plain SHA-256,
// not a slow password hash: the secret has full entropy, so there is nothing
// for key stretching to protect, and it is checked on every introspection.
const APITokenPrefix = "humi_pat_"

const (
	apiTokenPublicIDBytes = 8
	apiTokenSecretBytes   = 32
	apiTokenLength        = len(APITokenPrefix) + apiTokenPublicIDBytes*2 + 1 + apiTokenSecretBytes*2
)

// IsAPIToken reports whether bearer looks like an API token (has the prefix),
// as opposed to a use token. It does not check the rest of its format; see
// ParseAPIToken.
func IsAPIToken(bearer string) bool {
	return strings.HasPrefix(bearer, APITokenPrefix)
}

// GenerateAPIToken returns a new random API token, together with the parts
// the authentication service stores for it: its public ID and the SHA-256
// hash of its secret. The token itself must be shown to the user once and
// never stored.
func GenerateAPIToken() (token string, publicID string, secretHash []byte, err error) {
	idBytes := make([]byte, apiTokenPublicIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", nil, err
	}
	secretBytes := make([]byte, apiTokenSecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", nil, err
	}
	publicID = hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	sum := sha256.Sum256([]byte(secret))
	return APITokenPrefix + publicID + "_" + secret, publicID, sum[:], nil
}

// ParseAPIToken splits a well-formed API token into its public ID and the
// SHA-256 hash of its secret, for looking it up and comparing against what
// is stored. ok is false for anything not exactly in GenerateAPIToken's
// format.
func ParseAPIToken(token string) (publicID string, secretHash []byte, ok bool) {
	if len(token) != apiTokenLength || !IsAPIToken(token) {
		return "", nil, false
	}
	rest := token[len(APITokenPrefix):]
	publicID, secret := rest[:apiTokenPublicIDBytes*2], rest[apiTokenPublicIDBytes*2+1:]
	if rest[apiTokenPublicIDBytes*2] != '_' || !isLowerHex(publicID) || !isLowerHex(secret) {
		return "", nil, false
	}
	sum := sha256.Sum256([]byte(secret))
	return publicID, sum[:], true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
