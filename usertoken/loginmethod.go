package usertoken

// ClaimLoginMethod is the name of the use token claim ("lm") recording how the
// session it belongs to was established. See LoginMethod.
const ClaimLoginMethod = "lm"

// LoginMethod is how a caller authenticated. For a use token it is the lm
// claim, carried unchanged across refreshes of the same session; for a
// request authenticated with an API token, Middleware sets it to
// LoginMethodAPIToken.
//
// It exists so that operations which create lasting access - provisioning an
// API token, say - can demand a local login: a cloud session is re-checked
// against the cloud on every refresh, and must not be able to mint itself
// something that never is.
type LoginMethod string

const (
	// LoginMethodUnknown is a use token without an lm claim, e.g. one issued
	// before the claim existed. Treat it as "not local".
	LoginMethodUnknown LoginMethod = ""
	// LoginMethodLocal is a session that began with a local username and
	// password.
	LoginMethodLocal LoginMethod = "local"
	// LoginMethodCloud is a session that began with "Log in with Humi Cloud".
	LoginMethodCloud LoginMethod = "cloud"
	// LoginMethodImpersonation is a short-lived token a trusted service
	// minted on a user's behalf through the authentication service's internal
	// listener.
	LoginMethodImpersonation LoginMethod = "impersonation"
	// LoginMethodAPIToken is a request authenticated with an API token. Never
	// carried in a use token: only Middleware sets it.
	LoginMethodAPIToken LoginMethod = "api-token"
)

// signable reports whether m may appear in a use token's lm claim. An lm claim
// with any other value is read as LoginMethodUnknown, so a use token can never
// claim to be an API token (or anything else not listed here).
func (m LoginMethod) signable() bool {
	switch m {
	case LoginMethodLocal, LoginMethodCloud, LoginMethodImpersonation:
		return true
	}
	return false
}
