# Authentication service

This service keeps track of authentication for an appliance.

## Authentication architecture

The entire system utilizes JWTs to keep track of authentication.
Each authenticated user gets two tokens

* A `use` token, and
* A `refresh` token

The `use` token is what each service will be able to authenticate
and grant access based on. However, a user won't be able to 
re-authenticate with this token. When it expires, the `refresh` 
is required to get a new one.

The `refresh` token, expected to have a higher degree of security
around it is used to regularly re-issue a `use` token.

### Token architecture

#### `use` token architecture

The `use` token is simply sent back in a HTTP response from *Authentication Service*.
The `use` token is expected to be used by Javascript so we just
send it back to the user in the response. The `use` token is expected
to be short lived, around 10 minutes, but is expected to be refreshed 
continously while the user interacts with the UI.

The `use` token should be asymmetrically signed such that each
service does not need to have the secret, but rather a public key
of the *Authentication Service*. *Authentication Service* is the only
entity allowed to issue new `use` tokens (and obviously `refresh` tokens).

However, each service that needs authentication, like the `device-store`
or `adapter-attendant` needs to verify the signature of the `use` token.
Therefore they need the public key of the *Authentication Service* for
signature verification. No round trip to *Authentication Service* should
be necessary. This is expected to be passed in via configuration to each
service that requires authentication.

##### Go services: the `usertoken` package

This service owns the `use` token format, so it also exports the code that
signs and verifies it: the public Go package
`github.com/Kaese72/authentication/usertoken` (part of this module, not a
separate one). Go services that need to authenticate callers import it
instead of re-implementing the format:

* `usertoken.Middleware(publicKey, skipPrefixes...)` requires a valid `use`
  token as a bearer token, answering 401 otherwise. Any token that is not
  a well-formed `use` token, including one without a valid `id` claim, is
  rejected.
* `usertoken.UserID(ctx)` returns the authenticated user's ID (the `id`
  claim) inside a handler behind that middleware.
* `usertoken.LoadPublicKeyFromFile(path)` loads this service's PKIX
  PEM-encoded RSA public key, for passing to the above.
* `usertoken.Verify` / `usertoken.Sign` are the underlying verify and
  issue functions. Only this service, which holds the private key, should
  ever call `Sign`.

The package deliberately depends only on the JWT library and `huemie-lib`,
so importing it does not pull this service's own dependencies (database
driver, APM, ...) into the importing service.

#### `refresh` token architecture

The `refresh` token is expected to be signed by a symmetric key
unique to `refresh` tokens (separate secret from `use` tokens).
The *Authentication Service* is the only service aware of the secret
for `refresh` tokens.

`Refresh` tokens are sent in HTTPonly, Secure, path restricted cookies
to make sure only the *Authentication Service* gets it. 

The `refresh` token is expected to be sent along to an authentication
endpoint, `/authentication-service/v0/authentication/login` which
will

* If a valid `refresh` token is passed along in the `refresh-cookie`
  * Renew `refresh` token in cookie, such that the expiry is pushed forward
  * Return a `use` token in the HTTP response body
* If no valid `refresh` token is passed along
  * Check for username/password in the request.
    * If valid credentials are provided
      * set `refresh` token in cookie and return `use` token
    * If no valid credentials are provided
      * HTTP/401

The `refresh` token currently expires after 1 week of inactivity.
Since the token is re-issued with every authentication request
the session will never expire from the user perspective.

[FUTURE] Eventually we will want the `refresh` token to be invalidated
when a user logout, meaning we will need to keep track of the tokens
This is not implemented yet, but we should prepare for it. 

### Logging in

The authentication endpoint, `/authentication-service/v0/authentication/login`,
first checks for a `refresh` token. If none exists, then it looks for
username/password credentials.

Successful authentication leads to a `refresh` token and `use` token.
Both failing leads to HTTP/401.

Presenting a `refresh` token also requires the user it was issued for to still
exist; a token for a deleted user is treated as no token at all.

### Logging in with Humi Cloud

If the appliance is enrolled with the cloud (see `cloud-connect`), the login
page offers **Log in with Humi Cloud**: anyone who is a member of the cloud
Group that owns the appliance can log in without a local password. The flow
is redirect-based, and never puts a cloud token on the appliance - see
appliance-registry's README, "Cloud login", for the cloud half.

* `GET  /authentication-service/v0/authentication/cloud/status` - whether to
  offer it (cloud login is configured and the appliance is enrolled).
* `POST /authentication-service/v0/authentication/cloud/start` - takes the
  UI's callback URL, remembers a one-time `state`, and returns that `state`
  and the cloud URL to send the browser to. The UI keeps the `state` for the
  tab and refuses a callback whose `state` differs, so a login started
  elsewhere can't be planted into it.
* `POST /authentication-service/v0/authentication/cloud/complete` - takes the
  `code` and `state` the cloud redirected back with. It consumes the `state`,
  redeems the `code` with the cloud (only a user who currently has access
  gets an identity back), finds or creates the local user, and returns a
  `use` token and `refresh` cookie exactly like a password login.

The authentication service never talks to the cloud itself: it goes through
`cloud-connect-client`'s internal listener (port 8081, never routed by the
ingress, so not reachable through the cloud tunnel), which holds the
appliance's cloud credentials. Configure it with `CLOUD_CONNECT_CLIENT_URL`
and `CLOUD_SERVICE_TOKEN` (which must be one of the client's
`AUTH_INTERNAL_SERVICE_TOKENS`). With no `CLOUD_CONNECT_CLIENT_URL`, cloud
login is simply off.

**Cloud users.** A cloud user gets a local `users` row linked by
`cloudUserId`, with no password - they can only log in through the cloud, and
cannot set a local password (which would be a way in that never re-checks
their access). Users are matched on the cloud user id, never on username, so a
cloud user cannot take over an existing local account; if their cloud username
is taken locally they get `<username>-cloud-<id>`. Name and email follow the
cloud on each login. Every cloud member of the owning Group currently gets a
full local user; there is no per-user role on the appliance yet.

**Re-checking access.** When a cloud user's `refresh` token is presented, the
service asks the cloud (via `cloud-connect-client`) whether they still have
access, instead of just renewing:

* **Yes** - renew as usual, stamping the time of the check into the new
  `refresh` token (`cv` claim).
* **No** (removed from the Group, appliance revoked, or the appliance's cloud
  credentials no longer accepted) or the appliance is no longer enrolled -
  HTTP/401 straight away.
* **Cloud unreachable** - the appliance is meant to keep working without
  internet, so the session is renewed anyway, but only while the last
  successful check (`cv`) is less than `CLOUD_ACCESS_GRACE_HOURS` old
  (default 24). The timestamp is *not* advanced during an outage, so blocking
  the cloud cannot extend access past the grace period.

Since `use` tokens live 10 minutes and the UI refreshes every 8, a revocation
takes effect within about ten minutes.