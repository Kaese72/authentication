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