package restmodels

// CloudLoginStatusResponse tells the login page whether to offer "log in with
// Humi Cloud": true only when cloud login is configured and the appliance is
// enrolled with the cloud.
type CloudLoginStatusResponse struct {
	Available bool `json:"available"`
}

// CloudLoginStartRequest carries the login page's own callback URL, so this
// service does not need to know the UI's origin as config.
type CloudLoginStartRequest struct {
	ReturnTo string `json:"returnTo" minLength:"1" maxLength:"512"`
}

// CloudLoginStartResponse carries the cloud URL to send the browser to and
// the state value it will come back with. The browser must remember State
// (per tab) and check it against the one in the callback URL before calling
// complete, so a login started elsewhere cannot be planted into this browser.
type CloudLoginStartResponse struct {
	State    string `json:"state"`
	CloudURL string `json:"cloudUrl"`
}

// CloudLoginCompleteRequest is what the UI's callback page collects from the
// query string the cloud redirected the browser back with.
type CloudLoginCompleteRequest struct {
	Code  string `json:"code" minLength:"1"`
	State string `json:"state" minLength:"1"`
}
