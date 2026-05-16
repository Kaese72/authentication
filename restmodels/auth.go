package restmodels

type LoginRequest struct {
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
}

type LoginResponse struct {
	UseToken string `json:"use-token"`
}
