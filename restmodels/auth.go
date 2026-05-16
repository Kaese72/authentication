package restmodels

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	UseToken string `json:"use-token"`
}
