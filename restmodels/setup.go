package restmodels

type SetupStatus struct {
	User bool `json:"user"`
}

type SetupUserRequest struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	Name     string  `json:"name"`
	Surname  string  `json:"surname"`
	Email    *string `json:"email,omitempty"`
}
