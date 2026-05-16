package restmodels

type UserResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
