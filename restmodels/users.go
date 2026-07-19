package restmodels

type UserResponse struct {
	ID       int64   `json:"id"`
	Username string  `json:"username"`
	Name     string  `json:"name"`
	Surname  string  `json:"surname"`
	Email    *string `json:"email,omitempty"`
}

type CreateUserRequest struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	Name     string  `json:"name"`
	Surname  string  `json:"surname"`
	Email    *string `json:"email,omitempty"`
}

type UpdateUserRequest struct {
	Name    string  `json:"name"`
	Surname string  `json:"surname"`
	Email   *string `json:"email,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}
