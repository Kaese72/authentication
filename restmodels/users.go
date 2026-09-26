package restmodels

// ResourceDefinition describes one resource permissions can be granted for:
// its code (used in ResourcePermission maps and UpdatePermissionsRequest) and
// a human-readable name, so a UI can build a permissions editor without
// hardcoding the set of resources.
type ResourceDefinition struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// ResourcePermission is the REST shape of one resource's grant: whether the
// caller may view and/or modify it. Modify implies view.
type ResourcePermission struct {
	View   bool `json:"view"`
	Modify bool `json:"modify"`
}

// PermissionsResponse is the REST shape of a user's permissions. When Admin
// is true, Resources is omitted - the admin flag alone grants everything.
// Otherwise Resources carries every known resource code, including ones with
// no access, so a permissions editor always has a fixed set of rows to show.
type PermissionsResponse struct {
	Admin     bool                          `json:"admin"`
	Resources map[string]ResourcePermission `json:"resources,omitempty"`
}

// UpdatePermissionsRequest replaces a user's per-resource grants wholesale.
// It cannot grant or revoke admin - see SetAdminRequest - so it is safe to
// call for a user without also knowing or affecting their admin status.
type UpdatePermissionsRequest struct {
	Resources map[string]ResourcePermission `json:"resources,omitempty"`
}

// SetAdminRequest grants or revokes a user's admin flag. Its own endpoint
// requires the caller to already be an admin - modify access to users is not
// enough, since that would let a non-admin promote themselves or anyone else.
type SetAdminRequest struct {
	Admin bool `json:"admin"`
}

type UserResponse struct {
	ID          int64               `json:"id"`
	Username    string              `json:"username"`
	Name        string              `json:"name"`
	Surname     string              `json:"surname"`
	Email       *string             `json:"email,omitempty"`
	Permissions PermissionsResponse `json:"permissions"`
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
