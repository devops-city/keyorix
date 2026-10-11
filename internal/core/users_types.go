// users_types.go — Request/response types shared by users.go and groups.go.
package core

import "time"

// CreateUserRequest represents a request to create a new user.
//
// G38: the `validate:"..."` tags below are documentation only — no validator
// library in this codebase resolves struct tags on this type (that reflection
// convention exists only in server/validation, and is never invoked here); the
// actual enforcement is validateCreateUserRequest (users.go), called from every
// creation path (CreateUser, CreateUserWithSetupLink, CreateUserWithOneTimePassword,
// CreateUserWithAssignments) via the shared buildUserForCreate. Username's tag
// previously claimed `alphanum`, a rule the live HTTP handlers never actually
// enforce (server/http/handlers/users_handler.go, users_crud.go: `min=3,max=50`
// only) — corrected here to match what's genuinely enforced, not what the tag
// merely aspired to.
type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=50"`
	Email       string `json:"email" validate:"required,email"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
	IsActive    *bool  `json:"is_active,omitempty"`
	// AccountState optionally sets the initial lifecycle state (ADR-025). Empty
	// normalizes to "active". Setup-link provisioning sets pending_first_login so the
	// account is confined from creation — no separate write that could leave it active.
	AccountState string `json:"-"`
	// OneTimePasswordExpiresAt, when set, marks Password as a one-time password that
	// is refused at login from that instant (OTP-EXPIRY-1). Written in the same row
	// insert as the password, so there is no window in which the credential exists
	// without its expiry.
	OneTimePasswordExpiresAt *time.Time `json:"-"`
}

// UpdateUserRequest represents a request to update an existing user.
//
// ActorID is the caller making the change. Zero means "no human actor" (a
// system/background caller — see the same convention documented on
// DeleteUser's actorID) and is exempt from the admin-rank ceiling UpdateUser
// enforces for every other actor; every human-facing caller (HTTP, gRPC, the
// CLI) must set this to a real, resolved user ID. See UpdateUser's own doc
// comment (S1, CLI-split inventory #2012).
type UpdateUserRequest struct {
	ID          uint
	ActorID     uint
	Username    string
	Email       string
	DisplayName string
	IsActive    *bool
}

// CreateGroupRequest represents a request to create a new group.
type CreateGroupRequest struct {
	Name        string
	Description string
}

// UpdateGroupRequest represents a request to update an existing group.
type UpdateGroupRequest struct {
	ID          uint
	Name        string
	Description string
}
