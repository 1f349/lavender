package auth

import (
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/database"
)

type Form interface {
	Provider

	SupportsUser(user *database.User) bool

	// RenderTemplate returns HTML to embed in the page template.
	RenderTemplate(ctx authContext.TemplateContext) error

	// AttemptLogin processes the login request.
	AttemptLogin(ctx authContext.FormContext) error
}
