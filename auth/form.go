package auth

import "github.com/1f349/lavender/auth/authContext"

type Form interface {
	Provider

	// RenderTemplate returns HTML to embed in the page template.
	RenderTemplate(ctx authContext.TemplateContext) error

	// AttemptLogin processes the login request.
	AttemptLogin(ctx authContext.FormContext) error
}
