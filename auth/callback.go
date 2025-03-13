package auth

import "github.com/1f349/lavender/auth/authContext"

type Callback interface {
	Provider

	// AttemptCallback processes the login request.
	AttemptCallback(ctx authContext.TemplateContext) error
}
