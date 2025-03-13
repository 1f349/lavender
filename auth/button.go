package auth

import (
	"github.com/1f349/lavender/auth/authContext"
)

type Button interface {
	Provider

	// RenderButtonTemplate returns a template for the button widget.
	RenderButtonTemplate(ctx authContext.TemplateContext)
}
