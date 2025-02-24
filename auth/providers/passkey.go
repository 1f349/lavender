package providers

import (
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
)

type passkeyLoginDB interface {
	auth.LookupUserDB
}

var (
	_ auth.Provider = (*PasskeyLogin)(nil)
	_ auth.Button   = (*PasskeyLogin)(nil)
)

type PasskeyLogin struct {
	DB passkeyLoginDB
}

func (p *PasskeyLogin) AccessState() process.State { return process.StateUnauthorized }

func (p *PasskeyLogin) Name() string { return "passkey" }

func (p *PasskeyLogin) RenderButtonTemplate(ctx authContext.TemplateContext) {
	// provide something non-nil
	ctx.Render(struct{}{})
}
