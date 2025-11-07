package providers

import (
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/passkey"
)

var (
	_ auth.Provider = (*PasskeyDirect)(nil)
	_ auth.Button   = (*PasskeyDirect)(nil)
)

type PasskeyDirect struct {
	Service *passkey.Passkey
}

func (p *PasskeyDirect) AccessState() process.State { return process.StateUnauthorized }

func (p *PasskeyDirect) Name() string { return "passkeyDirect" }

func (p *PasskeyDirect) String() string { return "%Provider(passkeyDirect)" }

func (p *PasskeyDirect) RenderButtonTemplate(ctx authContext.TemplateContext) {
	// provide something non-nil
	ctx.Render(struct{}{})
}
