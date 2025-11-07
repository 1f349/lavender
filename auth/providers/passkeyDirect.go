package providers

import (
	"context"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
)

type passkeyLoginDB interface {
	GetUser(ctx context.Context, subject string) (database.User, error)
}

var (
	_ auth.Provider = (*PasskeyLogin)(nil)
	_ auth.Button   = (*PasskeyLogin)(nil)
)

type PasskeyLogin struct {
	DB passkeyLoginDB
}

func (p *PasskeyLogin) AccessState() process.State { return process.StateUnauthorized }

func (p *PasskeyLogin) Name() string { return "passkeyDirect" }

func (p *PasskeyLogin) String() string { return "%Provider(passkey)" }

func (p *PasskeyLogin) RenderButtonTemplate(ctx authContext.TemplateContext) {
	// provide something non-nil
	ctx.Render(struct{}{})
}
