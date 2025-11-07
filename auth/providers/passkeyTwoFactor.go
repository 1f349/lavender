package providers

import (
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/passkey"
)

var (
	_ auth.Provider = (*PasskeyTwoFactor)(nil)
	_ auth.Form     = (*PasskeyTwoFactor)(nil)
)

type PasskeyTwoFactor struct {
	Service *passkey.Passkey
}

func (p *PasskeyTwoFactor) AccessState() process.State { return process.StateBasic }

func (p *PasskeyTwoFactor) Name() string { return "passkeyTwoFactor" }

func (p *PasskeyTwoFactor) String() string { return "%Provider(passkeyTwoFactor)" }

func (p *PasskeyTwoFactor) SupportsUser(user *database.User) bool {
	return user != nil && user.TwoFactor == "passkeyTwoFactor"
}

func (p *PasskeyTwoFactor) RenderTemplate(ctx authContext.TemplateContext) error {
	//TODO implement me
	panic("implement me")
}

func (p *PasskeyTwoFactor) AttemptLogin(ctx authContext.FormContext) error {
	//TODO implement me
	panic("implement me")
}
