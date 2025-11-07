package providers

import (
	"context"
	"database/sql"
	"errors"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"github.com/gobuffalo/nulls"
	"net/http"
)

type passwordLoginDB interface {
	GetUser(ctx context.Context, subject string) (database.User, error)
	CheckLogin(ctx context.Context, un, pw string) (database.CheckLoginResult, error)
}

var (
	_ auth.Provider = (*PasswordLogin)(nil)
	_ auth.Form     = (*PasswordLogin)(nil)
)

type PasswordLogin struct {
	DB passwordLoginDB
}

func (p *PasswordLogin) AccessState() process.State { return process.StateBase }

func (p *PasswordLogin) Name() string { return "password" }

func (p *PasswordLogin) String() string { return "%Provider(password)" }

func (p *PasswordLogin) SupportsUser(user *database.User) bool { return user != nil && user.Password != "" }

func (p *PasswordLogin) RenderTemplate(ctx authContext.TemplateContext) error {
	// TODO(melon): rewrite this
	req := ctx.Request()
	redirect := req.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}
	ctx.Render(struct {
		UserEmail string
		Redirect  string
	}{
		UserEmail: ctx.LoginProcessData().Email,
		Redirect:  redirect,
	})
	return nil
}

func (p *PasswordLogin) AttemptLogin(ctx authContext.FormContext) error {
	req := ctx.Request()
	un := req.FormValue("email")
	pw := req.FormValue("password")
	if len(pw) < 8 {
		return auth.BasicUserSafeError(http.StatusBadRequest, "Password too short")
	}

	login, err := p.DB.CheckLogin(ctx.Context(), un, pw)
	switch {
	case err == nil:
		user, err := p.DB.GetUser(ctx.Context(), login.Subject)
		if err != nil {
			return err
		}
		ctx.SetUser(&user)
		ctx.UpdateSession(process.UpdateLoginProcessData{
			State:   process.StateBasic,
			Email:   nulls.NewString(un),
			Subject: nulls.NewString(user.Subject),
		})
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return auth.BasicUserSafeError(http.StatusForbidden, "Username or password is invalid")
	default:
		return err
	}
}
