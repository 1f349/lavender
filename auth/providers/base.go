package providers

import (
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	process "github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/logger"
	"net/http"
	"time"
)

var _ auth.Provider = (*InitialLogin)(nil)
var _ auth.Form = (*InitialLogin)(nil)

type InitialLogin struct {
	DB *database.Queries
}

func (m *InitialLogin) AccessState() process.State { return process.StateUnauthorized }

func (m *InitialLogin) Name() string { return "base" }

func (m *InitialLogin) RenderTemplate(ctx authContext.TemplateContext) error {
	type s struct {
		UserEmail string
		Redirect  string
	}

	req := ctx.Request()
	q := req.URL.Query()
	cookie, err := req.Cookie("lavender-user-memory")
	if err == nil && cookie.Valid() == nil {
		ctx.Render(s{
			UserEmail: cookie.Value,
			Redirect:  q.Get("redirect"),
		})
		return nil
	}

	ctx.Render(s{
		UserEmail: "",
		Redirect:  q.Get("redirect"),
	})
	return nil
}

func (m *InitialLogin) AttemptLogin(ctx authContext.FormContext) error {
	req := ctx.Request()
	userEmail := req.FormValue("email")
	rememberMe := req.FormValue("remember-me")
	logger.Logger.Debug("Hi", "em", userEmail, "rm", rememberMe)

	rw := ctx.ResponseWriter()
	now := time.Now()
	future := now.AddDate(1, 0, 0)
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-user-memory",
		Value:    userEmail,
		Path:     "/",
		Expires:  future,
		MaxAge:   int(future.Sub(now).Seconds()),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	ctx.UpdateSession(process.LoginProcessData{State: process.StateBase})

	return nil
}
