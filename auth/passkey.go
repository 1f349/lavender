package auth

import (
	"context"
	"github.com/1f349/lavender/database"
	"net/http"
)

type passkeyLoginDB interface {
	lookupUserDB
}

var _ Provider = (*PasskeyLogin)(nil)

type PasskeyLogin struct {
	DB passkeyLoginDB
}

func (p *PasskeyLogin) Factor() Factor { return FactorFirst }

func (p *PasskeyLogin) Name() string { return "passkey" }

func (p *PasskeyLogin) RenderData(ctx context.Context, req *http.Request, user *database.User, data map[string]any) error {
	if user == nil || user.Subject == "" {
		return ErrRequiresPreviousFactor
	}
	if user.OtpSecret == "" {
		return ErrUserDoesNotSupportFactor
	}

	//TODO implement me
	panic("implement me")
}

var passkeyShortcut = true

func init() {
	passkeyShortcut = true
}

func (p *PasskeyLogin) AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error {
	if user.Subject == "" && !passkeyShortcut {
		return ErrRequiresPreviousFactor
	}

	//TODO implement me
	panic("implement me")
}
