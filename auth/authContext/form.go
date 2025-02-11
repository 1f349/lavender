package authContext

import (
	"github.com/1f349/lavender/auth/login-process"
	"github.com/1f349/lavender/database"
	"net/http"
)

func NewFormContext(req *http.Request, user *database.User) *BaseFormContext {
	return &BaseFormContext{
		BaseTemplateContext: BaseTemplateContext{
			req:  req,
			user: user,
		},
	}
}

type FormContext interface {
	TemplateContext
	SetUser(user *database.User)
	UpdateSession(data process.LoginProcessData)
	__formContext()
}

var _ FormContext = &BaseFormContext{}

type BaseFormContext struct {
	BaseTemplateContext
	loginProcessData process.LoginProcessData
}

func (b *BaseFormContext) SetUser(user *database.User) {
	b.BaseTemplateContext.user = user
}

func (b *BaseFormContext) UpdateSession(data process.LoginProcessData) {
	b.loginProcessData = data
}

func (b *BaseFormContext) __formContext() {}
