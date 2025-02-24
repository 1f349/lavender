package authContext

import (
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"net/http"
)

func NewFormContext(req *http.Request, user *database.User, rw http.ResponseWriter) *BaseFormContext {
	return &BaseFormContext{
		BaseTemplateContext: BaseTemplateContext{
			req:  req,
			user: user,
		},
		rw: rw,
	}
}

type FormContext interface {
	TemplateContext
	SetUser(user *database.User)
	UpdateSession(data process.LoginProcessData)
	ResponseWriter() http.ResponseWriter
	__formContext()
}

var _ FormContext = &BaseFormContext{}

type BaseFormContext struct {
	BaseTemplateContext
	loginProcessData process.LoginProcessData
	rw               http.ResponseWriter
}

func (b *BaseFormContext) GetLoginProcessData() process.LoginProcessData {
	return b.loginProcessData
}

func (b *BaseFormContext) SetUser(user *database.User) {
	b.BaseTemplateContext.user = user
}

func (b *BaseFormContext) UpdateSession(data process.LoginProcessData) {
	b.loginProcessData = data
}

func (b *BaseFormContext) ResponseWriter() http.ResponseWriter {
	return b.rw
}

func (b *BaseFormContext) __formContext() {}
