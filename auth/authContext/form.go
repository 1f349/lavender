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
	UpdateSession(update process.UpdateLoginProcessData)
	GetLoginProcessData() process.LoginProcessData
	ResponseWriter() http.ResponseWriter
	__formContext()
	Hijack()
}

var _ FormContext = &BaseFormContext{}

type BaseFormContext struct {
	BaseTemplateContext
	loginProcessData process.LoginProcessData
	rw               http.ResponseWriter
	hijack           bool
}

func (b *BaseFormContext) GetLoginProcessData() process.LoginProcessData { return b.loginProcessData }

func (b *BaseFormContext) SetUser(user *database.User) { b.BaseTemplateContext.user = user }

func (b *BaseFormContext) UpdateSession(data process.UpdateLoginProcessData) {
	b.loginProcessData = b.loginProcessData.Merge(data)
}

func (b *BaseFormContext) ResponseWriter() http.ResponseWriter { return b.rw }

func (b *BaseFormContext) __formContext() {}

func (b *BaseFormContext) Hijack() { b.hijack = true }

func (b *BaseFormContext) HijackCalled() bool { return b.hijack }
