package authContext

import (
	"context"
	"github.com/1f349/lavender/database"
	"net/http"
)

func NewTemplateContext(req *http.Request, user *database.User) *BaseTemplateContext {
	return &BaseTemplateContext{
		req:  req,
		user: user,
	}
}

type TemplateContext interface {
	Context() context.Context
	Request() *http.Request
	User() *database.User
	Render(data any)
	__templateContext()
}

var _ TemplateContext = &BaseTemplateContext{}

type BaseTemplateContext struct {
	req  *http.Request
	user *database.User
	data any
}

func (t *BaseTemplateContext) Context() context.Context { return t.req.Context() }

func (t *BaseTemplateContext) Request() *http.Request { return t.req }

func (t *BaseTemplateContext) User() *database.User { return t.user }

func (t *BaseTemplateContext) Render(data any) { t.data = data }

func (t *BaseTemplateContext) Data() any { return t.data }

func (t *BaseTemplateContext) __templateContext() {}
