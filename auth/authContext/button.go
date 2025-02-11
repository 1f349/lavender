package authContext

import (
	"context"
	"github.com/1f349/lavender/database"
	"net/http"
)

func NewButtonContext(req *http.Request, user *database.User) *BaseButtonContext {
	return &BaseButtonContext{
		BaseTemplateContext: BaseTemplateContext{
			req:  req,
			user: user,
		},
	}
}

type ButtonContext interface {
	Context() context.Context
	Request() *http.Request
	Render(data any)
	__buttonContext()
}

var _ ButtonContext = &BaseButtonContext{}

type BaseButtonContext struct {
	BaseTemplateContext
}

func (b *BaseButtonContext) __buttonContext() {}
