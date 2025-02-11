package authContext

import "net/http"

type CallbackContext interface {
	TemplateContext
	HandleCallback(rw http.ResponseWriter, req *http.Request)
	__callbackContext()
}

var _ CallbackContext = &BaseCallbackContext{}

type BaseCallbackContext struct {
	BaseTemplateContext
}

func (b *BaseCallbackContext) HandleCallback(rw http.ResponseWriter, req *http.Request) {}

func (b *BaseCallbackContext) __callbackContext() {}
