package process

import (
	"github.com/1f349/mjwt"
)

var _ mjwt.Claims = (*LoginProcessData)(nil)

// LoginProcessData stores the current state and relevant information during the
// process of a login. This data is sent signed but unencrypted to the user's
// device. For this reason, all fields must only contain user input or generic
// enum state data.
//
// TODO: add some actual session management
type LoginProcessData struct {
	State State
	Email string
}

func (d LoginProcessData) Valid() error { return nil }

func (d LoginProcessData) Type() string { return "login-process" }
