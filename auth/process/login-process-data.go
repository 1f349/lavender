package process

import (
	"errors"
	"github.com/1f349/mjwt"
	"github.com/gobuffalo/nulls"
)

var _ mjwt.Claims = (*LoginProcessData)(nil)

// LoginProcessData stores the current state and relevant information during the
// process of a login. This data is sent signed but unencrypted to the user's
// device. For this reason, all fields must only contain user input or generic
// enum state data.
//
// TODO: add some actual session management
type LoginProcessData struct {
	State   State
	Email   string
	Subject string
}

func (d LoginProcessData) Type() string { return "login-process" }

func (d LoginProcessData) Valid() error {
	if !d.State.IsValid() {
		return errors.New("invalid state")
	}
	return nil
}

func (d LoginProcessData) Merge(update UpdateLoginProcessData) LoginProcessData {
	d.State = update.State
	if update.Email.Valid {
		d.Email = update.Email.String
	}
	if update.Subject.Valid {
		d.Subject = update.Subject.String
	}
	return d
}

// UpdateLoginProcessData will modify the values in LoginProcessData using Merge
type UpdateLoginProcessData struct {
	State   State
	Email   nulls.String
	Subject nulls.String
}
