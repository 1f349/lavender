package passkey

import (
	"context"
	"github.com/1f349/lavender/database"
)

// TODO: write passkey implementation

type passkeyDB interface {
	GetUserWithPasskey(ctx context.Context, passkeyId string) (database.User, error)
}

func New(db passkeyDB) *Passkey {
	return &Passkey{db: db}
}

type Passkey struct {
	db passkeyDB
}
