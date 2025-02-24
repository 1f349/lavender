package auth

import (
	"context"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
)

type Provider interface {
	// AccessState defines the state at which the provider is allowed to show.
	// Some factors might be unavailable due to user preference.
	AccessState() process.State

	// Name defines a string value for the provider.
	Name() string
}

type LookupUserDB interface {
	GetUser(ctx context.Context, subject string) (database.User, error)
}

func LookupUser(ctx context.Context, db LookupUserDB, subject string, user *database.User) error {
	getUser, err := db.GetUser(ctx, subject)
	if err != nil {
		return err
	}
	*user = getUser
	return nil
}
