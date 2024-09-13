package auth

import "github.com/1f349/lavender/database"

type LoginProvider interface {
	AttemptLogin(username, password string) (database.User, error)
}

type OAuthProvider interface {
	AttemptLogin(username string) (database.User, error)
}
