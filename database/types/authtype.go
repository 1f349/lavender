package types

type AuthType byte

const (
	AuthTypeLocal AuthType = iota
	AuthTypeOauth2
)

var authTypeNames = map[AuthType]string{
	AuthTypeOauth2: "OAuth2",
}

func (t AuthType) String() string {
	return authTypeNames[t]
}
