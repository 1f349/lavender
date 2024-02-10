package server

type UserInfoFields map[string]any

func (u UserInfoFields) GetString(key string) (string, bool) {
	s, ok := u[key].(string)
	return s, ok
}

func (u UserInfoFields) GetStringOrDefault(key, other string) string {
	s, ok := u[key].(string)
	if !ok {
		s = other
	}
	return s
}

func (u UserInfoFields) GetStringOrEmpty(key string) string {
	s, _ := u[key].(string)
	return s
}

func (u UserInfoFields) GetBoolean(key string) (bool, bool) {
	b, ok := u[key].(bool)
	return b, ok
}
