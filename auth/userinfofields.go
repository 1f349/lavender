package auth

import "github.com/hardfinhq/go-date"

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

func (u UserInfoFields) GetStringFromKeysOrEmpty(keys ...string) string {
	for _, key := range keys {
		s, _ := u[key].(string)
		if s == "" {
			continue
		}
		return s
	}
	return ""
}

func (u UserInfoFields) GetBoolean(key string) (bool, bool) {
	b, ok := u[key].(bool)
	return b, ok
}

func (u UserInfoFields) GetNullDate(key string) date.NullDate {
	s, _ := u[key].(string)
	fromStr, err := date.FromString(s)
	return date.NullDate{Date: fromStr, Valid: err == nil}
}
