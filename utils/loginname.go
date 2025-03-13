package utils

import (
	"errors"
	"strings"
)

var ErrInvalidLoginNameFormat = errors.New("invalid login name format")

func ParseLoginName(loginName string) (user string, namespace string, err error) {
	if loginName == "" || strings.HasPrefix(loginName, "@") || strings.HasSuffix(loginName, "@") || containsInvalidLoginNameRunes(loginName) {
		return "", "", ErrInvalidLoginNameFormat
	}

	// @ should have at least one byte before it
	n := strings.IndexByte(loginName, '@')
	if n < 1 {
		return "", "", ErrInvalidLoginNameFormat
	}
	// there should not be a second @
	n2 := strings.IndexByte(loginName[n+1:], '@')
	if n2 != -1 {
		return "", "", ErrInvalidLoginNameFormat
	}

	return loginName[:n], loginName[n+1:], nil
}

func containsInvalidLoginNameRunes(loginName string) bool {
	// check if the name contains an invalid rune
	return strings.ContainsFunc(loginName, func(r rune) bool {
		return !isValidLoginNameRune(r)
	})
}

func isValidLoginNameRune(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return true
	case r >= 'a' && r <= 'z':
		return true
	case r == '.':
		return true
	case r == '-':
		return true
	case r == '@':
		return true
	default:
		return false
	}
}
