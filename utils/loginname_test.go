package utils

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"regexp"
	"strings"
	"testing"
)

var parseLoginNameTests = []struct {
	User      string
	Namespace string
	HasError  bool
	Input     string
}{
	{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbb.com", false, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"},
	{"", "", true, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbb.com\u1111"},
	{"", "", true, "\u1111aaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"},
	{"", "", true, "@aaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"},
	{"", "", true, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbb.com@"},
	{"a", "b.com", false, "a@b.com"},
	{"aa", "bb.com", false, "aa@bb.com"},
}

var parseLoginNameImplementations = []struct {
	Name string
	Func func(string) (string, string, error)
}{
	{"ParseLoginName", ParseLoginName},
	{"parseLoginNameLoopRunes", parseLoginNameLoopRunes},
	{"parseLoginNameRegex", parseLoginNameRegex},
}

func TestParseLoginName(t *testing.T) {
	for _, impl := range parseLoginNameImplementations {
		t.Run(impl.Name, func(t *testing.T) {
			for _, i := range parseLoginNameTests {
				t.Run(i.Input, func(t *testing.T) {
					user, namespace, err := ParseLoginName(i.Input)
					if i.HasError {
						assert.Error(t, err)
					} else {
						assert.NoError(t, err)
					}
					assert.Equal(t, i.User, user)
					assert.Equal(t, i.Namespace, namespace)
				})
			}
		})
	}
}

func FuzzParseLoginName(f *testing.F) {
	for _, i := range parseLoginNameTests {
		f.Add(i.Input)
	}
	f.Fuzz(func(t *testing.T, s string) {
		t.Log("Input: ", s, hex.EncodeToString([]byte(s)))
		hasError := s == "" || strings.HasPrefix(s, "@") || strings.HasSuffix(s, "@") || strings.Count(s, "@") != 1 || strings.ContainsFunc(s, func(r rune) bool {
			return !isValidLoginNameRune(r)
		})
		login, namespace, err := ParseLoginName(s)
		if hasError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
		if err == nil {
			n := strings.IndexRune(s, '@')
			assert.Equal(t, s[:n], login)
			assert.Equal(t, s[n+1:], namespace)
		} else {
			assert.Equal(t, login, "", "Login should be empty if an error occurred")
			assert.Equal(t, namespace, "", "Namespace should be empty if an error occurred")
		}
	})
}

func parseLoginBench(b *testing.B, f func(string) (string, string, error)) {
	for _, i := range parseLoginNameTests {
		b.Run(i.Input, func(b *testing.B) {
			for range b.N {
				_, _, _ = f(i.Input)
			}
		})
	}
}

func BenchmarkParseLoginName(b *testing.B) {
	b.Run("ParseLoginName", func(b *testing.B) {
		parseLoginBench(b, ParseLoginName)
	})
	b.Run("parseLoginNameLoopRunes", func(b *testing.B) {
		parseLoginBench(b, parseLoginNameLoopRunes)
	})
	b.Run("parseLoginNameRegex", func(b *testing.B) {
		parseLoginBench(b, parseLoginNameRegex)
	})
}

func parseLoginNameLoopRunes(s string) (user string, namespace string, err error) {
	if s == "" || strings.HasPrefix(s, "@") || strings.HasSuffix(s, "@") {
		return "", "", ErrInvalidLoginNameFormat
	}
	hasAt := false
	atIndex := 0
	for i, r := range []rune(s) {
		switch {
		case r == '@':
			if hasAt {
				return "", "", ErrInvalidLoginNameFormat
			}
			hasAt = true
			atIndex = i
		case r == '.':
			continue
		case r == '-':
			continue
		case r >= 'a' && r <= 'z':
			continue
		case r >= '0' && r <= '9':
			continue
		default:
			return "", "", ErrInvalidLoginNameFormat
		}
	}

	return s[:atIndex], s[atIndex+1:], nil
}

// regexLoginName is a regex based implementation of ParseLoginName
//
// This implementation prevents using - or . at the start and end of the user and namespace
var regexLoginName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-.]*[a-z0-9]|))@([a-z0-9]([a-z0-9-.]*[a-z0-9]|))$`)

func parseLoginNameRegex(s string) (user string, namespace string, err error) {
	if s == "" {
		return "", "", ErrInvalidLoginNameFormat
	}

	matches := regexLoginName.FindStringSubmatch(s)
	if matches == nil {
		return "", "", ErrInvalidLoginNameFormat
	}
	return matches[1], matches[3], nil
}

func BenchmarkA(b *testing.B) {
	b.Run("A", func(b *testing.B) {
		for range b.N {
			_ = isValidLoginNameRune('b')
			_ = isValidLoginNameRune('4')
			_ = isValidLoginNameRune('.')
			_ = isValidLoginNameRune('-')
			_ = isValidLoginNameRune('@')
			_ = isValidLoginNameRune(' ')
		}
	})
	b.Run("B", func(b *testing.B) {
		for range b.N {
			_ = isValidLoginNameRune2('b')
			_ = isValidLoginNameRune2('4')
			_ = isValidLoginNameRune2('.')
			_ = isValidLoginNameRune2('-')
			_ = isValidLoginNameRune2('@')
			_ = isValidLoginNameRune2(' ')
		}
	})
}

func isValidLoginNameRune2(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || r == '.' || r == '-' || r == '@'
}
