package issuer

import (
	"fmt"
	"regexp"
	"strings"
)

var isValidNamespace = regexp.MustCompile("^[0-9a-z.]+$")

type Manager struct {
	m map[string]*WellKnownOIDC
}

func NewManager(services []SsoConfig) (*Manager, error) {
	l := &Manager{m: make(map[string]*WellKnownOIDC)}
	for _, i := range services {
		if !isValidNamespace.MatchString(i.Namespace) {
			return nil, fmt.Errorf("invalid namespace: %s", i.Namespace)
		}

		conf, err := i.FetchConfig()
		if err != nil {
			return nil, err
		}

		// save by namespace
		l.m[i.Namespace] = conf
	}
	return l, nil
}

func (m *Manager) CheckNamespace(namespace string) bool {
	_, ok := m.m[namespace]
	return ok
}

func (m *Manager) GetService(namespace string) *WellKnownOIDC {
	return m.m[namespace]
}

func (m *Manager) FindServiceFromLogin(login string) *WellKnownOIDC {
	// @ should have at least one byte before it
	n := strings.IndexByte(login, '@')
	if n < 1 {
		return nil
	}
	// there should not be a second @
	n2 := strings.IndexByte(login[n+1:], '@')
	if n2 != -1 {
		return nil
	}
	return m.GetService(login[n+1:])
}
