package issuer

type Manager struct {
	m map[string]*WellKnownOIDC
}

func NewManager(services []SsoConfig) (*Manager, error) {
	l := &Manager{m: make(map[string]*WellKnownOIDC)}
	for _, i := range services {
		conf, err := i.FetchConfig()
		if err != nil {
			return nil, err
		}

		// save by issuer
		l.m[conf.Issuer] = conf
	}
	return l, nil
}

func (l *Manager) CheckIssuer(issuer string) bool {
	_, ok := l.m[issuer]
	return ok
}

func (l *Manager) FindServiceFromLogin(login string) *WellKnownOIDC {

	return l.m[namespace]
}
