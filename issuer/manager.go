package issuer

import (
	"context"
	"fmt"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/logger"
	"github.com/robfig/cron"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	fetchPoolSize          = 4
	fetchTimeout           = 2 * time.Minute
	fetchRetryDelay        = 15 * time.Second
	fetchRetryAfterTimeout = 15 * time.Minute
	fetchRetryCount        = 3
)

var isValidNamespace = regexp.MustCompile("^[0-9a-z.]+$")

var MeWellKnown = &WellKnownOIDC{}

type managerReloadDB interface {
	GetOAuthSources(ctx context.Context) ([]database.OauthSource, error)
}

type Manager struct {
	db managerReloadDB

	client *http.Client

	sourceMu  *sync.RWMutex
	sourceMap map[string]*WellKnownOIDC

	errMu  *sync.RWMutex
	errMap map[string]FetchErrorDetails

	shutdownCall context.CancelFunc
}

type FetchErrorDetails struct {
	Retry  time.Time
	Errors []error
}

type managerRoundTripper struct {
	Base http.RoundTripper
}

func (a *managerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	userAgent := strings.Join(request.Header.Values("User-Agent"), " ")
	if strings.TrimSpace(userAgent) == "" {
		request.Header.Set("User-Agent", "Lavender/1.0 (OAuth Manager)")
	}
	return a.Base.RoundTrip(request)
}

func NewManager(db managerReloadDB, myNamespace string) (*Manager, error) {
	return NewManagerWithClient(db, myNamespace, &http.Client{
		Transport: &managerRoundTripper{
			Base: http.DefaultTransport,
		},
	})
}

func NewManagerWithClient(db managerReloadDB, myNamespace string, client *http.Client) (*Manager, error) {
	l := &Manager{
		db:        db,
		client:    client,
		sourceMu:  new(sync.RWMutex),
		sourceMap: make(map[string]*WellKnownOIDC),
		errMap:    make(map[string]FetchErrorDetails),
	}
	l.sourceMap[myNamespace] = MeWellKnown

	// reload should run blocking on start up
	l.internalReload(context.Background())

	reloadDaily := make(chan struct{}, 1)

	tab := cron.New()
	err := tab.AddFunc("0 2 * * *", func() {
		reloadDaily <- struct{}{}
	})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go l.reloadWorker(ctx, reloadDaily)

	l.shutdownCall = cancel

	return l, nil
}

func (m *Manager) Shutdown() { m.shutdownCall() }

func (m *Manager) reloadWorker(ctx context.Context, reload <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			logger.Logger.Info("Shutting down oauth manager reload worker")
			return
		case <-reload:
			m.internalReload(ctx)
		}
	}
}

func (m *Manager) internalReload(ctx context.Context) {
	logger.Logger.Info("Reloading oauth sources")
	dbCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	sources, err := m.db.GetOAuthSources(dbCtx)
	cancel()
	if err != nil {
		// TODO: send email to admin
		logger.Logger.Warn("Failed to load OAuth sources from the database", "err", err)
		return
	}

	// construct map of db oauth sources
	toAdd := make(map[string]database.OauthSource)
	for _, source := range sources {
		toAdd[source.Namespace] = source
	}

	// remove sources from the active map
	m.sourceMu.Lock()
	for k, v := range m.sourceMap {
		// ignore my own well-known
		if v == MeWellKnown {
			continue
		}

		if _, shouldAdd := toAdd[k]; !shouldAdd {
			delete(m.sourceMap, k)
		}
	}
	m.sourceMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(fetchPoolSize)

	fetchChan := make(chan database.OauthSource, fetchPoolSize)

	for range fetchPoolSize {
		go func() {
			defer wg.Done()

			for source := range fetchChan {
				itemCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
				errs := m.reloadSource(itemCtx, source)
				cancel()

				// this also resets the error if it was set previously
				m.sourceMu.Lock()
				if len(errs) > 0 {
					m.errMap[source.Namespace] = FetchErrorDetails{
						Retry:  time.Now().Add(fetchRetryAfterTimeout),
						Errors: errs,
					}
					// TODO: send email to admin
				} else {
					delete(m.errMap, source.Namespace)
					// TODO: send resolved email to admin
				}
				m.sourceMu.Unlock()
			}
		}()
	}

	// reload sources
	for _, source := range toAdd {
		fetchChan <- source
	}

	close(fetchChan)

	wg.Wait()
}

func (m *Manager) reloadSource(ctx context.Context, source database.OauthSource) []error {
	var errs []error

	for range fetchRetryCount {
		oidc, err := fetchConfig(ctx, m.client, source)
		fmt.Println(oidc, err)
		if err == nil {
			// fetch was successful
			m.sourceMu.Lock()
			m.sourceMap[source.Namespace] = oidc
			m.sourceMu.Unlock()
			return nil
		}
		errs = append(errs, fmt.Errorf("failed to fetch OIDC well-known configuration: %w", err))

		// wait before retrying
		select {
		case <-ctx.Done():
			return errs
		case <-time.After(fetchRetryDelay):
			continue
		}
	}

	return errs
}

func (m *Manager) CheckNamespace(namespace string) bool {
	m.sourceMu.RLock()
	defer m.sourceMu.RUnlock()
	_, ok := m.sourceMap[namespace]
	return ok
}

func (m *Manager) GetService(namespace string) *WellKnownOIDC {
	m.sourceMu.RLock()
	defer m.sourceMu.RUnlock()
	return m.sourceMap[namespace]
}
