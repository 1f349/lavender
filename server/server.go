package server

import (
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/mjwt"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type HttpServer struct {
	Server    *http.Server
	r         *httprouter.Router
	conf      atomic.Pointer[Conf]
	manager   atomic.Pointer[issuer.Manager]
	signer    mjwt.Signer
	flowState *cache.Cache[string, flowStateData]
	services  atomic.Pointer[map[string]AllowedClient]
}

type flowStateData struct {
	sso    *issuer.WellKnownOIDC
	target AllowedClient
}

func NewHttpServer(conf Conf, signer mjwt.Signer) *HttpServer {
	r := httprouter.New()

	// remove last slash from baseUrl
	{
		l := len(conf.BaseUrl)
		if conf.BaseUrl[l-1] == '/' {
			conf.BaseUrl = conf.BaseUrl[:l-1]
		}
	}

	hs := &HttpServer{
		Server: &http.Server{
			Addr:              conf.Listen,
			Handler:           r,
			ReadTimeout:       time.Minute,
			ReadHeaderTimeout: time.Minute,
			WriteTimeout:      time.Minute,
			IdleTimeout:       time.Minute,
			MaxHeaderBytes:    2500,
		},
		r:         r,
		signer:    signer,
		flowState: cache.New[string, flowStateData](),
	}
	err := hs.UpdateConfig(conf)
	if err != nil {
		log.Fatalln("Failed to load initial config:", err)
		return nil
	}

	r.GET("/", func(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(rw, "What is this?")
	})
	r.POST("/verify", hs.verifyHandler)
	r.GET("/popup", hs.flowPopup)
	r.POST("/popup", hs.flowPopupPost)
	r.GET("/callback", hs.flowCallback)
	return hs
}

func (h *HttpServer) UpdateConfig(conf Conf) error {
	m, err := issuer.NewManager(conf.SsoServices)
	if err != nil {
		return fmt.Errorf("failed to reload SSO service manager: %w", err)
	}

	clientLookup := make(map[string]AllowedClient)
	for _, i := range conf.AllowedClients {
		clientLookup[i.Url.String()] = i
	}

	h.conf.Store(&conf)
	h.manager.Store(m)
	h.services.Store(&clientLookup)
	return nil
}
