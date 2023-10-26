package server

import (
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/issuer"
	"github.com/MrMelon54/mjwt"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"time"
)

type HttpServer struct {
	r         *httprouter.Router
	conf      Conf
	manager   *issuer.Manager
	signer    mjwt.Signer
	flowState *cache.Cache[string, flowStateData]
	services  map[string]AllowedClient
}

type flowStateData struct {
	sso    *issuer.WellKnownOIDC
	target AllowedClient
}

func NewHttpServer(conf Conf, signer mjwt.Signer) *http.Server {
	r := httprouter.New()

	// remove last slash from baseUrl
	{
		l := len(conf.BaseUrl)
		if conf.BaseUrl[l-1] == '/' {
			conf.BaseUrl = conf.BaseUrl[:l-1]
		}
	}

	manager, err := issuer.NewManager(conf.SsoServices)
	if err != nil {
		log.Fatal("[Lavender] Failed to create SSO service manager: ", err)
	}

	services := make(map[string]AllowedClient)
	for _, i := range conf.AllowedClients {
		services[i.Url.String()] = i
	}

	hs := &HttpServer{
		r:         r,
		conf:      conf,
		manager:   manager,
		signer:    signer,
		flowState: cache.New[string, flowStateData](),
		services:  services,
	}

	r.GET("/", func(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(rw, "What is this?")
	})
	r.POST("/verify", hs.verifyHandler)
	r.GET("/popup", hs.flowPopup)
	r.POST("/popup", hs.flowPopupPost)
	r.GET("/callback", hs.flowCallback)

	return &http.Server{
		Addr:              conf.Listen,
		Handler:           r,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    2500,
	}
}
