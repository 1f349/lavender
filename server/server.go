package server

import (
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/utils"
	"github.com/MrMelon54/mjwt"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

type HttpServer struct {
	r         *httprouter.Router
	baseUrl   string
	manager   *issuer.Manager
	signer    mjwt.Signer
	flowState *cache.Cache[string, flowStateData]
	services  map[string]struct{}
}

type flowStateData struct {
	sso          *issuer.WellKnownOIDC
	targetOrigin string
}

func NewHttpServer(listen, baseUrl string, clients []utils.JsonUrl, manager *issuer.Manager, signer mjwt.Signer) *http.Server {
	r := httprouter.New()

	// remove last slash from baseUrl
	{
		l := len(baseUrl)
		if baseUrl[l-1] == '/' {
			baseUrl = baseUrl[:l-1]
		}
	}

	services := make(map[string]struct{})
	for _, i := range clients {
		services[i.Host] = struct{}{}
	}

	hs := &HttpServer{
		r:        r,
		baseUrl:  baseUrl,
		manager:  manager,
		signer:   signer,
		services: services,
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
		Addr:              listen,
		Handler:           r,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    2500,
	}
}
