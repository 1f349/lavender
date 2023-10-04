package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/server"
	"github.com/1f349/violet/utils"
	exit_reload "github.com/MrMelon54/exit-reload"
	"github.com/MrMelon54/mjwt"
	"github.com/google/subcommands"
	"log"
	"os"
	"path/filepath"
)

type serveCmd struct{ configPath string }

func (s *serveCmd) Name() string { return "serve" }

func (s *serveCmd) Synopsis() string { return "Serve API authentication service" }

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
}

func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>]
  Serve API authentication service using information from the config file
`
}

func (s *serveCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	log.Println("[Lavender] Starting...")

	if s.configPath == "" {
		log.Println("[Lavender] Error: config flag is missing")
		return subcommands.ExitUsageError
	}

	openConf, err := os.Open(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[Lavender] Error: missing config file")
		} else {
			log.Println("[Lavender] Error: open config file: ", err)
		}
		return subcommands.ExitFailure
	}

	var config startUpConfig
	err = json.NewDecoder(openConf).Decode(&config)
	if err != nil {
		log.Println("[Lavender] Error: invalid config file: ", err)
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		log.Fatal("[Lavender] Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)
	normalLoad(config, wd)
	return subcommands.ExitSuccess
}

func normalLoad(startUp startUpConfig, wd string) {
	mSign, err := mjwt.NewMJwtSignerFromFileOrCreate(startUp.Issuer, filepath.Join(wd, "lavender.private.key"), rand.Reader, 4096)
	if err != nil {
		log.Fatal("[Lavender] Failed to load or create MJWT signer:", err)
	}

	manager, err := issuer.NewManager(startUp.SsoServices)
	if err != nil {
		log.Fatal("[Lavender] Failed to create SSO service manager: ", err)
	}

	srv := server.NewHttpServer(startUp.Listen, startUp.BaseUrl, startUp.ServiceName, startUp.AllowedClients, manager, mSign)
	log.Printf("[Lavender] Starting HTTP server on '%s'\n", srv.Addr)
	go utils.RunBackgroundHttp("HTTP", srv)

	exit_reload.ExitReload("Tulip", func() {}, func() {
		// stop http server
		_ = srv.Close()
	})
}
