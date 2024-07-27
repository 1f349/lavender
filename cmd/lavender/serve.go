package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/1f349/lavender"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/lavender/server"
	"github.com/1f349/mjwt"
	"github.com/1f349/violet/utils"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
	exitReload "github.com/mrmelon54/exit-reload"
	"github.com/spf13/afero"
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
	logger.Logger.Info("Starting...")

	if s.configPath == "" {
		logger.Logger.Fatal("Config flag is missing")
		return subcommands.ExitUsageError
	}

	openConf, err := os.Open(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Logger.Fatal("Missing config file")
		} else {
			logger.Logger.Fatal("Open config file: ", err)
		}
		return subcommands.ExitFailure
	}

	var config server.Conf
	err = json.NewDecoder(openConf).Decode(&config)
	if err != nil {
		logger.Logger.Fatal("Invalid config file: ", err)
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		logger.Logger.Fatal("Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)

	keyDir := filepath.Join(wd, "keys")
	err = os.MkdirAll(keyDir, 0700)
	if err != nil {
		logger.Logger.Fatal("Failed to create keys dir", "err", err)
	}
	keyStore, err := mjwt.NewKeyStoreFromDir(afero.NewBasePathFs(afero.NewOsFs(), keyDir))
	if err != nil {
		logger.Logger.Fatal("Failed to load MJWT keystore", "err", err)
	}

	if config.Kid == "" {
		logger.Logger.Fatal("Invalid kid value")
	}

	signingKey, err := mjwt.NewIssuerWithKeyStore(config.Issuer, config.Kid, jwt.SigningMethodRS512, keyStore)
	if err != nil {
		logger.Logger.Fatal("Failed to load or create MJWT issuer", "err", err)
	}

	db, err := lavender.InitDB(filepath.Join(wd, "lavender.db.sqlite"))
	if err != nil {
		logger.Logger.Fatal("Failed to open database", "err", err)
	}

	if err := pages.LoadPages(wd); err != nil {
		logger.Logger.Fatal("Failed to load page templates:", err)
	}

	srv := server.NewHttpServer(config, db, signingKey)
	logger.Logger.Info("Starting server", "addr", srv.Addr)
	go utils.RunBackgroundHttp(logger.Logger, srv)

	exitReload.ExitReload("Lavender", func() {}, func() {
		// stop http server
		_ = srv.Close()
	})

	return subcommands.ExitSuccess
}
