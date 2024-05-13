package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/lavender/server"
	"github.com/1f349/mjwt"
	"github.com/1f349/violet/utils"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
	exitReload "github.com/mrmelon54/exit-reload"
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

	signingKey, err := mjwt.NewMJwtSignerFromFileOrCreate(config.Issuer, filepath.Join(wd, "lavender.private.key"), rand.Reader, 4096)
	if err != nil {
		logger.Logger.Fatal("Failed to load or create MJWT signer:", err)
	}
	saveMjwtPubKey(signingKey, wd)

	db, err := database.Open(filepath.Join(wd, "lavender.db.sqlite"))
	if err != nil {
		logger.Logger.Fatal("Failed to open database:", err)
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

func saveMjwtPubKey(mSign mjwt.Signer, wd string) {
	pubKey := x509.MarshalPKCS1PublicKey(mSign.PublicKey())
	b := new(bytes.Buffer)
	err := pem.Encode(b, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKey})
	if err != nil {
		logger.Logger.Fatal("Failed to encode MJWT public key:", err)
	}
	err = os.WriteFile(filepath.Join(wd, "lavender.public.key"), b.Bytes(), 0600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		logger.Logger.Fatal("Failed to save MJWT public key:", err)
	}
}
