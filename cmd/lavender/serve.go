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
	"github.com/1f349/lavender/pages"
	"github.com/1f349/lavender/server"
	"github.com/1f349/mjwt"
	"github.com/1f349/violet/utils"
	exitReload "github.com/MrMelon54/exit-reload"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
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
			log.Println("[Tulip] Error: missing config file")
		} else {
			log.Println("[Tulip] Error: open config file: ", err)
		}
		return subcommands.ExitFailure
	}

	var config server.Conf
	err = json.NewDecoder(openConf).Decode(&config)
	if err != nil {
		log.Println("[Tulip] Error: invalid config file: ", err)
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		log.Fatal("[Lavender] Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)

	signingKey, err := mjwt.NewMJwtSignerFromFileOrCreate(config.Issuer, filepath.Join(wd, "lavender.private.key"), rand.Reader, 4096)
	if err != nil {
		log.Fatal("[Lavender] Failed to load or create MJWT signer:", err)
	}
	saveMjwtPubKey(signingKey, wd)

	db, err := database.Open(filepath.Join(wd, "lavender.db.sqlite"))
	if err != nil {
		log.Fatal("[Lavender] Failed to open database:", err)
	}

	if err := pages.LoadPages(wd); err != nil {
		log.Fatal("[Lavender] Failed to load page templates:", err)
	}

	srv := server.NewHttpServer(config, db, signingKey)
	log.Printf("[Lavender] Starting HTTP server on '%s'\n", srv.Addr)
	go utils.RunBackgroundHttp("HTTP", srv)

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
		log.Fatal("[Lavender] Failed to encode MJWT public key:", err)
	}
	err = os.WriteFile(filepath.Join(wd, "lavender.public.key"), b.Bytes(), 0600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		log.Fatal("[Lavender] Failed to save MJWT public key:", err)
	}
}
