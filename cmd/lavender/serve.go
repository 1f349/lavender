package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/1f349/lavender"
	"github.com/1f349/lavender/conf"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/lavender/role"
	"github.com/1f349/lavender/server"
	"github.com/1f349/mjwt"
	"github.com/charmbracelet/log"
	"github.com/cloudflare/tableflip"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/subcommands"
	"github.com/julienschmidt/httprouter"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type serveCmd struct {
	configPath string
	debugLog   bool
	pidFile    string
}

func (s *serveCmd) Name() string { return "serve" }

func (s *serveCmd) Synopsis() string { return "Serve authentication service" }

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
	f.BoolVar(&s.debugLog, "debug", false, "enable debug mode")
	f.StringVar(&s.pidFile, "pid-file", "", "path to pid file")
}

func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>] [-debug] [-pid-file <pid file>]
  Serve authentication service using information from the config file
`
}

func (s *serveCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if s.debugLog {
		logger.Logger.SetLevel(log.DebugLevel)
	}
	logger.Logger.Info("Starting...")

	upg, err := tableflip.New(tableflip.Options{
		PIDFile: s.pidFile,
	})
	if err != nil {
		panic(err)
	}
	defer upg.Stop()

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

	var config conf.Conf
	err = yaml.NewDecoder(openConf).Decode(&config)
	if err != nil {
		logger.Logger.Fatal("Invalid config file: ", err)
		return subcommands.ExitFailure
	}

	if config.Kid == "" {
		logger.Logger.Fatal("Invalid kid value")
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		logger.Logger.Fatal("Failed to get absolute config path", "err", err)
	}
	wd := filepath.Dir(configPathAbs)

	// load the keystore private and public keys
	keyDir := filepath.Join(wd, "keystore")
	err = os.MkdirAll(keyDir, 0700)
	if err != nil {
		logger.Logger.Fatal("Failed to create keystore dir", "err", err)
	}
	keystore, err := mjwt.NewKeyStoreFromDir(afero.NewBasePathFs(afero.NewOsFs(), keyDir))
	if err != nil {
		logger.Logger.Fatal("Failed to load MJWT keystore", "err", err)
	}

	signingKey, err := mjwt.NewIssuerWithKeyStore(config.Issuer, config.Kid, jwt.SigningMethodRS512, keystore)
	if err != nil {
		logger.Logger.Fatal("Failed to load or create MJWT issuer", "err", err)
	}

	db, err := lavender.InitDB(filepath.Join(wd, "lavender.db.sqlite"))
	if err != nil {
		logger.Logger.Fatal("Failed to open database", "err", err)
	}

	if err := checkDbHasUser(db); err != nil {
		logger.Logger.Fatal("Failed to add initial user", "err", err)
	}

	if err := pages.LoadPages(wd); err != nil {
		logger.Logger.Fatal("Failed to load page templates:", err)
	}

	ln, err := upg.Listen("tcp", config.Listen)
	if err != nil {
		logger.Logger.Fatal("Listen failed", "err", err)
	}

	mux := httprouter.New()
	server.SetupRouter(mux, config, db, signingKey)
	srv := &http.Server{
		Handler:           mux,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    2500,
	}
	logger.Logger.Info("Starting server", "addr", config.Listen)
	go func() {
		err := srv.Serve(ln)
		if err != nil {
			logger.Logger.Error("Failed to start API server", "err", err)
		}
	}()

	// Do an upgrade on SIGHUP
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			err := upg.Upgrade()
			if err != nil {
				logger.Logger.Error("Failed upgrade", "err", err)
			}
		}
	}()

	logger.Logger.Info("Ready")
	if err := upg.Ready(); err != nil {
		panic(err)
	}
	<-upg.Exit()

	time.AfterFunc(30*time.Second, func() {
		logger.Logger.Warn("Graceful shutdown timed out")
		os.Exit(1)
	})

	_ = srv.Shutdown(context.Background())

	return subcommands.ExitSuccess
}

func checkDbHasUser(db *database.Queries) error {
	value, err := db.HasUser(context.Background())
	if err != nil {
		return err
	}

	if !value {
		logger.Logger.Warn("No users are available, setting up initial admin user")

		ctx := context.Background()
		err = db.UseTx(ctx, func(tx *database.Queries) error {
			adminUuid, err := db.AddLocalUser(context.Background(), database.AddLocalUserParams{
				Password:       "admin",
				Email:          "admin@localhost",
				EmailVerified:  false,
				Name:           "Admin",
				Username:       "admin",
				ChangePassword: true,
			})
			if err != nil {
				return fmt.Errorf("failed to add user: %w", err)
			}
			roleId, err := db.AddRole(context.Background(), role.LavenderAdmin)
			if err != nil {
				return fmt.Errorf("failed to add role: %w", err)
			}
			err = db.AddUserRole(context.Background(), database.AddUserRoleParams{
				RoleID:  roleId,
				Subject: adminUuid,
			})
			if err != nil {
				return fmt.Errorf("failed to add user role: %w", err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
