package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	serverapp "github.com/nexus-research-lab/nexus-control/internal/app/server"
	"github.com/nexus-research-lab/nexus-control/internal/config"
	"github.com/nexus-research-lab/nexus-control/internal/infra/logx"
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
	"github.com/nexus-research-lab/nexus-control/internal/storage"
)

func main() {
	cfg := config.Load()
	logger := newLogger(cfg)
	slog.SetDefault(logger)
	if err := run(context.Background(), os.Args[1:], cfg, logger); err != nil {
		logger.Error("nexus-control 退出", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, cfg config.Config, logger *slog.Logger) error {
	if err := cfg.PrepareServiceToken(); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	database, err := storage.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer database.Close()
	signer, err := authservice.LoadSigner(cfg.SigningPrivateKey, cfg.SigningKeyFile, cfg.SigningPublicKeyFile)
	if err != nil {
		return err
	}
	service := authservice.NewService(cfg, database, signer)
	if len(args) > 0 {
		switch args[0] {
		case "import-nexus":
			return importNexus(ctx, service, args[1:])
		case "import-nexus-subscriptions":
			return importNexusSubscriptions(ctx, service, args[1:])
		case "serve":
		default:
			return errors.New("仅支持 serve、import-nexus 或 import-nexus-subscriptions")
		}
	}
	if err = initializeOwner(ctx, service); err != nil {
		return err
	}
	shutdownContext, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serverapp.New(cfg, service, logger).ListenAndServe(shutdownContext)
}

func newLogger(cfg config.Config) *slog.Logger {
	return logx.New(logx.Options{
		Service: "nexus-control",
		Level:   cfg.LogLevel,
		Format:  cfg.LogFormat,
		Stdout:  cfg.LogStdout,
		NoColor: cfg.LogNoColor,
		File: logx.FileOptions{
			Enabled:     cfg.LogFileEnabled,
			Path:        cfg.LogPath,
			RotateDaily: cfg.LogRotateDaily,
			MaxSizeMB:   cfg.LogMaxSizeMB,
			MaxAgeDays:  cfg.LogMaxAgeDays,
			MaxBackups:  cfg.LogMaxBackups,
			Compress:    cfg.LogCompress,
		},
	})
}

func initializeOwner(ctx context.Context, service *authservice.Service) error {
	password := os.Getenv("AUTH_INIT_OWNER_PASSWORD")
	if strings.TrimSpace(password) == "" {
		return nil
	}
	state, err := service.State(ctx)
	if err != nil || !state.SetupRequired {
		return err
	}
	_, err = service.SetupOwner(ctx, authservice.SetupOwnerInput{
		Username:       env("AUTH_INIT_OWNER_USERNAME", "admin"),
		DisplayName:    env("AUTH_INIT_OWNER_DISPLAY_NAME", "Admin"),
		Password:       password,
		DeploymentName: env("CONTROL_DEPLOYMENT_NAME", "Nexus"),
	})
	return err
}

func importNexus(ctx context.Context, service *authservice.Service, args []string) error {
	flags := flag.NewFlagSet("import-nexus", flag.ContinueOnError)
	source := flags.String("source", "", "旧 Nexus SQLite 数据库路径")
	deploymentName := flags.String("deployment-name", "Nexus", "导入后的 Deployment 名称")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return service.ImportNexusSQLite(ctx, *source, *deploymentName)
}

func importNexusSubscriptions(ctx context.Context, service *authservice.Service, args []string) error {
	flags := flag.NewFlagSet("import-nexus-subscriptions", flag.ContinueOnError)
	source := flags.String("source", "", "旧 Nexus SQLite 数据库路径")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return service.ImportNexusSubscriptionsSQLite(ctx, *source)
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
