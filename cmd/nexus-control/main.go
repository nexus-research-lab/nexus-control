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
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
	"github.com/nexus-research-lab/nexus-control/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(context.Background(), os.Args[1:], logger); err != nil {
		logger.Error("nexus-control 退出", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	cfg := config.Load()
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
	if len(args) > 0 && args[0] == "import-nexus" {
		return importNexus(ctx, service, args[1:])
	}
	if len(args) > 0 && args[0] != "serve" {
		return errors.New("仅支持 serve 或 import-nexus")
	}
	if err = initializeOwner(ctx, service); err != nil {
		return err
	}
	shutdownContext, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serverapp.New(cfg, service, logger).ListenAndServe(shutdownContext)
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

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
