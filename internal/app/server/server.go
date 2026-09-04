package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
	authhandler "github.com/nexus-research-lab/nexus-control/internal/handler/auth"
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

// Server 是 Control HTTP 进程。
type Server struct {
	config  config.Config
	service *authservice.Service
	logger  *slog.Logger
	http    *http.Server
}

// New 创建 HTTP 服务。
func New(cfg config.Config, service *authservice.Service, logger *slog.Logger) *Server {
	handler := authhandler.NewHTTPServer(cfg, service, logger).Handler()
	return &Server{
		config: cfg, service: service, logger: logger,
		http: &http.Server{
			Addr: cfg.Address, Handler: handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

// ListenAndServe 运行服务，并在 context 结束时优雅退出。
func (s *Server) ListenAndServe(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.http.Shutdown(deadline)
	}()
	s.logger.Info(
		"nexus-control 已启动",
		"address", s.config.Address,
		"api_base", s.config.APIBase,
		"log_level", s.config.LogLevel,
		"log_format", s.config.LogFormat,
		"principal_public_key", s.service.PublicKey(),
	)
	err := s.http.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
