// Command auth-server-go is the self-hosted auth centre (SSO / OIDC provider).
//
// It is a drop-in replacement for the legacy Node service: it reads the same
// DATA_DIR key files, uses the same Redis key space and exposes the same HTTP
// contract. It listens on its own port (19260 by default) so the two can run
// side by side.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	assets "auth-server-go"
	"auth-server-go/internal/config"
	"auth-server-go/internal/httpapi"
	"auth-server-go/internal/oidc"
	"auth-server-go/internal/redis"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("auth-server-go 退出", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger.Info("配置已加载",
		"listen", cfg.Host+":"+strconv.Itoa(cfg.Port),
		"issuer", cfg.Issuer,
		"data_dir", cfg.DataDir,
		"redis_db", cfg.RedisDB,
		"session_ttl", cfg.SessionTTL,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := redis.New(cfg.RedisHost, cfg.RedisPort, cfg.RedisDB)
	store.Start(ctx)
	defer func() { _ = store.Close() }()

	provider, err := oidc.New(oidc.Options{
		Store:           store,
		DataDir:         cfg.DataDir,
		Issuer:          cfg.Issuer,
		Subject:         cfg.Subject,
		DisplayName:     cfg.DisplayName,
		LegacySubjects:  config.LegacySubjects(),
		SessionTTL:      cfg.SessionTTL,
		SessionShortTTL: cfg.SessionShortTTL,
		CookieName:      "HomeAuth",
		AccessTTL:       cfg.AccessTTL,
		BackchannelURL:  cfg.GatewayBackchannelURL,
		InternalToken:   cfg.InternalToken,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	api, err := httpapi.New(cfg, store, provider, assets.Public, logger)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Host + ":" + strconv.Itoa(cfg.Port),
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("auth-server-go 启动", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("收到退出信号，正在优雅关闭")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
