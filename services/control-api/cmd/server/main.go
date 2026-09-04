package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	handler := api.NewHandler(api.Metadata{Version: version})
	server := &http.Server{
		Addr:              address(),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("control API shutdown failed", "error", err)
		}
	}()

	logger.Info("control API starting", "address", server.Addr, "version", version)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("control API stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}

func address() string {
	if value := os.Getenv("CYBERIA_API_ADDRESS"); value != "" {
		return value
	}
	return "127.0.0.1:8080"
}
