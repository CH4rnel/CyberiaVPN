package main

import (
	"context"
	"log/slog"
	"net"
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

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Error("control API listen failed", "error", err)
		os.Exit(1)
	}
	logger.Info("control API starting", "address", listener.Addr().String(), "version", version)
	if err := serve(ctx, server, listener); err != nil {
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
