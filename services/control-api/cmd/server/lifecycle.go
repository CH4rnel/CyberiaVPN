package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// serve owns the listener and waits for active requests to drain on cancellation.
func serve(ctx context.Context, server *http.Server, listener net.Listener) error {
	return serveWithShutdownTimeout(ctx, server, listener, 10*time.Second)
}

func serveWithShutdownTimeout(ctx context.Context, server *http.Server, listener net.Listener, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		return servingError(err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownCtx)
		var closeErr error
		if shutdownErr != nil {
			closeErr = server.Close()
		}
		return errors.Join(shutdownErr, closeErr, servingError(<-result))
	}
}

func servingError(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
