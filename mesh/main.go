package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix(fmt.Sprintf("P-%d ", os.Getpid()))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	testLoop(ctx)
	log.Println("bye!")
}

func testLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		if resp, err := http.DefaultClient.Do(req); err != nil {
			log.Printf("http request: %v", err)
		} else {
			log.Printf("http request: %s %s bytes=%d", resp.Proto, resp.Status, resp.ContentLength)
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}
