package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kangheeyong/authgate/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	fmt.Fprintf(os.Stdout, "authgate starting on :%d (dev=%v, provider=%s)\n",
		cfg.Port, cfg.DevMode, cfg.UpstreamProvider)
}
