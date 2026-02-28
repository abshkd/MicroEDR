package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"microedr/agent/internal/collectors/windows/etw"
	"microedr/agent/internal/config"
	"microedr/agent/internal/spool"
	"microedr/agent/internal/uploader"
	"microedr/pkg/model"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to agent config")
	flag.Parse()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.Spool.Dir == "" {
		cfg.Spool.Dir = filepath.Join(os.TempDir(), "microedr-spool")
	}
	sp, err := spool.New(cfg.Spool.Dir, cfg.Spool.MaxSegmentMB*1024*1024)
	if err != nil {
		log.Fatalf("init spool: %v", err)
	}
	defer sp.Close()

	up := uploader.New(cfg.Ingest.URL, cfg.TenantID, cfg.HostID)
	c := etw.New(cfg.HostID)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	eventOut := make(chan model.Event, 2048)
	go func() {
		if err := c.Run(ctx, eventOut); err != nil {
			log.Printf("collector exited: %v", err)
		}
	}()
	go func() {
		t := time.NewTicker(time.Duration(cfg.Upload.FlushInterval) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := up.FlushOnce(sp); err != nil {
					log.Printf("flush failed: %v", err)
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-eventOut:
			if err := sp.Append(ev); err != nil {
				log.Printf("spool append failed: %v", err)
			}
		}
	}
}
