// SPDX-License-Identifier: GPL-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/ewyun-ntels/tc-loadbalancer/internal/agent"
	"github.com/ewyun-ntels/tc-loadbalancer/internal/dataplane"
)

func main() {
	if err := run(); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	config := flag.String("config", "configs/agent.example.json", "agent configuration")
	table := flag.String("table", "configs/assignments.example.json", "materialized assignment table")
	check := flag.Bool("check", false, "validate configuration, table and ELF ABI without changing networking")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	c, err := agent.LoadConfig(*config)
	if err != nil {
		return err
	}
	if *check {
		file := &agent.TableFile{}
		if err := file.Reload(*table, c); err != nil {
			return err
		}
		spec, err := ebpf.LoadCollectionSpec(c.Object)
		if err != nil {
			return err
		}
		if err := dataplane.ValidateSpec(spec); err != nil {
			return err
		}
		fmt.Printf("valid: generation=%d entries=%d backends=%d; no network changes\n", file.Table.Generation, len(file.Table.Assignments)*2, len(file.Table.Backends))
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return agent.Run(ctx, c, *table)
}
