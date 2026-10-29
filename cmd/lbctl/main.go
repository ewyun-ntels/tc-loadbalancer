// SPDX-License-Identifier: GPL-2.0
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lbctl generate -plan plan.json [-out table.json] | validate -table table.json")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "generate":
		plan := fs.String("plan", "configs/plan.example.json", "known client IPs, VIP pairs and stable backends")
		out := fs.String("out", "", "output path; default stdout")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		var p control.Plan
		if err := control.DecodeFile(*plan, &p); err != nil {
			return err
		}
		t, err := control.Generate(p)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if *out == "" {
			_, err = os.Stdout.Write(data)
			return err
		}
		return writeAtomic(*out, data)
	case "validate":
		file := fs.String("table", "configs/assignments.example.json", "assignment table")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		var t control.Table
		if err := control.DecodeFile(*file, &t); err != nil {
			return err
		}
		if err := t.Validate(); err != nil {
			return err
		}
		fmt.Printf("valid: generation=%d entries=%d\n", t.Generation, len(t.Assignments)*2)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".assignments-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
