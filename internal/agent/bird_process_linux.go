// SPDX-License-Identifier: GPL-2.0
//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const birdStartupTimeout = 10 * time.Second
const birdStopTimeout = 3 * time.Second
const birdRestartInterval = time.Second

type birdChild struct {
	command *exec.Cmd
	done    chan struct{}
	life    context.Context
	cancel  context.CancelFunc
	err     error // published by closing done
}

type ownedBirdProcess struct {
	config      BirdConfig
	lock        *os.File
	child       *birdChild
	starts      uint64
	lastAttempt time.Time
	event       func(int, uint64, error)
}

func newBirdProcess(c BirdConfig, event func(int, uint64, error)) (birdProcess, error) {
	if c.Socket == "" {
		return noBirdProcess{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(c.Socket), 0750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(c.PIDFile), 0750); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(c.Socket+".agent.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("another agent owns BIRD: %w", err)
	}
	if conn, err := net.DialTimeout("unix", c.Socket, 200*time.Millisecond); err == nil {
		conn.Close()
		lock.Close()
		return nil, errors.New("BIRD is already running; refusing to adopt an external daemon")
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ECONNREFUSED) {
		lock.Close()
		return nil, err
	}
	return &ownedBirdProcess{config: c, lock: lock, event: event}, nil
}

func (p *ownedBirdProcess) Done() <-chan struct{} {
	if p.child == nil {
		return nil
	}
	return p.child.done
}
func (p *ownedBirdProcess) Context() context.Context {
	if p.child == nil {
		return context.Background()
	}
	return p.child.life
}
func (c *birdChild) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (p *ownedBirdProcess) EnsureStarted(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p.child != nil && p.child.alive() {
		return nil
	}
	// Stable BIRD instances restart immediately. Repeated startup/crash
	// failures are rate limited to one launch attempt per second.
	if delay := birdRestartInterval - time.Since(p.lastAttempt); delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	p.lastAttempt = time.Now()
	child := &birdChild{done: make(chan struct{})}
	child.life, child.cancel = context.WithCancel(context.Background())
	child.command = exec.Command(p.config.Executable, "-f", "-c", p.config.ConfigFile, "-s", p.config.Socket, "-P", p.config.PIDFile)
	child.command.Stdout = os.Stdout
	child.command.Stderr = os.Stderr
	child.command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	started := make(chan error, 1)
	nextStart := p.starts + 1
	go func() {
		// Linux Pdeathsig follows the creating thread. Keep this thread
		// alive until Wait completes, even when running outside a container.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := child.command.Start(); err != nil {
			child.err = err
			child.cancel()
			started <- err
			close(child.done)
			return
		}
		if p.event != nil {
			p.event(child.command.Process.Pid, nextStart, nil)
		}
		started <- nil
		child.err = child.command.Wait()
		if p.event != nil {
			p.event(0, nextStart, fmt.Errorf("BIRD exited: %w", birdExitError(child.err)))
		}
		child.cancel()
		close(child.done)
	}()
	if err := <-started; err != nil {
		<-child.done
		return err
	}
	p.child = child
	p.starts = nextStart
	startup, cancel := context.WithTimeout(ctx, birdStartupTimeout)
	defer cancel()
	controller := Bird{Config: p.config}
	var lastError error
	for {
		if !child.alive() {
			return fmt.Errorf("BIRD exited during startup: %w", birdExitError(child.err))
		}
		attempt, stop := context.WithTimeout(startup, time.Second)
		lastError = controller.Set(attempt, false)
		stop()
		if lastError == nil && child.alive() {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-child.done:
			timer.Stop()
			return fmt.Errorf("BIRD exited during startup: %w", birdExitError(child.err))
		case <-startup.Done():
			timer.Stop()
			p.stopChild()
			return fmt.Errorf("BIRD control startup: %w", lastError)
		case <-timer.C:
		}
	}
}

func birdExitError(err error) error {
	if err == nil {
		return errors.New("foreground process ended")
	}
	return err
}

func (p *ownedBirdProcess) stopChild() {
	child := p.child
	if child == nil || !child.alive() {
		return
	}
	_ = unix.Kill(-child.command.Process.Pid, unix.SIGTERM)
	timer := time.NewTimer(birdStopTimeout)
	defer timer.Stop()
	select {
	case <-child.done:
	case <-timer.C:
		_ = unix.Kill(-child.command.Process.Pid, unix.SIGKILL)
		<-child.done
	}
}

func (p *ownedBirdProcess) Stop()        { p.stopChild() }
func (p *ownedBirdProcess) Close() error { p.Stop(); return p.lock.Close() }
