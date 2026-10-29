// SPDX-License-Identifier: GPL-2.0
package agent

import "context"

// Lifecycle methods are serialized by Run. The exit callback only publishes
// process/readiness status and never enables routes or changes BPF maps.
type birdProcess interface {
	EnsureStarted(context.Context) error
	Done() <-chan struct{}
	Context() context.Context
	Stop()
	Close() error
}

type noBirdProcess struct{}

func (noBirdProcess) EnsureStarted(context.Context) error { return nil }
func (noBirdProcess) Done() <-chan struct{}               { return nil }
func (noBirdProcess) Context() context.Context            { return context.Background() }
func (noBirdProcess) Stop()                               {}
func (noBirdProcess) Close() error                        { return nil }
