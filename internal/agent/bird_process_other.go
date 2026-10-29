// SPDX-License-Identifier: GPL-2.0
//go:build !linux

package agent

import "errors"

func newBirdProcess(c BirdConfig, _ func(int, uint64, error)) (birdProcess, error) {
	if c.Socket == "" {
		return noBirdProcess{}, nil
	}
	return nil, errors.New("BIRD process management requires Linux")
}
