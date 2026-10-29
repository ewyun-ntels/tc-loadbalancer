// SPDX-License-Identifier: GPL-2.0
//go:build !linux

package agent

import "errors"

func OpenPlatform(Config) (Plane, Prober, error) {
	return nil, nil, errors.New("TC agent requires Linux; validation and lbctl work on this platform")
}
