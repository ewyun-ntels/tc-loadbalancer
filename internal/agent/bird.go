// SPDX-License-Identifier: GPL-2.0
package agent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Bird controls ONLY dedicated static VIP protocols, never the BGP sessions.
// Enable/disable is reasserted each cycle so an external BIRD restart does not
// leave the agent's cached state out of sync with actual advertisements.
type Bird struct{ Config BirdConfig }

func (b Bird) Set(ctx context.Context, on bool) error {
	protocols := append(append(append([]string(nil), b.Config.Protocols...), b.Config.IPv4Protocols...), b.Config.IPv6Protocols...)
	return b.setProtocols(ctx, on, protocols)
}

// SetFamilies independently withdraws an address family with no surviving
// client path, while keeping a serviceable family advertised.
func (b Bird) SetFamilies(ctx context.Context, families map[uint8]bool) error {
	if len(b.Config.Protocols) > 0 {
		on := len(families) > 0
		for _, covered := range families {
			on = on && covered
		}
		return b.Set(ctx, on)
	}
	groups := []struct {
		on        bool
		protocols []string
	}{{families[4], b.Config.IPv4Protocols}, {families[6], b.Config.IPv6Protocols}}
	// Disable unserviceable families before enabling any surviving family.
	for _, on := range []bool{false, true} {
		var failures []error
		for _, g := range groups {
			if g.on == on {
				failures = append(failures, b.setProtocols(ctx, on, g.protocols))
			}
		}
		if err := errors.Join(failures...); err != nil {
			return err
		}
	}
	return nil
}

func (b Bird) setProtocols(ctx context.Context, on bool, protocols []string) error {
	if b.Config.Socket == "" {
		return nil
	}
	command := "disable"
	if on {
		command = "enable"
	}
	var failures []error
	for _, protocol := range protocols {
		deadline, cancel := context.WithTimeout(ctx, 2*time.Second)
		output, err := exec.CommandContext(deadline, "birdc", "-v", "-s", b.Config.Socket, command, protocol).CombinedOutput()
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("birdc %s %s: %w: %.512s", command, protocol, err, output))
			if on {
				break
			}
			continue
		}
		if err := checkBirdReply(string(output)); err != nil {
			failures = append(failures, fmt.Errorf("birdc %s %s: %w", command, protocol, err))
			if on {
				break
			}
		}
	}
	return errors.Join(failures...)
}

func checkBirdReply(reply string) error {
	success := false
	for _, line := range strings.Split(reply, "\n") {
		if len(line) < 4 {
			continue
		}
		code, err := strconv.Atoi(line[:4])
		if err != nil {
			continue
		}
		if code >= 8000 {
			return fmt.Errorf("BIRD rejected command: %s", line)
		}
		// 0008..0011 are BIRD's protocol state replies: already disabled,
		// disabled, already enabled, enabled. There may be no separate 0000.
		// 0001 is only the greeting and must never imply command success.
		if code == 0 || (code >= 8 && code <= 11) {
			success = true
		}
	}
	if !success {
		return fmt.Errorf("missing BIRD success reply: %.512s", reply)
	}
	return nil
}
