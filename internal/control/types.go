// SPDX-License-Identifier: GPL-2.0
// Package control contains the platform independent assignment policy and map ABI.
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
)

const (
	Version        = 1
	MaxAssignments = 1024
	Active         = 1
)

// Key and Dest match bpf/lb_common.h. Addresses are network byte order;
// IPv4 occupies the FIRST four bytes, unlike netip.Addr.As16().
type Key struct {
	Family uint8
	Pad    [3]uint8
	Source [16]uint8
	VIP    [16]uint8
}

type Dest struct {
	MAC   [6]uint8
	Flags uint8
	Pad   uint8
}

func MakeKey(source, vip netip.Addr) (Key, error) {
	if !validIP(source) || !validIP(vip) || source.Is4() != vip.Is4() {
		return Key{}, fmt.Errorf("source and VIP must be unicast addresses of the same family")
	}
	k := Key{Family: 6}
	if source.Is4() {
		k.Family = 4
		s, d := source.As4(), vip.As4()
		copy(k.Source[:4], s[:])
		copy(k.VIP[:4], d[:])
	} else {
		k.Source, k.VIP = source.As16(), vip.As16()
	}
	return k, nil
}

func validIP(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && a != netip.MustParseAddr("255.255.255.255")
}

type Backend struct {
	ID string `json:"id"`
	// Each field accepts a literal Multus IP or a name resolving to that family.
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	HealthPort uint16 `json:"health_port"`
}

type Pair struct {
	Primary   string `json:"primary"`
	Secondary string `json:"secondary"`
}

type Client struct {
	ID        string   `json:"id"`
	Addresses []string `json:"addresses"`
}

type Plan struct {
	Version    int       `json:"version"`
	Generation uint64    `json:"generation"`
	Backends   []Backend `json:"backends"`
	VIPs       []Pair    `json:"vip_pairs"`
	Clients    []Client  `json:"clients"`
}

type Assignment struct {
	Source           string `json:"source"`
	PrimaryVIP       string `json:"primary_vip"`
	SecondaryVIP     string `json:"secondary_vip"`
	PrimaryBackend   string `json:"primary_backend"`
	SecondaryBackend string `json:"secondary_backend"`
}

type Table struct {
	Version     int          `json:"version"`
	Generation  uint64       `json:"generation"`
	Backends    []Backend    `json:"backends"`
	Assignments []Assignment `json:"assignments"`
}

func DecodeFile(path string, target any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 2<<20 {
		return errors.New("configuration exceeds 2 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}

func (t Table) Validate() error {
	if t.Version != Version || t.Generation == 0 {
		return errors.New("version must be 1 and generation must be positive")
	}
	if len(t.Backends) < 2 || len(t.Backends) > 256 {
		return errors.New("require 2..256 backends for distinct primary and secondary")
	}
	backends := make(map[string]Backend)
	for _, b := range t.Backends {
		if b.ID == "" || len(b.ID) > 128 || b.HealthPort == 0 || (b.IPv4 == "" && b.IPv6 == "") {
			return fmt.Errorf("invalid backend %q", b.ID)
		}
		if _, exists := backends[b.ID]; exists {
			return fmt.Errorf("duplicate backend %q", b.ID)
		}
		for family, host := range map[int]string{4: b.IPv4, 6: b.IPv6} {
			if host == "" {
				continue
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				if !validIP(ip) || ip.Is4() != (family == 4) {
					return fmt.Errorf("backend %s: wrong/unsafe IPv%d address", b.ID, family)
				}
			} else if !validHostname(host) {
				return fmt.Errorf("backend %s: invalid DNS name %q", b.ID, host)
			}
		}
		backends[b.ID] = b
	}
	if len(t.Assignments) == 0 || len(t.Assignments)*2 > MaxAssignments {
		return errors.New("require 1..512 assignment pairs")
	}
	keys := make(map[Key]bool)
	roles := make(map[netip.Addr]string)
	sources := make(map[netip.Addr]bool)
	for _, a := range t.Assignments {
		s, err := netip.ParseAddr(a.Source)
		if err != nil {
			return err
		}
		sources[s] = true
		p, err := netip.ParseAddr(a.PrimaryVIP)
		if err != nil {
			return err
		}
		q, err := netip.ParseAddr(a.SecondaryVIP)
		if err != nil {
			return err
		}
		if p == q || a.PrimaryBackend == a.SecondaryBackend {
			return errors.New("primary and secondary must be distinct VIPs and backends")
		}
		for _, entry := range []struct {
			vip           netip.Addr
			backend, role string
		}{{p, a.PrimaryBackend, "primary"}, {q, a.SecondaryBackend, "secondary"}} {
			k, err := MakeKey(s, entry.vip)
			if err != nil {
				return err
			}
			if keys[k] {
				return fmt.Errorf("duplicate source/VIP key: %s -> %s", s, entry.vip)
			}
			keys[k] = true
			if old := roles[entry.vip]; old != "" && old != entry.role {
				return fmt.Errorf("VIP %s has inconsistent roles", entry.vip)
			}
			roles[entry.vip] = entry.role
			b, ok := backends[entry.backend]
			if !ok {
				return fmt.Errorf("unknown backend %q", entry.backend)
			}
			if (s.Is4() && b.IPv4 == "") || (s.Is6() && b.IPv6 == "") {
				return fmt.Errorf("backend %s has no address for %s", b.ID, s)
			}
		}
	}
	for vip := range roles {
		if sources[vip] {
			return fmt.Errorf("VIP %s is also a client", vip)
		}
	}
	return nil
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	if len(s) == 0 {
		return false
	}
	label := 0
	for i, c := range s {
		if c == '.' {
			if label == 0 || s[i-1] == '-' {
				return false
			}
			label = 0
			continue
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') || (label == 0 && c == '-') {
			return false
		}
		label++
		if label > 63 {
			return false
		}
	}
	return label > 0 && s[len(s)-1] != '-'
}
