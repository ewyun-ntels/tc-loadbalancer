// SPDX-License-Identifier: GPL-2.0
package control

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
)

const MaglevSize = 65537 // Prime; fixed as part of the v1 algorithm.

func score(parts ...string) uint64 {
	h := sha256.New()
	for _, p := range parts {
		// Length prefixes keep tuple boundaries unambiguous.
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))
	}
	return binary.BigEndian.Uint64(h.Sum(nil))
}

// Maglev returns a deterministic, equal-weight lookup table. Backend ordering
// and hashing are fixed; callers must use stable IDs, never DNS answer order.
func Maglev(ids []string) ([]string, error) {
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	if len(ids) == 0 || len(ids) > 256 {
		return nil, errors.New("Maglev requires 1..256 backends")
	}
	off, skip, next := make([]uint64, len(ids)), make([]uint64, len(ids)), make([]uint64, len(ids))
	for i, id := range ids {
		if id == "" || (i > 0 && id == ids[i-1]) {
			return nil, errors.New("backend IDs must be unique and nonempty")
		}
		off[i] = score("offset", id) % MaglevSize
		skip[i] = score("skip", id)%(MaglevSize-1) + 1
	}
	table := make([]string, MaglevSize)
	for filled := 0; filled < MaglevSize; {
		for i, id := range ids {
			pos := (off[i] + next[i]*skip[i]) % MaglevSize
			for table[pos] != "" {
				next[i]++
				pos = (off[i] + next[i]*skip[i]) % MaglevSize
			}
			table[pos] = id
			next[i]++
			filled++
			if filled == MaglevSize {
				break
			}
		}
	}
	return table, nil
}

// Generate materializes final (source, VIP)->backend assignments. Maglev alone
// balances hash slots, not a small finite client set. Here it supplies candidate
// preferences, while explicit count constraints balance the known clients.
// The primary-group/secondary count has priority over total secondary count.
func Generate(p Plan) (Table, error) {
	t := Table{Version: p.Version, Generation: p.Generation, Backends: append([]Backend(nil), p.Backends...)}
	if len(p.Clients) == 0 || len(p.VIPs) == 0 {
		return t, errors.New("clients and vip_pairs are required")
	}
	if len(p.Clients) > MaxAssignments/2 || len(p.VIPs) > MaxAssignments/2 {
		return t, errors.New("plan exceeds assignment capacity")
	}
	families := map[bool]bool{}
	for _, pair := range p.VIPs {
		vip, err := netip.ParseAddr(pair.Primary)
		if err != nil {
			return t, err
		}
		families[vip.Is4()] = true
	}
	for _, client := range p.Clients {
		for _, raw := range client.Addresses {
			ip, err := netip.ParseAddr(raw)
			if err != nil || !validIP(ip) || !families[ip.Is4()] {
				return t, fmt.Errorf("client %s address %q has no valid VIP family", client.ID, raw)
			}
		}
	}
	sort.Slice(t.Backends, func(i, j int) bool { return t.Backends[i].ID < t.Backends[j].ID })
	clients := append([]Client(nil), p.Clients...)
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	clientIDs := make(map[string]bool)
	for _, c := range clients {
		if c.ID == "" || clientIDs[c.ID] || len(c.Addresses) == 0 {
			return t, fmt.Errorf("invalid/duplicate client %q", c.ID)
		}
		clientIDs[c.ID] = true
	}
	pairs := append([]Pair(nil), p.VIPs...)
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Primary < pairs[j].Primary })
	for _, pair := range pairs {
		vip, err := netip.ParseAddr(pair.Primary)
		if err != nil {
			return t, err
		}
		other, err := netip.ParseAddr(pair.Secondary)
		if err != nil {
			return t, err
		}
		if !validIP(vip) || !validIP(other) || vip == other || vip.Is4() != other.Is4() {
			return t, errors.New("invalid VIP pair")
		}
		var ids []string
		for _, b := range t.Backends {
			if (vip.Is4() && b.IPv4 != "") || (vip.Is6() && b.IPv6 != "") {
				ids = append(ids, b.ID)
			}
		}
		mt, err := Maglev(ids)
		if err != nil {
			return t, err
		}
		if len(ids) < 2 {
			return t, errors.New("each VIP family requires at least two backends")
		}
		primaryCounts, secondaryCounts := make(map[string]int), make(map[string]int)
		groupCounts := make(map[string]map[string]int)
		for _, client := range clients {
			// Both families of one logical system use the same seed/ordering when
			// they have the same eligible backend set, keeping dual-stack aligned.
			preferred := preferences(mt, strconv.FormatUint(score("client", client.ID), 10))
			primary := preferred[0]
			for _, id := range preferred {
				if primaryCounts[id] < primaryCounts[primary] {
					primary = id
				}
			}
			if groupCounts[primary] == nil {
				groupCounts[primary] = make(map[string]int)
			}
			secondary := ""
			for _, id := range preferred {
				if id == primary {
					continue
				}
				if secondary == "" || groupCounts[primary][id] < groupCounts[primary][secondary] || (groupCounts[primary][id] == groupCounts[primary][secondary] && secondaryCounts[id] < secondaryCounts[secondary]) {
					secondary = id
				}
			}
			matched := false
			addresses := append([]string(nil), client.Addresses...)
			sort.Strings(addresses)
			for _, raw := range addresses {
				a, err := netip.ParseAddr(raw)
				if err != nil || !validIP(a) {
					return t, fmt.Errorf("invalid client address %q", raw)
				}
				if a.Is4() != vip.Is4() {
					continue
				}
				matched = true
				t.Assignments = append(t.Assignments, Assignment{a.String(), vip.String(), other.String(), primary, secondary})
				if len(t.Assignments)*2 > MaxAssignments {
					return t, errors.New("plan exceeds assignment capacity")
				}
			}
			if matched {
				primaryCounts[primary]++
				secondaryCounts[secondary]++
				groupCounts[primary][secondary]++
			}
		}
	}
	return t, t.Validate()
}

func preferences(table []string, seed string) []string {
	start := int(score("lookup", seed) % uint64(len(table)))
	seen := make(map[string]bool)
	var out []string
	for i := range table {
		id := table[(start+i)%len(table)]
		if !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out
}

type EndpointKey struct {
	Backend string
	Family  uint8
}
type Endpoint struct {
	IP      netip.Addr
	MAC     [6]uint8
	Healthy bool
}
type Decision struct {
	Source  string `json:"source"`
	VIP     string `json:"vip"`
	Backend string `json:"backend"`
	Active  bool   `json:"active"`
}

// Desired preserves every healthy baseline assignment. Only a failed baseline
// moves, using rendezvous hashing and excluding its paired backend. Recovery
// returns to baseline; existing connections on the fallback may reconnect.
func Desired(t Table, endpoints map[EndpointKey]Endpoint) (map[Key]Dest, []Decision) {
	out := make(map[Key]Dest)
	var decisions []Decision
	for _, a := range t.Assignments {
		s := netip.MustParseAddr(a.Source)
		family := uint8(6)
		if s.Is4() {
			family = 4
		}
		healthy := func(id string) bool { return endpoints[EndpointKey{id, family}].Healthy }
		choose := func(base, exclude, role string) string {
			if healthy(base) && base != exclude {
				return base
			}
			chosen := ""
			var best uint64
			for _, b := range t.Backends {
				if b.ID == exclude || !healthy(b.ID) {
					continue
				}
				v := score("fallback-v1", s.String(), a.PrimaryVIP, a.SecondaryVIP, role, b.ID)
				if chosen == "" || v > best || (v == best && b.ID < chosen) {
					chosen, best = b.ID, v
				}
			}
			return chosen
		}
		// Reserve a healthy baseline secondary before moving primary. This
		// prevents a primary failure from changing the healthy secondary too.
		exclude := ""
		if healthy(a.SecondaryBackend) {
			exclude = a.SecondaryBackend
		}
		primary := choose(a.PrimaryBackend, exclude, "primary")
		secondary := choose(a.SecondaryBackend, primary, "secondary")
		for _, v := range []struct{ vip, id string }{{a.PrimaryVIP, primary}, {a.SecondaryVIP, secondary}} {
			k, _ := MakeKey(s, netip.MustParseAddr(v.vip))
			d := Dest{}
			if v.id != "" {
				d.MAC = endpoints[EndpointKey{v.id, family}].MAC
				d.Flags = Active
			}
			out[k] = d
			decisions = append(decisions, Decision{s.String(), v.vip, v.id, v.id != ""})
		}
	}
	return out, decisions
}

type Health struct {
	Healthy             bool
	Successes, Failures int
}

func (h *Health) Observe(ok bool, up, down int) {
	if ok {
		h.Failures = 0
		if h.Successes < up {
			h.Successes++
		}
		if h.Successes >= up {
			h.Healthy = true
		}
	} else {
		h.Successes = 0
		if h.Failures < down {
			h.Failures++
		}
		if h.Failures >= down {
			h.Healthy = false
		}
	}
}

// Map is intentionally small so reconciliation can be tested without root.
type Map interface {
	Entries() (map[Key]Dest, error)
	Put(Key, Dest) error
}

// Sync updates whole values per key, never deleting a removed key into MISS
// (which the C program passes to routing). Removed keys become inactive
// tombstones. The current C ABI cannot swap an entire table atomically.
func Sync(m Map, desired map[Key]Dest) error {
	old, err := m.Entries()
	if err != nil {
		return err
	}
	count := len(old)
	for k := range desired {
		if _, ok := old[k]; !ok {
			count++
		}
	}
	if count > MaxAssignments {
		return fmt.Errorf("map capacity exceeded including tombstones: %d", count)
	}
	// First disable obsolete entries, then apply changes. On any error the
	// caller must withdraw BGP and must not advertise a partially synced map.
	for k, v := range old {
		if _, ok := desired[k]; !ok && v != (Dest{}) {
			if err := m.Put(k, Dest{}); err != nil {
				return err
			}
		}
	}
	for k, v := range desired {
		if prev, ok := old[k]; ok && prev == v {
			continue
		}
		if err := m.Put(k, v); err != nil {
			return err
		}
	}
	return nil
}
