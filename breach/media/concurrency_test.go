package media

import (
	"bytes"
	"encoding/binary"
	"sort"
	"sync"
	"testing"
)

func TestConcurrentDataAndKeepaliveAcrossRollover(t *testing.T) {
	s := newLoopbackSession(t, DefaultMaxPadding)
	const start = 65500
	s.seq = start
	packets := make(chan []byte, 1024)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			pt := byte(PTData)
			if worker%2 == 0 {
				pt = PTKeepalive
			}
			for i := 0; i < 128; i++ {
				wire, err := s.Protect(pt, []byte{pt, byte(worker), byte(i)})
				if err != nil {
					t.Error(err)
					return
				}
				packets <- wire
			}
		}(worker)
	}
	wg.Wait()
	close(packets)
	all := make([][]byte, 0, 1024)
	for wire := range packets {
		all = append(all, wire)
	}
	sequence := func(wire []byte) int { return int(uint16(binary.BigEndian.Uint16(wire[2:4]) - uint16(start))) }
	sort.Slice(all, func(i, j int) bool { return sequence(all[i]) < sequence(all[j]) })
	if len(all) != 1024 {
		t.Fatalf("missing packets: %d", len(all))
	}
	for i, wire := range all {
		if sequence(wire) != i {
			t.Fatalf("sequence collision at %d", i)
		}
		pt, payload, err := s.Unprotect(wire)
		if err != nil || len(payload) != 3 || !bytes.Equal(payload[:1], []byte{pt}) {
			t.Fatalf("packet %d failed authentication/roundtrip: %v", i, err)
		}
	}
}
