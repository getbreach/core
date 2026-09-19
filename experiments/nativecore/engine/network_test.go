package engine

import (
	"errors"
	"testing"
	"time"
)

func TestNetworkRecoveryAndSleep(t *testing.T) {
	state := networkTracker{}
	now := int64(time.Second)
	step := func(gap time.Duration, snapshot string, changed bool, err error, want bool) {
		t.Helper()
		now += int64(gap)
		state.observe(now, snapshot, nil)
		if got := state.prepared(changed, err); got != want {
			t.Fatalf("reset=%v want=%v (snapshot=%s err=%v)", got, want, snapshot, err)
		}
	}
	step(time.Second, "en1:192.0.2.2", false, nil, false)
	step(2*time.Second, "en1:192.0.2.2", true, nil, true) // same IP, new gateway
	step(2*time.Second, "en1:192.0.2.2", false, nil, false)
	offline := errors.New("physical network unavailable")
	step(2*time.Second, "en1:192.0.2.2", false, offline, false)
	step(2*time.Second, "en1:192.0.2.2", false, offline, false)
	step(2*time.Second, "en1:192.0.2.2", false, nil, true) // recover once
	step(2*time.Second, "en1:192.0.2.2", false, nil, false)
	step(time.Minute, "en1:192.0.2.2", false, nil, true) // wake, unchanged address
	step(2*time.Second, "en2:192.0.2.3", false, offline, false)
	step(2*time.Second, "en2:192.0.2.3", false, nil, true) // reset only after routes ready
}
