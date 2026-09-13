package maxproto

import (
	"reflect"
	"testing"
)

// turnHosts must strip the scheme by matching a leading token, not by cutting at
// the first colon: the old code did the latter and ate the host of a scheme-less
// "host:3478", leaving a bare port the pool would then try to allocate on.
func TestTurnHostsStripsSchemeKeepsHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "schemes are stripped to host:port",
			in:   []string{"turn:relay.example.org:3478", "stun:stun.example.org:3478", "stuns:stun.example.org:5349", "turns:relay.example.org:443"},
			want: []string{"relay.example.org:3478", "stun.example.org:3478", "stun.example.org:5349", "relay.example.org:443"},
		},
		{
			name: "query suffix is dropped",
			in:   []string{"turn:relay.example.org:3478?transport=tcp"},
			want: []string{"relay.example.org:3478"},
		},
		{
			// The regression: a scheme-less host must survive untouched.
			name: "bare host:port is left intact",
			in:   []string{"relay.example.org:3478"},
			want: []string{"relay.example.org:3478"},
		},
		{
			name: "ipv6 literals keep their colons",
			in:   []string{"turn:[2001:db8::1]:3478", "[2001:db8::1]:3478"},
			want: []string{"[2001:db8::1]:3478", "[2001:db8::1]:3478"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := turnHosts(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("turnHosts(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}
