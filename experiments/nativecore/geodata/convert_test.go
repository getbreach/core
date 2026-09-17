package geodata

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"breach-nativecore/routing"
)

func bfield(n uint64, b []byte) []byte {
	p := binary.AppendUvarint(nil, n<<3|2)
	p = binary.AppendUvarint(p, uint64(len(b)))
	return append(p, b...)
}
func vfield(n, v uint64) []byte { return binary.AppendUvarint(binary.AppendUvarint(nil, n<<3), v) }
func TestGeositeConversion(t *testing.T) {
	domain := append(vfield(1, 2), bfield(2, []byte("example.com"))...)
	entry := append(bfield(1, []byte("TEST")), bfield(2, domain)...)
	data := bfield(1, entry)
	sets, e := Decode(data, "geosite")
	if e != nil || len(sets["geosite-test"].Domains) != 1 || sets["geosite-test"].Domains[0] != "domain:example.com" {
		t.Fatalf("%v %v", sets, e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "in.dat")
	os.WriteFile(path, data, 0600)
	if _, e = Convert(path, "geosite", "test", dir); e != nil {
		t.Fatal(e)
	}
	if _, e = routing.LoadSet(filepath.Join(dir, "geosite-test.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = Convert(path, "geosite", "absent", dir); e == nil {
		t.Fatal("missing category accepted")
	}
}
func TestGeoIPAndMalformedData(t *testing.T) {
	cidr := append(bfield(1, []byte{192, 0, 2, 1}), vfield(2, 24)...)
	entry := append(bfield(1, []byte("TEST")), bfield(2, cidr)...)
	sets, e := Decode(bfield(1, entry), "geoip")
	if e != nil || sets["geoip-test"].IPs[0] != "192.0.2.0/24" {
		t.Fatalf("%v %v", sets, e)
	}
	if _, e = Decode(bfield(1, append(entry, vfield(3, 1)...)), "geoip"); e == nil {
		t.Fatal("inverse list ignored")
	}
	for _, b := range [][]byte{{0xff}, {0x0a, 0xff}, {0x0a, 9, 1}, {0}, nil} {
		if _, e = Decode(b, "geosite"); e == nil {
			t.Fatalf("malformed accepted: %x", b)
		}
	}
}
