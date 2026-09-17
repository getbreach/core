// Package geodata converts V2Ray/Xray .dat lists into Breach native JSON sets.
// No Xray or sing-box runtime is linked. Only the protobuf wire format is read.
package geodata

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"breach-nativecore/routing"
)

type field struct {
	number  uint64
	bytes   []byte
	integer uint64
	wire    uint64
}

func fields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 || key>>3 == 0 {
			return nil, errors.New("invalid protobuf tag")
		}
		b = b[n:]
		f := field{number: key >> 3, wire: key & 7}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("invalid protobuf integer")
			}
			f.integer = v
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("short protobuf fixed64")
			}
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, errors.New("short protobuf bytes")
			}
			b = b[n:]
			f.bytes = b[:int(l)]
			b = b[int(l):]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("short protobuf fixed32")
			}
			b = b[4:]
		default:
			return nil, errors.New("unsupported protobuf wire type")
		}
		out = append(out, f)
	}
	return out, nil
}

var tagPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

func Decode(data []byte, kind string) (map[string]routing.Set, error) {
	if kind != "geosite" && kind != "geoip" {
		return nil, errors.New("kind must be geosite or geoip")
	}
	root, e := fields(data)
	if e != nil {
		return nil, e
	}
	sets := map[string]routing.Set{}
	for _, entry := range root {
		if entry.number != 1 || entry.wire != 2 {
			continue
		}
		fs, e := fields(entry.bytes)
		if e != nil {
			return nil, e
		}
		name := ""
		set := routing.Set{}
		for _, f := range fs {
			if f.number == 1 && f.wire == 2 {
				name = strings.ToLower(string(f.bytes))
			}
			if kind == "geoip" && f.number == 3 && f.integer != 0 {
				return nil, errors.New("inverse GeoIP lists are not supported")
			}
			if f.number != 2 || f.wire != 2 {
				continue
			}
			inner, e := fields(f.bytes)
			if e != nil {
				return nil, e
			}
			if kind == "geosite" {
				typ := uint64(0)
				value := ""
				for _, v := range inner {
					if v.number == 1 && v.wire == 0 {
						typ = v.integer
					}
					if v.number == 2 && v.wire == 2 {
						value = string(v.bytes)
					}
				}
				prefix := []string{"keyword:", "regexp:", "domain:", "full:"}
				if typ >= uint64(len(prefix)) || value == "" {
					return nil, errors.New("invalid geosite domain")
				}
				set.Domains = append(set.Domains, prefix[typ]+value)
			} else {
				var ip []byte
				bits := uint64(0)
				for _, v := range inner {
					if v.number == 1 && v.wire == 2 {
						ip = v.bytes
					}
					if v.number == 2 && v.wire == 0 {
						bits = v.integer
					}
				}
				a, ok := netip.AddrFromSlice(ip)
				if !ok || bits > uint64(a.BitLen()) {
					return nil, errors.New("invalid GeoIP prefix")
				}
				set.IPs = append(set.IPs, netip.PrefixFrom(a, int(bits)).Masked().String())
			}
		}
		if !tagPattern.MatchString(name) {
			return nil, fmt.Errorf("invalid category name %q", name)
		}
		key := kind + "-" + name
		if _, ok := sets[key]; ok {
			return nil, fmt.Errorf("duplicate category %s", name)
		}
		sets[key] = set
	}
	if len(sets) == 0 {
		return nil, errors.New("no categories found")
	}
	return sets, nil
}

// Convert writes one category, or all categories when category is empty.
func Convert(path, kind, category, outDir string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return "", e
	}
	if st.Size() > 64<<20 {
		return "", errors.New("geodata exceeds 64 MiB")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	sets, e := Decode(data, kind)
	if e != nil {
		return "", e
	}
	if category != "" {
		key := kind + "-" + strings.ToLower(category)
		v, ok := sets[key]
		if !ok {
			return "", fmt.Errorf("category not found: %s", category)
		}
		sets = map[string]routing.Set{key: v}
	}
	if e = os.MkdirAll(outDir, 0700); e != nil {
		return "", e
	}
	var tags []string
	for tag, set := range sets {
		b, e := json.Marshal(set)
		if e != nil {
			return "", e
		}
		temp, e := os.CreateTemp(outDir, ".geodata-*.json")
		if e != nil {
			return "", e
		}
		path := temp.Name()
		_, e = temp.Write(b)
		closeErr := temp.Close()
		if e == nil {
			e = closeErr
		}
		if e == nil {
			e = os.Rename(path, filepath.Join(outDir, tag+".json"))
		}
		if e != nil {
			os.Remove(path)
			return "", e
		}
		tags = append(tags, tag)
	}
	return strings.Join(tags, "\n"), nil
}
