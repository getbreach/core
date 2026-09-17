package routing

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// LoadSet accepts the native JSON format. Old binary .srs files must be
// converted explicitly; treating an unreadable list as empty would bypass rules.
func LoadSet(path string) (Set, error) {
	var s Set
	f, e := os.Open(path)
	if e != nil {
		return s, e
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return s, e
	}
	if stat.Size() > 32<<20 {
		return s, fmt.Errorf("rule set too large: %s", path)
	}
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if e = d.Decode(&s); e != nil {
		return s, fmt.Errorf("native JSON rule set %s: %w", path, e)
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return s, fmt.Errorf("rule set must contain one object")
	}
	return s, nil
}
func loadSets(cfg Config) (Config, error) {
	merged := make(map[string]Set, len(cfg.Sets)+len(cfg.SetFiles))
	for k, v := range cfg.Sets {
		merged[k] = v
	}
	for k, path := range cfg.SetFiles {
		if _, ok := merged[k]; ok {
			return cfg, fmt.Errorf("duplicate rule set %s", k)
		}
		v, e := LoadSet(path)
		if e != nil {
			return cfg, e
		}
		merged[k] = v
	}
	cfg.Sets = merged
	return cfg, nil
}
