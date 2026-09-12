package loader

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kilo666mj/switchboard/internal/capability"
	capremote "github.com/kilo666mj/switchboard/internal/capability/remote"
	caprest "github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/egress"
)

func Load(ctx context.Context, dir string, selected []string, policy *egress.Policy) ([]capability.Capability, error) {
	wanted := make(map[string]bool, len(selected))
	for _, name := range selected {
		wanted[name] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read capability directory: %w", err)
	}
	found := map[string]bool{}
	var result []capability.Capability
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".example.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var envelope struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
		}
		if !wanted[envelope.Name] {
			continue
		}
		if found[envelope.Name] {
			return nil, fmt.Errorf("duplicate capability %q", envelope.Name)
		}
		var item capability.Capability
		if envelope.Type == "mcp" {
			var manifest capremote.Manifest
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				return nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
			}
			item, err = capremote.NewWithEgress(ctx, manifest, policy)
		} else {
			var manifest caprest.Manifest
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				return nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
			}
			item, err = caprest.NewWithEgress(manifest, policy)
		}
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", entry.Name(), err)
		}
		found[item.Name()] = true
		result = append(result, item)
	}
	var missing []string
	for name := range wanted {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("profile references missing capabilities: %s", strings.Join(missing, ", "))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name() < result[j].Name() })
	return result, nil
}
