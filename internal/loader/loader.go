package loader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kilo666mj/switchboard/internal/capability"
	capmodule "github.com/kilo666mj/switchboard/internal/capability/module"
	capremote "github.com/kilo666mj/switchboard/internal/capability/remote"
	caprest "github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/egress"
)

type LoadFailure struct {
	Name string
	Err  error
}

func (f LoadFailure) Error() string {
	return fmt.Sprintf("load capability %s: %v", f.Name, f.Err)
}

func Load(ctx context.Context, dir string, selected []string, policy *egress.Policy) ([]capability.Capability, error) {
	items, failures, err := LoadAvailable(ctx, dir, selected, policy)
	if err != nil {
		return nil, err
	}
	if len(failures) > 0 {
		closeCapabilities(items)
		return nil, failures[0]
	}
	return items, nil
}

// LoadAvailable validates the complete selected configuration but treats
// recoverable MCP process/connectivity failures as per-capability degradation.
// Invalid manifests, missing selections, and policy violations remain fatal.
func LoadAvailable(ctx context.Context, dir string, selected []string, policy *egress.Policy) ([]capability.Capability, []LoadFailure, error) {
	wanted := make(map[string]bool, len(selected))
	for _, name := range selected {
		wanted[name] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read capability directory: %w", err)
	}
	found := map[string]bool{}
	var result []capability.Capability
	var failures []LoadFailure
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".example.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			closeCapabilities(result)
			return nil, nil, err
		}
		var envelope struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			closeCapabilities(result)
			return nil, nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
		}
		if !wanted[envelope.Name] {
			continue
		}
		if found[envelope.Name] {
			closeCapabilities(result)
			return nil, nil, fmt.Errorf("duplicate capability %q", envelope.Name)
		}
		found[envelope.Name] = true
		var item capability.Capability
		switch envelope.Type {
		case "mcp":
			var manifest capremote.Manifest
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				closeCapabilities(result)
				return nil, nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
			}
			item, err = capremote.NewWithEgress(ctx, manifest, policy)
		case "module":
			var manifest capmodule.Manifest
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				closeCapabilities(result)
				return nil, nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
			}
			item, err = capmodule.New(ctx, manifest, policy)
		case "":
			var manifest caprest.Manifest
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				closeCapabilities(result)
				return nil, nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
			}
			item, err = caprest.NewWithEgress(manifest, policy)
		default:
			closeCapabilities(result)
			return nil, nil, fmt.Errorf("decode %s: unsupported capability type %q", entry.Name(), envelope.Type)
		}
		if err != nil {
			if errors.Is(err, capability.ErrUnavailable) {
				failures = append(failures, LoadFailure{Name: envelope.Name, Err: fmt.Errorf("load %s: %w", entry.Name(), err)})
				continue
			}
			closeCapabilities(result)
			return nil, nil, fmt.Errorf("load %s: %w", entry.Name(), err)
		}
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
		closeCapabilities(result)
		return nil, nil, fmt.Errorf("profile references missing capabilities: %s", strings.Join(missing, ", "))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name() < result[j].Name() })
	sort.Slice(failures, func(i, j int) bool { return failures[i].Name < failures[j].Name })
	return result, failures, nil
}

func closeCapabilities(items []capability.Capability) {
	for _, item := range items {
		if closer, ok := item.(capability.Closer); ok {
			_ = closer.Close()
		}
	}
}
