package gateway

import (
	"testing"

	"github.com/kilo666mj/switchboard/internal/capability"
)

func TestSearchRankingFilteringAndBounds(t *testing.T) {
	entries := []capability.Description{
		{Name: "z", Metadata: capability.Metadata{Description: "dns records", Tags: []string{"network"}}},
		{Name: "dns", Metadata: capability.Metadata{Title: "DNS records", Tags: []string{"Network"}}},
		{Name: "a", Metadata: capability.Metadata{Description: "dns records", Tags: []string{"network"}}},
	}
	for _, tc := range []struct {
		input searchInput
		names string
		total int
	}{
		{searchInput{Query: "DNS", Limit: 2}, "dns,a", 3},
		{searchInput{Query: "dns records", Tags: []string{"NETWORK"}}, "dns,a,z", 3},
		{searchInput{}, "a,dns,z", 3},
		{searchInput{Tags: []string{"network", "missing"}}, "", 0},
		{searchInput{Query: "absent"}, "", 0},
	} {
		got, err := searchCatalog(entries, tc.input)
		if err != nil {
			t.Fatal(err)
		}
		names := ""
		for _, d := range got.Capabilities {
			if names != "" {
				names += ","
			}
			names += d.Name
		}
		if names != tc.names || got.Total != tc.total {
			t.Fatalf("%+v: names=%s total=%d", tc.input, names, got.Total)
		}
	}
}
