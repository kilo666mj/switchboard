package config

import "testing"

func TestValidateProfile(t *testing.T) {
	t.Parallel()
	cfg := Config{Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {"rilldns", "fleetglass"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsDuplicateCapability(t *testing.T) {
	t.Parallel()
	cfg := Config{Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {"rilldns", "rilldns"}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate succeeded with a duplicate capability")
	}
}

func TestClientPolicyValidation(t *testing.T) {
	for _, client := range []Client{
		{TokenEnv: "TOKEN", Profile: "missing"},
		{Profile: "all"},
		{TokenEnv: "TOKEN", Profile: "all", InitialCapabilities: []string{"hidden"}},
		{TokenEnv: "TOKEN", Profile: "all", InitialCapabilities: []string{"demo", "demo"}},
	} {
		cfg := Config{Transport: "http", Profile: "all", Profiles: map[string][]string{"all": {"demo"}}, Clients: map[string]Client{"test": client}}
		if cfg.Validate() == nil {
			t.Fatalf("invalid client accepted: %+v", client)
		}
	}
}
