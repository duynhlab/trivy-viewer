package config

import "testing"

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(envFrom(nil), "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.Mode != ModeServer {
		t.Errorf("Mode = %q, want %q", c.Mode, ModeServer)
	}
	if c.HealthPort != 8080 {
		t.Errorf("HealthPort = %d, want 8080", c.HealthPort)
	}
	if c.ServerPort != 3000 {
		t.Errorf("ServerPort = %d, want 3000", c.ServerPort)
	}
	if c.StoragePath != "/data" {
		t.Errorf("StoragePath = %q, want /data", c.StoragePath)
	}
	if !c.WatchLocal {
		t.Errorf("WatchLocal = false, want true (default)")
	}
}

func TestModeOverrideBeatsEnv(t *testing.T) {
	c, err := Load(envFrom(map[string]string{EnvMode: "server"}), "scraper")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.Mode != ModeScraper {
		t.Errorf("Mode = %q, want scraper (override wins)", c.Mode)
	}
}

func TestInvalidMode(t *testing.T) {
	_, err := Load(envFrom(map[string]string{EnvMode: "bogus"}), "")
	if err == nil {
		t.Fatal("expected error for invalid MODE, got nil")
	}
}

func TestInvalidHealthPort(t *testing.T) {
	_, err := Load(envFrom(map[string]string{EnvHealthPort: "99999"}), "")
	if err == nil {
		t.Fatal("expected error for out-of-range HEALTH_PORT, got nil")
	}
}

func TestAuthModeUnsupported(t *testing.T) {
	_, err := Load(envFrom(map[string]string{EnvAuthMode: "keycloak"}), "server")
	if err == nil {
		t.Fatal("expected error for unsupported AUTH_MODE in v1, got nil")
	}
}

func TestNamespacesCSV(t *testing.T) {
	c, err := Load(envFrom(map[string]string{
		EnvMode:       "scraper",
		EnvNamespaces: "default, prod ,, kube-system",
	}), "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"default", "prod", "kube-system"}
	if len(c.Namespaces) != len(want) {
		t.Fatalf("Namespaces = %v, want %v", c.Namespaces, want)
	}
	for i := range want {
		if c.Namespaces[i] != want[i] {
			t.Errorf("Namespaces[%d] = %q, want %q", i, c.Namespaces[i], want[i])
		}
	}
}
