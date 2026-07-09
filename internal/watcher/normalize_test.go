package watcher

import (
	"encoding/json"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

func mustObj(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return m
}

func TestNormalizeVulnReport(t *testing.T) {
	obj := mustObj(t, `{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind": "VulnerabilityReport",
		"metadata": {
			"namespace": "default",
			"name": "replicaset-nginx-abc",
			"labels": {"trivy-operator.resource.name": "nginx"}
		},
		"report": {
			"artifact": {"repository": "library/nginx", "tag": "1.25"},
			"registry": {"server": "docker.io"},
			"summary": {"criticalCount": 5, "highCount": 10, "mediumCount": 20, "lowCount": 15, "unknownCount": 3}
		}
	}`)

	rep, err := Normalize("hub", model.ReportTypeVuln, obj)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if rep.Cluster != "hub" || rep.Namespace != "default" || rep.Name != "replicaset-nginx-abc" {
		t.Errorf("keys = %s/%s/%s", rep.Cluster, rep.Namespace, rep.Name)
	}
	if rep.App != "nginx" {
		t.Errorf("app = %q, want nginx", rep.App)
	}
	if rep.Image != "library/nginx:1.25" {
		t.Errorf("image = %q, want library/nginx:1.25", rep.Image)
	}
	if rep.Registry != "docker.io" {
		t.Errorf("registry = %q, want docker.io", rep.Registry)
	}
	if rep.Critical != 5 || rep.High != 10 || rep.Medium != 20 || rep.Low != 15 || rep.Unknown != 3 {
		t.Errorf("counts = %d/%d/%d/%d/%d", rep.Critical, rep.High, rep.Medium, rep.Low, rep.Unknown)
	}
	if rep.Data == "" {
		t.Error("data should hold full report JSON")
	}
}

func TestNormalizeSbomReport(t *testing.T) {
	obj := mustObj(t, `{
		"kind": "SbomReport",
		"metadata": {"namespace": "prod", "name": "rs-app", "labels": {"app": "app"}},
		"report": {
			"artifact": {"repository": "app", "tag": ""},
			"summary": {"componentsCount": 150}
		}
	}`)

	rep, err := Normalize("edge", model.ReportTypeSbom, obj)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if rep.ComponentsCount != 150 {
		t.Errorf("components = %d, want 150", rep.ComponentsCount)
	}
	if rep.Image != "app" {
		t.Errorf("image = %q, want app (no tag)", rep.Image)
	}
	if rep.App != "app" {
		t.Errorf("app = %q, want app", rep.App)
	}
}

func TestNormalizeMissingName(t *testing.T) {
	obj := mustObj(t, `{"metadata": {"namespace": "x"}}`)
	if _, err := Normalize("hub", model.ReportTypeVuln, obj); err == nil {
		t.Fatal("expected error for missing metadata.name")
	}
}

func TestNormalizeMissingFieldsDefaultsZero(t *testing.T) {
	obj := mustObj(t, `{"metadata": {"name": "x", "namespace": "y"}}`)
	rep, err := Normalize("hub", model.ReportTypeVuln, obj)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if rep.App != "" || rep.Image != "" || rep.Registry != "" {
		t.Errorf("expected empty metadata, got %q/%q/%q", rep.App, rep.Image, rep.Registry)
	}
	if rep.Critical != 0 {
		t.Errorf("critical = %d, want 0", rep.Critical)
	}
}
