package model

import (
	"encoding/json"
	"testing"
)

func TestReportMetaProjection(t *testing.T) {
	created := "2026-01-01T00:00:00Z"
	rep := Report{
		Cluster: "hub", Namespace: "default", Name: "app", ReportType: ReportTypeVuln,
		App: "app", Image: "app:1", Registry: "docker.io",
		Critical: 1, High: 2, Medium: 3, Low: 4, Unknown: 5,
		ComponentsCount: 9, UpdatedAt: created, Notes: "n",
		NotesCreatedAt: &created,
	}
	m := rep.Meta()
	if m.Cluster != "hub" || m.Namespace != "default" || m.Name != "app" {
		t.Errorf("keys wrong: %+v", m)
	}
	if m.Summary != (VulnSummary{1, 2, 3, 4, 5}) {
		t.Errorf("summary = %+v", m.Summary)
	}
	if m.ComponentsCount != 9 || m.Registry != "docker.io" {
		t.Errorf("meta = %+v", m)
	}
	if m.NotesCreatedAt == nil || *m.NotesCreatedAt != created {
		t.Errorf("notes_created_at not carried through")
	}
}

func TestListResponseMarshalsItemsKey(t *testing.T) {
	b, err := json.Marshal(ListResponse[string]{Items: []string{"a"}, Total: 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	if got != `{"items":["a"],"total":1}` {
		t.Errorf("json = %s", got)
	}
}

func TestReportMetaJSONFieldNames(t *testing.T) {
	b, _ := json.Marshal(Report{Cluster: "c"}.Meta())
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"cluster", "namespace", "name", "summary", "components_count", "updated_at"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON key %q (UI contract)", key)
		}
	}
}
