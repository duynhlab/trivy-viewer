package watcher

import (
	"encoding/json"
	"fmt"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

// Normalize converts a Trivy report object (as an unstructured content map) into
// a model.Report tagged with the given cluster. The full object JSON is stored
// in Data; severity counts and metadata are extracted into columns. Field paths
// mirror upstream src/storage/extractors.rs so the reused UI reads them the same.
func Normalize(cluster, reportType string, obj map[string]any) (model.Report, error) {
	namespace, _ := nestedString(obj, "metadata", "namespace")
	name, _ := nestedString(obj, "metadata", "name")
	if name == "" {
		return model.Report{}, fmt.Errorf("report missing metadata.name")
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return model.Report{}, fmt.Errorf("marshal report data: %w", err)
	}

	rep := model.Report{
		Cluster:    cluster,
		Namespace:  namespace,
		Name:       name,
		ReportType: reportType,
		Data:       string(data),
	}
	rep.App = extractApp(obj)
	rep.Image = extractImage(obj)
	rep.Registry, _ = nestedString(obj, "report", "registry", "server")

	if reportType == model.ReportTypeSbom {
		rep.ComponentsCount = nestedInt(obj, "report", "summary", "componentsCount")
	} else {
		rep.Critical = nestedInt(obj, "report", "summary", "criticalCount")
		rep.High = nestedInt(obj, "report", "summary", "highCount")
		rep.Medium = nestedInt(obj, "report", "summary", "mediumCount")
		rep.Low = nestedInt(obj, "report", "summary", "lowCount")
		rep.Unknown = nestedInt(obj, "report", "summary", "unknownCount")
	}
	return rep, nil
}

// extractApp prefers the trivy-operator resource label, then common app labels.
func extractApp(obj map[string]any) string {
	labels, ok := nestedMap(obj, "metadata", "labels")
	if !ok {
		return ""
	}
	for _, key := range []string{"trivy-operator.resource.name", "app.kubernetes.io/name", "app"} {
		if v, ok := labels[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// extractImage joins artifact repository and tag ("repo:tag" or just "repo").
func extractImage(obj map[string]any) string {
	artifact, ok := nestedMap(obj, "report", "artifact")
	if !ok {
		return ""
	}
	repo, _ := artifact["repository"].(string)
	tag, _ := artifact["tag"].(string)
	if repo == "" {
		return ""
	}
	if tag == "" {
		return repo
	}
	return repo + ":" + tag
}

// --- nested accessors over unstructured content ---

func nestedMap(obj map[string]any, path ...string) (map[string]any, bool) {
	cur := obj
	for i, p := range path {
		v, ok := cur[p]
		if !ok {
			return nil, false
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			return m, true
		}
		cur = m
	}
	return cur, true
}

func nestedString(obj map[string]any, path ...string) (string, bool) {
	if len(path) == 0 {
		return "", false
	}
	parent, ok := nestedMap(obj, path[:len(path)-1]...)
	if !ok {
		return "", false
	}
	s, ok := parent[path[len(path)-1]].(string)
	return s, ok
}

// nestedInt reads a numeric leaf, tolerating JSON float64 and int64 encodings.
func nestedInt(obj map[string]any, path ...string) int {
	if len(path) == 0 {
		return 0
	}
	parent, ok := nestedMap(obj, path[:len(path)-1]...)
	if !ok {
		return 0
	}
	switch n := parent[path[len(path)-1]].(type) {
	case float64:
		return int(n)
	case int64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}
