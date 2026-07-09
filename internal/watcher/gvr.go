// Package watcher watches Trivy Operator CRDs via a dynamic informer and
// normalizes them into model.Report values. It is used both for the Hub's own
// cluster (local watcher) and for each registered Edge cluster.
package watcher

import (
	"github.com/duynhlab/trivy-viewer/internal/model"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Trivy Operator CRD group/version.
const (
	trivyGroup   = "aquasecurity.github.io"
	trivyVersion = "v1alpha1"
)

// GVRs for the two report kinds we collect.
var (
	VulnGVR = schema.GroupVersionResource{Group: trivyGroup, Version: trivyVersion, Resource: "vulnerabilityreports"}
	SbomGVR = schema.GroupVersionResource{Group: trivyGroup, Version: trivyVersion, Resource: "sbomreports"}
)

// reportTypeForGVR maps a GVR to the stored report_type discriminator.
func reportTypeForGVR(gvr schema.GroupVersionResource) string {
	if gvr.Resource == SbomGVR.Resource {
		return model.ReportTypeSbom
	}
	return model.ReportTypeVuln
}
