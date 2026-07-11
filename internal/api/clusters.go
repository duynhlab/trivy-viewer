package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/hub"
	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type registerClusterRequest struct {
	Name        string   `json:"name"`
	Server      string   `json:"server"`
	BearerToken string   `json:"bearer_token"`
	CAData      string   `json:"ca_data"`
	Insecure    bool     `json:"insecure"`
	Namespaces  []string `json:"namespaces"`
}

type registeredCluster struct {
	Name                string   `json:"name"`
	Server              string   `json:"server"`
	Namespaces          []string `json:"namespaces"`
	Insecure            bool     `json:"insecure"`
	InCluster           bool     `json:"in_cluster"`
	Reachable           *bool    `json:"reachable,omitempty"`
	ReachabilityMessage string   `json:"reachability_message,omitempty"`
}

// hubReady guards endpoints that need Kubernetes access for Secret CRUD.
func (s *Server) hubReady(w http.ResponseWriter) (kubernetes.Interface, string, bool) {
	if s.kube == nil || s.hubNamespace == "" {
		writeError(w, http.StatusPreconditionFailed,
			"cluster registration requires in-cluster access and HUB_SECRET_NAMESPACE")
		return nil, "", false
	}
	return s.kube, s.hubNamespace, true
}

func (s *Server) listRegisteredClusters(w http.ResponseWriter, r *http.Request) {
	kube, ns, ok := s.hubReady(w)
	if !ok {
		return
	}
	secrets, err := kube.CoreV1().Secrets(ns).List(r.Context(), metav1.ListOptions{
		LabelSelector: hub.SecretTypeLabelKey + "=" + hub.SecretTypeCluster,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]registeredCluster, 0, len(secrets.Items))
	for i := range secrets.Items {
		cfg, err := hub.ParseClusterSecret(&secrets.Items[i])
		if err != nil {
			continue
		}
		out = append(out, registeredCluster{
			Name: cfg.Name, Server: cfg.Server, Namespaces: nonNil(cfg.Namespaces), Insecure: cfg.Insecure,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) registerCluster(w http.ResponseWriter, r *http.Request) {
	kube, ns, ok := s.hubReady(w)
	if !ok {
		return
	}
	var req registerClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateName(req.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Server == "" {
		writeError(w, http.StatusBadRequest, "server is required")
		return
	}

	nsJSON, _ := json.Marshal(nonNil(req.Namespaces))
	configJSON, _ := json.Marshal(map[string]any{
		"bearerToken": req.BearerToken,
		"tlsClientConfig": map[string]any{
			"caData":   req.CAData,
			"insecure": req.Insecure,
		},
	})

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-" + req.Name,
			Namespace: ns,
			Labels: map[string]string{
				hub.SecretTypeLabelKey: hub.SecretTypeCluster,
				hub.ManagedByLabelKey:  hub.ManagedByValue,
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"name":       req.Name,
			"server":     req.Server,
			"config":     string(configJSON),
			"namespaces": string(nsJSON),
		},
	}

	_, err := kube.CoreV1().Secrets(ns).Create(r.Context(), secret, metav1.CreateOptions{})
	if err != nil {
		// Update in place if it already exists.
		existing, getErr := kube.CoreV1().Secrets(ns).Get(r.Context(), secret.Name, metav1.GetOptions{})
		if getErr != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		existing.StringData = secret.StringData
		existing.Labels = secret.Labels
		if _, err := kube.CoreV1().Secrets(ns).Update(r.Context(), existing, metav1.UpdateOptions{}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, registeredCluster{
		Name: req.Name, Server: req.Server, Namespaces: nonNil(req.Namespaces), Insecure: req.Insecure,
	})
}

func (s *Server) deleteRegisteredCluster(w http.ResponseWriter, r *http.Request) {
	kube, ns, ok := s.hubReady(w)
	if !ok {
		return
	}
	name := chi.URLParam(r, "name")
	secrets, err := kube.CoreV1().Secrets(ns).List(r.Context(), metav1.ListOptions{
		LabelSelector: hub.SecretTypeLabelKey + "=" + hub.SecretTypeCluster,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	deleted := false
	for i := range secrets.Items {
		if string(secrets.Items[i].Data["name"]) == name {
			if err := kube.CoreV1().Secrets(ns).Delete(r.Context(), secrets.Items[i].Name, metav1.DeleteOptions{}); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			deleted = true
		}
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "cluster not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) validateCluster(w http.ResponseWriter, r *http.Request) {
	var req registerClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	restCfg, err := hub.BuildRESTConfig(hub.ClusterConfig{
		Name: req.Name, Server: req.Server, BearerToken: req.BearerToken,
		CAData: req.CAData, Insecure: req.Insecure,
	})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"reachable": false, "message": err.Error()})
		return
	}
	restCfg.Timeout = 5 * time.Second
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"reachable": false, "message": err.Error()})
		return
	}
	ver, err := client.Discovery().ServerVersion()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"reachable": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reachable": true, "message": "Kubernetes " + ver.GitVersion})
}

func (s *Server) registrationManifests(w http.ResponseWriter, r *http.Request) {
	edgeNS := orDefault(r.URL.Query().Get("edge_namespace"), "trivy-system")
	hubNS := orDefault(r.URL.Query().Get("hub_namespace"), orDefault(s.hubNamespace, "trivy-system"))
	clusterName := orDefault(r.URL.Query().Get("cluster_name"), "edge-a")

	writeJSON(w, http.StatusOK, map[string]any{
		"edge_namespace":      edgeNS,
		"hub_namespace":       hubNS,
		"cluster_name":        clusterName,
		"edge_rbac":           edgeRBACYAML(edgeNS),
		"extract_commands":    extractCommands(edgeNS),
		"hub_secret_template": hubSecretTemplate(hubNS, clusterName),
	})
}

func validateName(name string) error {
	if name == "" || len(name) > 63 {
		return fmt.Errorf("name must be 1-63 characters")
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("name may only contain lowercase letters, digits, and hyphens")
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return fmt.Errorf("name may not start or end with a hyphen")
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
