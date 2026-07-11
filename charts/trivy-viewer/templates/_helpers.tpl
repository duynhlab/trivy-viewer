{{/* Chart name */}}
{{- define "trivy-viewer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name */}}
{{- define "trivy-viewer.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Common labels */}}
{{- define "trivy-viewer.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "trivy-viewer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels for a component */}}
{{- define "trivy-viewer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trivy-viewer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Image reference */}}
{{- define "trivy-viewer.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* Per-component ServiceAccount names. A user-supplied
     .Values.serviceAccount.name collapses both components onto that single
     account (backward compatible with releases before the split). */}}
{{- define "trivy-viewer.serverServiceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else if .Values.serviceAccount.create -}}
{{- printf "%s-server" (include "trivy-viewer.fullname" .) -}}
{{- else -}}
default
{{- end -}}
{{- end -}}

{{- define "trivy-viewer.scraperServiceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else if .Values.serviceAccount.create -}}
{{- printf "%s-scraper" (include "trivy-viewer.fullname" .) -}}
{{- else -}}
default
{{- end -}}
{{- end -}}

{{/* Namespace holding cluster-registration Secrets */}}
{{- define "trivy-viewer.hubSecretNamespace" -}}
{{- .Values.hubSecretNamespace | default .Release.Namespace -}}
{{- end -}}
