{{/*
Expand the name of the chart.
*/}}
{{- define "cyberbox.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "cyberbox.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cyberbox.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cyberbox.labels" -}}
helm.sh/chart: {{ include "cyberbox.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cyberbox
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Selector labels for a given component.
Usage: {{ include "cyberbox.selectorLabels" (dict "root" . "component" "api") }}
*/}}
{{- define "cyberbox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cyberbox.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "cyberbox.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cyberbox.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference for a component.
Usage: {{ include "cyberbox.image" (dict "root" . "component" "api" "overrideRepo" .Values.api.image.repository) }}
*/}}
{{- define "cyberbox.image" -}}
{{- $repo := .overrideRepo -}}
{{- if not $repo -}}
{{- $repo = printf "%s/cyberbox-%s" .root.Values.global.image.registry .component -}}
{{- end -}}
{{- printf "%s:%s" $repo (.root.Values.global.image.tag | default "latest") -}}
{{- end }}
