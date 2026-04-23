{{/*
Expand the name of the chart.
*/}}
{{- define "authgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "authgate.fullname" -}}
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
Chart name and version for labels.
*/}}
{{- define "authgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels (shared across authgate + postgres subresources).
*/}}
{{- define "authgate.labels" -}}
helm.sh/chart: {{ include "authgate.chart" . }}
{{ include "authgate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: authgate
{{- end }}

{{/*
Selector labels (authgate app).
*/}}
{{- define "authgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: authgate
{{- end }}

{{/*
Postgres component labels.
*/}}
{{- define "authgate.postgres.labels" -}}
helm.sh/chart: {{ include "authgate.chart" . }}
{{ include "authgate.postgres.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: authgate
{{- end }}

{{- define "authgate.postgres.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end }}

{{/*
Service account name.
*/}}
{{- define "authgate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "authgate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference. Defaults tag to "v" + .Chart.AppVersion to match the
release workflow which tags images with a leading "v".
*/}}
{{- define "authgate.image" -}}
{{- $tag := .Values.image.tag -}}
{{- if not $tag -}}
{{- $tag = printf "v%s" .Chart.AppVersion -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Name of the Secret that holds authgate's session secret, OIDC client
secret, and signing key. Returns existingSecret if provided.
*/}}
{{- define "authgate.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "authgate.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Postgres StatefulSet / Service name.
*/}}
{{- define "authgate.postgres.fullname" -}}
{{- printf "%s-postgres" (include "authgate.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Name of the Secret that holds the Postgres password.
*/}}
{{- define "authgate.postgres.secretName" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{- .Values.postgresql.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-postgres" (include "authgate.fullname" .) -}}
{{- end -}}
{{- end }}
