{{/*
Expand the name of the chart.
*/}}
{{- define "defensia-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "defensia-agent.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "defensia-agent.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "defensia-agent.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "defensia-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "defensia-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "defensia-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "defensia-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret holding the organization API key: the chart-managed one, or
.Values.existingSecret when the key is managed outside the chart.
*/}}
{{- define "defensia-agent.secretName" -}}
{{- default (include "defensia-agent.fullname" .) .Values.existingSecret }}
{{- end }}

{{- define "defensia-agent.secretKey" -}}
{{- if .Values.existingSecret }}
{{- default "api-key" .Values.existingSecretKey }}
{{- else }}
{{- print "api-key" }}
{{- end }}
{{- end }}

{{/*
Value accessors. apiKey/serverUrl/clusterName are the documented names; the
config.organizationApiKey / config.serverUrl / config.clusterName spellings
from older READMEs are still honoured.
*/}}
{{- define "defensia-agent.apiKey" -}}
{{- $legacy := .Values.config | default dict }}
{{- coalesce .Values.apiKey $legacy.organizationApiKey | default "" }}
{{- end }}

{{- define "defensia-agent.serverUrl" -}}
{{- $legacy := .Values.config | default dict }}
{{- coalesce $legacy.serverUrl .Values.serverUrl "https://defensia.cloud" }}
{{- end }}

{{- define "defensia-agent.clusterName" -}}
{{- $legacy := .Values.config | default dict }}
{{- coalesce .Values.clusterName $legacy.clusterName | default "" }}
{{- end }}
