{{/* Common labels */}}
{{- define "aegis.labels" -}}
app.kubernetes.io/name: {{ .Values.target.name }}
app.kubernetes.io/managed-by: aegis-self-healing
app.kubernetes.io/component: protected-workload
{{- end }}

{{- define "aegis.controllerLabels" -}}
app.kubernetes.io/name: aegis-healing-controller
app.kubernetes.io/managed-by: aegis-self-healing
app.kubernetes.io/component: healing-controller
{{- end }}
