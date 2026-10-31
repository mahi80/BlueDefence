{{- define "aegis-obs.labels" -}}
app.kubernetes.io/name: aegis-otel-collector
app.kubernetes.io/managed-by: aegis-observability
app.kubernetes.io/component: telemetry-collector
{{- end }}
