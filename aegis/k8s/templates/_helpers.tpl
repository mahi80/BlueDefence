{{- define "aegis-agent.labels" -}}
app.kubernetes.io/name: aegis-agent
app.kubernetes.io/managed-by: aegis-agent-helm
app.kubernetes.io/component: agent-layer
{{- end }}
