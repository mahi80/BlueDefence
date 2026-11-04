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

{{- /* Forensic snapshot pods: their own name, so the target's Service, Rollout and
       egress policy never select them (they used to carry the target's labels). */ -}}
{{- define "aegis.forensicLabels" -}}
app.kubernetes.io/name: aegis-forensic-snapshot
app.kubernetes.io/managed-by: aegis-self-healing
app.kubernetes.io/component: forensic-snapshot
aegis.bank/role: forensic-snapshot
{{- end }}
