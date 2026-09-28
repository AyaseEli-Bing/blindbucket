{{- define "blindbucket.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "blindbucket.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "blindbucket.labels" -}}
{{ include "blindbucket.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/*
Refuses a release that would run without what the gateway's claim rests on.
A missing Secret name here would otherwise surface as a pod stuck in
ContainerCreating, or -- for TLS -- as a gateway that serves plaintext across
the cluster network, which is the one outcome this chart exists to prevent.
*/}}
{{- define "blindbucket.validate" -}}
{{- if not .Values.tls.existingSecret -}}
{{- fail "tls.existingSecret is required: this chart serves S3 across the network, and without TLS the plaintext would cross it. For a deployment without TLS, run the gateway as a sidecar (deploy/kubernetes-sidecar.yaml)." -}}
{{- end -}}
{{- if not .Values.upstream.endpoint -}}
{{- fail "upstream.endpoint is required" -}}
{{- end -}}
{{- if not .Values.upstream.existingSecret -}}
{{- fail "upstream.existingSecret is required: a Secret with access_key_id and secret_access_key" -}}
{{- end -}}
{{- if not .Values.keys.keyringSecret -}}
{{- fail "keys.keyringSecret is required: a Secret with the keyring under keyring.json" -}}
{{- end -}}
{{- $p := .Values.keys.provider -}}
{{- if eq $p "file" -}}
{{- if not .Values.keys.passphraseSecret -}}
{{- fail "keys.passphraseSecret is required with keys.provider=file" -}}
{{- end -}}
{{- else if eq $p "vault" -}}
{{- if or (not .Values.keys.vault.address) (not .Values.keys.vault.tokenSecret) -}}
{{- fail "keys.vault.address and keys.vault.tokenSecret are required with keys.provider=vault" -}}
{{- end -}}
{{- else if eq $p "awskms" -}}
{{- if or (not .Values.keys.awskms.region) (not .Values.keys.awskms.keyId) (not .Values.keys.awskms.credentialsSecret) -}}
{{- fail "keys.awskms.region, keys.awskms.keyId and keys.awskms.credentialsSecret are required with keys.provider=awskms" -}}
{{- end -}}
{{- else -}}
{{- fail (printf "keys.provider must be file, vault or awskms, not %q" $p) -}}
{{- end -}}
{{- if not .Values.clients -}}
{{- fail "clients must name at least one client: without one, every request is refused" -}}
{{- end -}}
{{- range $i, $c := .Values.clients -}}
{{- if or (not $c.name) (not $c.existingSecret) (not $c.buckets) -}}
{{- fail (printf "clients[%d] needs name, existingSecret and buckets" $i) -}}
{{- end -}}
{{- end -}}
{{- end -}}
