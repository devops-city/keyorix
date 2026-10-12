{{/* Base name, overridable, truncated to the 63-char DNS limit. */}}
{{- define "keyorix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "keyorix.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "keyorix.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "keyorix.server.fullname" -}}{{ printf "%s-server" (include "keyorix.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "keyorix.web.fullname" -}}{{ printf "%s-web" (include "keyorix.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "keyorix.postgresql.fullname" -}}{{ printf "%s-postgresql" (include "keyorix.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}

{{/* The Secret holding KEYORIX_MASTER_PASSWORD / KEYORIX_DB_PASSWORD / admin / bootstrap token. */}}
{{- define "keyorix.secretName" -}}
{{- if .Values.auth.existingSecret -}}{{ .Values.auth.existingSecret }}{{- else -}}{{ include "keyorix.fullname" . }}{{- end -}}
{{- end -}}

{{/*
The token gating POST /system/init (server/main.go, KEYORIX_BOOTSTRAP_TOKEN).
Re-read from the already-rendered Secret via `lookup` so it survives
`helm upgrade` unchanged -- the standard idempotent-random-value pattern
(`lookup` sees nothing under `helm template`/`--dry-run`/`helm install
--dry-run`, so those always mint a fresh value; that's expected, since there
is no live Secret yet for it to diverge from).
*/}}
{{- define "keyorix.bootstrapToken" -}}
{{- $existing := (lookup "v1" "Secret" .Release.Namespace (include "keyorix.fullname" .)) -}}
{{- if and $existing $existing.data (index $existing.data "KEYORIX_BOOTSTRAP_TOKEN") -}}
{{- index $existing.data "KEYORIX_BOOTSTRAP_TOKEN" | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}

{{/*
Which optional keys the server's Secret carries, so the pod only gets a *_FILE
variable for a file that will exist (the server and entrypoint treat a *_FILE that
points at nothing as a fatal misconfiguration, not as "unset").
  - chart-managed Secret: the admin password only when auth.adminPassword is set;
    the bootstrap token always (secret.yaml generates it).
  - auth.existingSecret: true when auth.existingSecretKeys.<key> says so, or when
    the live Secret already has the key (`lookup`; empty under `helm template`/
    `--dry-run`, so CI renders see "false" there unless the flag is set).
Renders "true" or nothing.
*/}}
{{- define "keyorix.hasAdminPassword" -}}
{{- if .Values.auth.existingSecret -}}
{{- $k := .Values.auth.existingSecretKeys | default dict -}}
{{- $s := lookup "v1" "Secret" .Release.Namespace .Values.auth.existingSecret -}}
{{- if or $k.adminPassword (and $s $s.data (hasKey $s.data "KEYORIX_ADMIN_PASSWORD")) -}}true{{- end -}}
{{- else if .Values.auth.adminPassword -}}true{{- end -}}
{{- end -}}
{{- define "keyorix.hasBootstrapToken" -}}
{{- if .Values.auth.existingSecret -}}
{{- $k := .Values.auth.existingSecretKeys | default dict -}}
{{- $s := lookup "v1" "Secret" .Release.Namespace .Values.auth.existingSecret -}}
{{- if or $k.bootstrapToken (and $s $s.data (hasKey $s.data "KEYORIX_BOOTSTRAP_TOKEN")) -}}true{{- end -}}
{{- else -}}true{{- end -}}
{{- end -}}

{{/* Database host: the bundled Postgres service, or the external host. */}}
{{- define "keyorix.dbHost" -}}
{{- if .Values.postgresql.enabled -}}{{ include "keyorix.postgresql.fullname" . }}{{- else -}}{{ required "externalDatabase.host is required when postgresql.enabled is false" .Values.externalDatabase.host }}{{- end -}}
{{- end -}}

{{- define "keyorix.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "keyorix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "keyorix.server.image" -}}
{{- if .Values.server.image.digest -}}
{{- printf "%s@%s" .Values.server.image.repository .Values.server.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.server.image.repository (default .Chart.AppVersion .Values.server.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "keyorix.web.image" -}}
{{- if .Values.web.image.digest -}}
{{- printf "%s@%s" .Values.web.image.repository .Values.web.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.web.image.repository (default .Chart.AppVersion .Values.web.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
nginx's add_header does NOT merge/inherit across nesting levels: if a location
block defines even one add_header of its own, every add_header inherited from
the enclosing http/server block is silently dropped for that location, not
just individually overridden. web-config.yaml's http{} block sets these as
baseline security headers, but several location blocks also set their own
add_header (CORS, Cache-Control, health-check Content-Type) for other
purposes, which would otherwise strip all of these from those responses. This
template is the single source of truth; every location block that defines its
own add_header must also include this so the headers still apply there.

Strict-Transport-Security is NOT unconditional: this nginx listens on plain http
(port 80), TLS terminates at the Ingress / load balancer in front of it, and HSTS
sent over http:// is wrong (DEMO-WALK-3 finding 23, same as web/nginx.conf).
$keyorix_hsts (see keyorix.web.hsts below, rendered in web-config.yaml) is
non-empty only for a request from a web.trustedProxies peer that carries
X-Forwarded-Proto=https; add_header omits the header when it is empty.
*/}}
{{- define "keyorix.web.securityHeaders" -}}
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none';" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Strict-Transport-Security $keyorix_hsts always;
{{- end -}}

{{/*
geo/map defining $keyorix_trusted_proxy and $keyorix_hsts (http context). Mirrors
web/nginx-hsts.conf + web/docker-entrypoint.d/40-keyorix-hsts.sh for the compose
image. Values are validated here because they land in nginx config unquoted.
*/}}
{{- define "keyorix.web.hsts" -}}
{{- $mode := default "auto" .Values.web.hsts.mode -}}
{{- if not (has $mode (list "auto" "on" "off")) -}}
{{- fail (printf "web.hsts.mode must be auto, on or off (got %q)" $mode) -}}
{{- end -}}
{{- if not (regexMatch "^[0-9]+$" (toString (int64 .Values.web.hsts.maxAge))) -}}
{{- fail "web.hsts.maxAge must be a number of seconds" -}}
{{- end -}}
{{- range .Values.web.trustedProxies -}}
{{- if not (regexMatch "^[0-9a-fA-F:.]+(/[0-9]{1,3})?$" (toString .)) -}}
{{- fail (printf "web.trustedProxies: %q is not an IP or CIDR" (toString .)) -}}
{{- end -}}
{{- end -}}
{{- if and (eq $mode "on") (not .Values.web.trustedProxies) -}}
{{- fail "web.hsts.mode=on needs web.trustedProxies (HSTS is only sent for a trusted TLS-terminating proxy)" -}}
{{- end -}}
{{- $enabled := and (ne $mode "off") (gt (len .Values.web.trustedProxies) 0) -}}
geo $keyorix_trusted_proxy {
  default 0;
{{- if $enabled }}
{{- range .Values.web.trustedProxies }}
  {{ toString . }} 1;
{{- end }}
{{- end }}
}
map "$keyorix_trusted_proxy:$http_x_forwarded_proto" $keyorix_hsts {
  default "";
{{- if $enabled }}
  "~*^1:https$" "max-age={{ int64 .Values.web.hsts.maxAge }}{{ if .Values.web.hsts.includeSubDomains }}; includeSubDomains{{ end }}";
{{- end }}
}
{{- end -}}

{{/*
secureBaseline Secret data (SECURE-DEFAULT-1), computed ONCE per render and
returned as JSON, so the Secret and the pods' checksum/secure-baseline
annotation always describe the same bytes (the generated values are random, two
independent computations would differ). Existing keys are kept across upgrades
(lookup); only missing ones are generated. `helm template` has no cluster to
look up, so it renders fresh values each time.
*/}}
{{- define "keyorix.secureBaseline.data" -}}
{{- if not (hasKey .Values "_secureBaselineData") -}}
{{- $name := printf "%s-secure-baseline" (include "keyorix.fullname" .) -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $name -}}
{{- $data := dict -}}
{{- if and $existing $existing.data -}}
{{- $data = deepCopy $existing.data -}}
{{- end -}}
{{- $days := int .Values.secureBaseline.certValidityDays -}}
{{- if not (and (hasKey $data "server.crt") (hasKey $data "server.key")) -}}
{{- $svc := include "keyorix.server.fullname" . -}}
{{- $cert := genSelfSignedCert $svc nil (list $svc (printf "%s.%s" $svc .Release.Namespace) (printf "%s.%s.svc" $svc .Release.Namespace) "localhost") $days -}}
{{- $_ := set $data "server.crt" ($cert.Cert | b64enc) -}}
{{- $_ := set $data "server.key" ($cert.Key | b64enc) -}}
{{- end -}}
{{- if not (hasKey $data "metrics_token") -}}
{{- $_ := set $data "metrics_token" (randAlphaNum 48 | b64enc) -}}
{{- end -}}
{{- if and .Values.postgresql.enabled (not (and (hasKey $data "postgres.crt") (hasKey $data "postgres.key"))) -}}
{{- $pg := include "keyorix.postgresql.fullname" . -}}
{{- $pgCert := genSelfSignedCert $pg nil (list $pg (printf "%s.%s" $pg .Release.Namespace) (printf "%s.%s.svc" $pg .Release.Namespace)) $days -}}
{{- $_ := set $data "postgres.crt" ($pgCert.Cert | b64enc) -}}
{{- $_ := set $data "postgres.key" ($pgCert.Key | b64enc) -}}
{{- end -}}
{{- $_ := set .Values "_secureBaselineData" $data -}}
{{- end -}}
{{- toJson .Values._secureBaselineData -}}
{{- end -}}

{{/*
sha256 over "key=value\n" for the sorted secureBaseline Secret keys. A pod
template annotation checksum/secure-baseline: <this> rolls the pods when the
Secret changes (delete it to rotate, then helm upgrade), since Kubernetes does
not restart pods on a mounted Secret change.
*/}}
{{- define "keyorix.secureBaseline.checksum" -}}
{{- $d := include "keyorix.secureBaseline.data" . | fromJson -}}
{{- $s := "" -}}
{{- range $k := keys $d | sortAlpha -}}
{{- $s = printf "%s%s=%s\n" $s $k (index $d $k) -}}
{{- end -}}
{{- sha256sum $s -}}
{{- end -}}
