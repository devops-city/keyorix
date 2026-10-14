{{/*
Fill in chart values that older releases did not have. `helm upgrade
--reuse-values` replaces this chart's values.yaml defaults with the OLD
release's values, so a key added after that release (secureBaseline.*,
web.hsts.*, web.trustedProxies, postgresql.runAsUser, auth.existingSecretKeys.*,
externalDatabase.caSecret.*)
is absent and `.Values.secureBaseline.enabled` is a nil-pointer error. Every
template that reads such a key includes this first (`{{- include
"keyorix.valuesDefaults" . -}}`; it renders nothing). Only a MISSING (or null)
key is set, never one the user gave, so `enabled: false` stays false. KEEP IN
SYNC with values.yaml: deploy/helm_reuse_values_test.go fails if they drift.
*/}}
{{- define "keyorix.valuesDefaults" -}}
{{- $v := .Values -}}
{{- $defaults := dict
  "auth" (dict "existingSecretKeys" (dict "adminPassword" false "bootstrapToken" false))
  "secureBaseline" (dict "enabled" true "certValidityDays" 3650 "existingSecret" "" "existingSecretRevision" "")
  "web" (dict "trustedProxies" (list) "hsts" (dict "mode" "auto" "maxAge" 31536000 "includeSubDomains" true))
  "postgresql" (dict "runAsUser" 70 "migrateOwnership" false)
  "externalDatabase" (dict "caSecret" (dict "name" "" "key" "ca.crt"))
-}}
{{- range $top, $sub := $defaults -}}
{{- if not (kindIs "map" (get $v $top)) -}}{{- $_ := set $v $top (dict) -}}{{- end -}}
{{- $cur := get $v $top -}}
{{- range $k, $d := $sub -}}
{{- if kindIs "map" $d -}}
{{- if not (kindIs "map" (get $cur $k)) -}}{{- $_ := set $cur $k (dict) -}}{{- end -}}
{{- $cur2 := get $cur $k -}}
{{- range $k2, $d2 := $d -}}
{{- if not (hasKey $cur2 $k2) -}}{{- $_ := set $cur2 $k2 $d2 -}}{{- else if kindIs "invalid" (get $cur2 $k2) -}}{{- $_ := set $cur2 $k2 $d2 -}}{{- end -}}
{{- end -}}
{{- else -}}
{{- if not (hasKey $cur $k) -}}{{- $_ := set $cur $k $d -}}{{- else if kindIs "invalid" (get $cur $k) -}}{{- $_ := set $cur $k $d -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

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
{{- $name := include "keyorix.secureBaseline.secretName" . -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $name -}}
{{- $data := dict -}}
{{- if and $existing $existing.data -}}
{{- $data = deepCopy $existing.data -}}
{{- end -}}
{{- if .Values.secureBaseline.existingSecret -}}
{{- /* BYO Secret: generate nothing. Where Helm can see the cluster (install,
upgrade) check the keys; under `helm template` (ArgoCD) lookup is empty, so the
check is skipped and the workloads fail to start if a key is missing. */ -}}
{{- if $existing -}}
{{- $missing := list -}}
{{- range $k := include "keyorix.secureBaseline.requiredKeys" . | fromJsonArray -}}
{{- if not (index $data $k) -}}
{{- $missing = append $missing $k -}}
{{- end -}}
{{- end -}}
{{- if $missing -}}
{{- fail (printf "secureBaseline.existingSecret %q is missing required key(s): %s. See deploy/helm/keyorix/README.md (Secure baseline with an existing Secret)." $name (join ", " $missing)) -}}
{{- end -}}
{{- end -}}
{{- else -}}
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
{{- end -}}
{{- $_ := set .Values "_secureBaselineData" $data -}}
{{- end -}}
{{- toJson .Values._secureBaselineData -}}
{{- end -}}

{{/*
Name of the Secret the secure-baseline pods mount: the operator's
secureBaseline.existingSecret, else the chart-generated <fullname>-secure-baseline.
*/}}
{{- define "keyorix.secureBaseline.secretName" -}}
{{- if .Values.secureBaseline.existingSecret -}}
{{- .Values.secureBaseline.existingSecret -}}
{{- else -}}
{{- printf "%s-secure-baseline" (include "keyorix.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Keys a secureBaseline Secret must carry (JSON list). The Postgres pair is only
required when the bundled PostgreSQL is deployed.
*/}}
{{- define "keyorix.secureBaseline.requiredKeys" -}}
{{- $keys := list "server.crt" "server.key" "metrics_token" -}}
{{- if .Values.postgresql.enabled -}}
{{- $keys = concat $keys (list "postgres.crt" "postgres.key") -}}
{{- end -}}
{{- toJson $keys -}}
{{- end -}}

{{/*
sha256 over "key=value\n" for the sorted secureBaseline Secret keys. A pod
template annotation checksum/secure-baseline: <this> rolls the pods when the
Secret changes (delete it to rotate, then helm upgrade), since Kubernetes does
not restart pods on a mounted Secret change.
With secureBaseline.existingSecretRevision set (BYO Secret) the revision is mixed
in: under `helm template` (ArgoCD) the Secret is invisible, so the data part is
constant and bumping the revision is the only way a GitOps change rolls the pods
after the operator rotated the Secret. Empty (default): the checksum is unchanged.
*/}}
{{- define "keyorix.secureBaseline.checksum" -}}
{{- $d := include "keyorix.secureBaseline.data" . | fromJson -}}
{{- $s := "" -}}
{{- range $k := keys $d | sortAlpha -}}
{{- $s = printf "%s%s=%s\n" $s $k (index $d $k) -}}
{{- end -}}
{{- if and .Values.secureBaseline.existingSecret .Values.secureBaseline.existingSecretRevision -}}
{{- $s = printf "%sexistingSecretRevision=%s\n" $s (toString .Values.secureBaseline.existingSecretRevision) -}}
{{- end -}}
{{- sha256sum $s -}}
{{- end -}}

{{/*
storage.database.ssl_root_cert for an external database (PG-TLS-2): the mounted
externalDatabase.caSecret, or externalDatabase.sslRootCert, or "". Fails the
render on the shapes the server would refuse at boot (a verifying sslMode with
no CA, a CA with sslMode disable) and on ambiguous ones (both set, caSecret
with the bundled PostgreSQL, which has no CA to name).
*/}}
{{- define "keyorix.externalDatabase.sslRootCert" -}}
{{- $db := .Values.externalDatabase -}}
{{- $ca := $db.caSecret | default dict -}}
{{- if .Values.postgresql.enabled -}}
{{- if $ca.name -}}
{{- fail "externalDatabase.caSecret applies to an external database only: set postgresql.enabled=false, or remove externalDatabase.caSecret.name" -}}
{{- end -}}
{{- else -}}
{{- if and $ca.name $db.sslRootCert -}}
{{- fail "set externalDatabase.caSecret.name OR externalDatabase.sslRootCert, not both: the server can trust only one CA source" -}}
{{- end -}}
{{- if $ca.name -}}
{{- if not $ca.key -}}
{{- fail "externalDatabase.caSecret.key must name the Secret key holding the CA's PEM (default ca.crt)" -}}
{{- end -}}
{{- if not (has $db.sslMode (list "require" "verify-ca" "verify-full")) -}}
{{- fail (printf "externalDatabase.caSecret needs externalDatabase.sslMode verify-full (or verify-ca/require), got %q: with %q the CA is never used to protect the connection" (toString $db.sslMode) (toString $db.sslMode)) -}}
{{- end -}}
{{- include "keyorix.externalDatabase.caFile" . -}}
{{- else if $db.sslRootCert -}}
{{- $db.sslRootCert -}}
{{- else if has $db.sslMode (list "verify-ca" "verify-full") -}}
{{- fail (printf "externalDatabase.sslMode is %s but no CA is configured: set externalDatabase.caSecret.name (a Secret holding the CA's PEM) or externalDatabase.sslRootCert (\"system\" or a path you mount); the server refuses to start without one" $db.sslMode) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Where the server pod mounts externalDatabase.caSecret. */}}
{{- define "keyorix.externalDatabase.caDir" -}}/app/db-ca{{- end -}}
{{- define "keyorix.externalDatabase.caFile" -}}{{ include "keyorix.externalDatabase.caDir" . }}/ca.crt{{- end -}}

{{/*
postgresql.settings (DB-TUNE-1): extra `postgres -c key=value` settings for the
bundled PostgreSQL. Keys must be plain setting names.
- Durability is not tunable here: the audit row is committed before a secret is
  returned, so synchronous_commit, fsync and full_page_writes accept only values
  that keep commits durable (an allow-list: PostgreSQL also accepts boolean
  prefixes such as "of" or "f", which a deny-list would miss).
- Settings that would override the secure baseline or run commands are refused:
  ssl and every ssl_* setting, hba_file, ident_file, listen_addresses, port,
  password_encryption, data_directory, config_file, archive_command,
  archive_library, restore_command.
- Whole-number values are printed as integers (a values file's 10000000 is a
  float to Helm and would otherwise render as 1e+07).
*/}}
{{- define "keyorix.postgresql.settings.value" -}}
{{- $v := . -}}
{{- if and (kindIs "float64" $v) (eq (floor $v) $v) -}}{{ int64 $v }}{{- else -}}{{ $v }}{{- end -}}
{{- end -}}
{{- define "keyorix.postgresql.settings" -}}
{{- $settings := .Values.postgresql.settings | default dict -}}
{{- $denied := list "ssl" "hba_file" "ident_file" "listen_addresses" "port" "password_encryption" "data_directory" "config_file" "archive_command" "archive_library" "restore_command" -}}
{{- $durable := dict "synchronous_commit" (list "on" "true" "yes" "1" "local" "remote_write" "remote_apply") "fsync" (list "on" "true" "yes" "1") "full_page_writes" (list "on" "true" "yes" "1") -}}
{{- range $k, $v := $settings -}}
{{- if not (regexMatch "^[a-z][a-z0-9_.]*$" $k) -}}
{{- fail (printf "postgresql.settings: %q is not a PostgreSQL setting name" $k) -}}
{{- end -}}
{{- if or (has $k $denied) (hasPrefix "ssl_" $k) -}}
{{- fail (printf "postgresql.settings.%s is not settable here: it would override the chart's secure baseline (TLS, authentication, listen address) or run a command" $k) -}}
{{- end -}}
{{- if hasKey $durable $k -}}
{{- if not (has (toString $v) (get $durable $k)) -}}
{{- fail (printf "postgresql.settings.%s=%q is refused: only %s keep a committed audit entry (or any write) safe on a crash" $k (toString $v) (join ", " (get $durable $k))) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range $k, $v := $settings }}
- -c
- {{ printf "%s=%s" $k (include "keyorix.postgresql.settings.value" $v) | quote }}
{{- end -}}
{{- end -}}

{{/*
GOMEMLIMIT for the server container, or "" for none. server.goMemLimit wins
verbatim when set (a Go size such as "400MiB"); otherwise it is
server.goMemLimitPercent of server.resources.limits.memory, rounded down to
KiB. Without a memory limit (or a quantity this parser doesn't know) nothing is
set and the Go default (no soft limit) applies; a percent of 0 turns the
default off.
*/}}
{{- define "keyorix.server.goMemLimit" -}}
{{- $s := .Values.server -}}
{{- if $s.goMemLimit -}}
{{- $s.goMemLimit -}}
{{- else -}}
{{- $lim := "" -}}
{{- if $s.resources -}}{{- if $s.resources.limits -}}{{- $lim = toString (default "" $s.resources.limits.memory) -}}{{- end -}}{{- else -}}{{- $lim = "512Mi" -}}{{- end -}}
{{- /* Absent (values reused from a release before this key) means the chart default, 85; an explicit 0 turns it off. */ -}}
{{- $pct := 85 -}}
{{- if hasKey $s "goMemLimitPercent" -}}{{- $pct = int $s.goMemLimitPercent -}}{{- end -}}
{{- if and $lim $pct -}}
{{- $num := regexFind "^[0-9]*\\.?[0-9]+" $lim -}}
{{- $unit := regexFind "[A-Za-z]+$" $lim -}}
{{- $mult := dict "" 1.0 "Ki" 1024.0 "Mi" 1048576.0 "Gi" 1073741824.0 "Ti" 1099511627776.0 "k" 1000.0 "K" 1000.0 "M" 1000000.0 "G" 1000000000.0 "T" 1000000000000.0 -}}
{{- if and $num (hasKey $mult $unit) -}}
{{- $kib := div (int64 (mulf (float64 $num) (get $mult $unit) (divf (float64 $pct) 100.0))) 1024 -}}
{{- if gt $kib 0 -}}{{ $kib }}KiB{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
