### Security

- Alert-escalation and recover-admin webhook/Slack POSTs now re-validate the destination at send time (https only; private, loopback, link-local and IMDS IP literals refused), in addition to the create/update-time check and the existing dial-time guard, so a stored or injected-client destination can no longer reach 169.254.169.254 / 127.0.0.1 (CodeQL #1209).
