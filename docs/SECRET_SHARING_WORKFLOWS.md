# Secret Sharing Workflows and Examples

## Overview

This document provides practical examples and workflows for common secret sharing scenarios. These examples demonstrate best practices and real-world usage patterns for the Secret Sharing feature.

Every CLI command below was checked against the real `keyorix` command tree
(`keyorix <command> --help`). Two things to know before you copy them:

- **The CLI addresses secrets, users and groups by numeric ID in `share`
  commands**, not by name. Find IDs with `keyorix secret list`,
  `keyorix user get --email <email>` and `keyorix group get <name>`.
- **No secret value ever goes on a command line** (arguments are visible via
  `ps` and saved in shell history). Use `--interactive`, `--from-file` or a
  `KEYORIX_*` environment variable, as in Workflow 6.

## Table of Contents
1. [Basic Workflows](#basic-workflows)
2. [Team Collaboration](#team-collaboration)
3. [DevOps Scenarios](#devops-scenarios)
4. [Enterprise Workflows](#enterprise-workflows)
5. [Automation Examples](#automation-examples)
6. [Troubleshooting Workflows](#troubleshooting-workflows)

## Basic Workflows

### Workflow 1: Share Database Credentials with Developer

**Scenario**: A DBA needs to share production database credentials with a developer for debugging.

**Steps**:
1. **DBA creates/locates the secret**
2. **Share with read-only access**
3. **Developer accesses credentials**
4. **DBA revokes access after debugging**

**Implementation**:

#### Via Web Interface
```
1. DBA navigates to "Production DB Password" secret
2. Clicks "Share" button
3. Enters developer username: "john.developer"
4. Selects "Read" permission
5. Clicks "Share Secret"
6. Developer receives notification
7. After debugging, DBA revokes access
```

#### Via CLI
```bash
# DBA looks up the IDs (secret 123, user 789 in this example)
keyorix secret list
keyorix user get --email john.developer@company.com

# DBA shares the secret
keyorix share create \
  --secret-id 123 \
  --recipient-id 789 \
  --permission read

# Developer accesses the secret
keyorix secret get --id 123 --show-value

# DBA revokes access after debugging
keyorix share list --secret-id 123
keyorix share revoke --share-id 456
```

#### Via API
```bash
# DBA shares the secret
curl -X POST "$KEYORIX_SERVER/api/v1/secrets/123/share" \
  -H "Authorization: Bearer dba-token" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": 789,
    "is_group": false,
    "permission": "read"
  }'

# Developer accesses the secret
curl -X GET "$KEYORIX_SERVER/api/v1/secrets/123" \
  -H "Authorization: Bearer dev-token"

# DBA revokes access
curl -X DELETE "$KEYORIX_SERVER/api/v1/shares/456" \
  -H "Authorization: Bearer dba-token"
```

### Workflow 2: Temporary Access for Contractor

**Scenario**: Grant temporary access to API keys for a contractor working on integration.

**Steps**:
1. **Create time-limited share**
2. **Monitor contractor access**
3. **Automatic or manual revocation**

**Implementation**:
```bash
# Share with contractor for 7 days (secret 124, contractor is user 790).
# --ttl is a Go duration (168h = 7 days); --expires takes an absolute RFC3339 time.
keyorix share create \
  --secret-id 124 \
  --recipient-id 790 \
  --permission read \
  --ttl 168h

# Monitor access
keyorix secret access-log --id 124 --days 7
keyorix audit logs --user-id 790 --since 2026-01-01T00:00:00Z

# Extend or shorten the expiry later
keyorix share update --share-id 457 --permission read --ttl 24h

# Manual revocation if needed
keyorix share list --secret-id 124
keyorix share revoke --share-id 457
```

## Team Collaboration

### Workflow 3: Development Team Secret Sharing

**Scenario**: Share development environment secrets with the entire development team.

**Implementation**:

#### Using Groups (Recommended)
```bash
# Create or use existing development group
keyorix group create --name "developers" \
  --description "Development team members"

# Add team members to group (username, email or numeric ID)
keyorix group add-member --group developers --user alice.dev
keyorix group add-member --group developers --user bob.dev
keyorix group add-member --group developers --user charlie.dev

# Find the group's ID
keyorix group get developers

# Share secrets with the entire group (group 5; secrets 101 and 102)
keyorix share create \
  --secret-id 101 \
  --recipient-id 5 --is-group \
  --permission write

keyorix share create \
  --secret-id 102 \
  --recipient-id 5 --is-group \
  --permission read
```

#### Individual Sharing (Alternative)
```bash
# Share with each team member individually (user IDs 11, 12, 13)
for uid in 11 12 13; do
  keyorix share create \
    --secret-id 101 \
    --recipient-id "$uid" \
    --permission write
done
```

Sharing again with the same recipient updates the existing share instead of
creating a duplicate, so these commands are safe to re-run.

### Workflow 4: Cross-Team Collaboration

**Scenario**: Frontend team needs access to backend API secrets for integration testing.

**Implementation**:
```bash
# Backend team lead shares API secrets with the frontend-team group (group 8)
keyorix share create \
  --secret-id 201 \
  --recipient-id 8 --is-group \
  --permission read

# Share staging environment secrets
keyorix share create \
  --secret-id 202 \
  --recipient-id 8 --is-group \
  --permission read

# Monitor usage
keyorix share group-shares --group-id 8
keyorix secret access-log --id 201
```

## DevOps Scenarios

### Workflow 5: CI/CD Pipeline Secrets

**Scenario**: Give a CI/CD pipeline access to deployment secrets.

Shares go to users and groups. A pipeline is not a person, so it gets a
**machine identity** with a project-scoped role and its own token instead.

**Implementation**:
```bash
# Create a machine identity for CI/CD in project 1
keyorix machine create \
  --name "github-actions" \
  --project 1 \
  --type ci \
  --description "GitHub Actions CI/CD"

# Pick a role (keyorix rbac list-roles) and grant it at the project's scope
keyorix machine grant-role github-actions --project 1 --role <role>

# Issue a token for the pipeline; the raw token is shown once, store it in the
# CI system's own secret store
keyorix machine token issue github-actions --project 1 \
  --name "github-actions-prod" --expires-in-days 90

# Monitor CI/CD access
keyorix machine audit
keyorix audit logs --actor-type machine_identity --limit 100
```

### Workflow 6: Infrastructure Team Rotation

**Scenario**: Rotate infrastructure secrets and update team access.

**Implementation**:
```bash
#!/bin/bash
# Infrastructure secret rotation script

# Infrastructure secrets to rotate, as "<secret id>:<name>"
SECRETS=("11:AWS Root Key" "12:Database Master Password" "13:SSL Certificates")
INFRA_GROUP_ID=5   # numeric ID of the infrastructure-team group

# The new value goes through a private file, never onto the command line
# (arguments are visible via ps/proc and saved in shell history).
# --from-file takes a relative, non-symlink path, so keep the file in the
# current directory and remove it when done.
umask 077
VALUE_FILE=./.new-secret-value
trap 'rm -f "$VALUE_FILE"' EXIT

for entry in "${SECRETS[@]}"; do
  id="${entry%%:*}"
  secret="${entry#*:}"
  echo "Rotating: $secret"

  # Generate new secret value
  openssl rand -base64 32 | tr -d '\n' > "$VALUE_FILE"

  # Update secret
  keyorix secret update --id "$id" --from-file "$VALUE_FILE"

  # Ensure infrastructure team has access (re-sharing updates the existing share)
  keyorix share create \
    --secret-id "$id" \
    --recipient-id "$INFRA_GROUP_ID" --is-group \
    --permission write

  # The CLI has no "notify" command. Tell the team through your own channel
  # (chat webhook, e-mail), or rely on the server's notification channels
  # (keyorix notification channel --help).
  echo "Secret '$secret' has been rotated"
done
```

## Enterprise Workflows

### Workflow 7: Compliance Audit Preparation

**Scenario**: Prepare for security audit by reviewing all secret shares.

**Implementation**:
```bash
# Export the audit trail as CSV for the auditor
keyorix audit export --csv --all --since 2026-01-01T00:00:00Z > audit-export.csv

# Who can reach a project's secrets through a role or a share (project 1)
keyorix access-review --project-id 1

# Review the effective access list of one high-value secret
keyorix secret access --id 123

# Review the shares of one secret, and everything shared with one group or user
keyorix share list --secret-id 123
keyorix share group-shares --group-id 5
keyorix share shared-secrets --user-id 789

# Review group memberships
keyorix group list
keyorix group members developers
```

### Workflow 8: Incident Response - Compromised Account

**Scenario**: Respond to a compromised user account by revoking all their access.

**Implementation**:
```bash
#!/bin/bash
# Incident response script for compromised account
# Usage: ./respond.sh <user id> <your admin email>

COMPROMISED_USER_ID="$1"
ADMIN_EMAIL="$2"
INCIDENT_ID="INC-2025-001"

echo "Starting incident response for user id: $COMPROMISED_USER_ID"

# 1. Immediately block login
keyorix user suspend --id "$COMPROMISED_USER_ID" --by "$ADMIN_EMAIL"

# 2. Revoke all active sessions
keyorix user revoke-sessions --id "$COMPROMISED_USER_ID" --by "$ADMIN_EMAIL"

# 3. List all secrets shared with the user
keyorix share shared-secrets --user-id "$COMPROMISED_USER_ID"

# 4. Remove each share (list the share IDs per secret, then revoke)
#    keyorix share list --secret-id <secret id>
#    keyorix share revoke --share-id <share id>

# 5. Review what the user did
keyorix audit logs --user-id "$COMPROMISED_USER_ID" --limit 100
keyorix audit export --csv --all --since 2026-01-01T00:00:00Z > "incident-${INCIDENT_ID}-audit.csv"

# 6. Re-home or rotate what they owned
#    keyorix secret reassign-owner --help
#    keyorix secret rotate --id <secret id>   (prompts for the new value)

echo "Incident response completed. Review generated reports."
```

## Automation Examples

### Workflow 9: Automated Onboarding

**Scenario**: Automatically grant new team members access to appropriate secrets.

**Implementation**:
```bash
#!/bin/bash
# New employee onboarding script
# Secret IDs are examples; look yours up with: keyorix secret list

NEW_USER="$1"      # username, email or numeric ID
NEW_USER_ID="$2"   # numeric user ID (share create takes IDs)
TEAM="$3"
ROLE="$4"

if [ -z "$NEW_USER" ] || [ -z "$NEW_USER_ID" ] || [ -z "$TEAM" ] || [ -z "$ROLE" ]; then
  echo "Usage: $0 <username> <user id> <team> <role>"
  exit 1
fi

echo "Onboarding $NEW_USER to $TEAM as $ROLE"

# Add user to team group
keyorix group add-member --group "$TEAM" --user "$NEW_USER"

# Grant role-specific access
case "$ROLE" in
  "developer")
    keyorix share create --secret-id 301 --recipient-id "$NEW_USER_ID" --permission write
    keyorix share create --secret-id 302 --recipient-id "$NEW_USER_ID" --permission read
    ;;
  "devops")
    keyorix share create --secret-id 303 --recipient-id "$NEW_USER_ID" --permission write
    keyorix share create --secret-id 304 --recipient-id "$NEW_USER_ID" --permission read
    ;;
  "qa")
    keyorix share create --secret-id 305 --recipient-id "$NEW_USER_ID" --permission read
    ;;
esac

# The CLI has no "notify" command; send the welcome message through your own channel.
echo "Onboarding completed for $NEW_USER"
```

### Workflow 10: Automated Secret Rotation

**Scenario**: Automatically rotate secrets and update all shares.

**Implementation**:
```python
#!/usr/bin/env python3
"""
Automated secret rotation with sharing updates
"""

import os
import json
import requests
from datetime import datetime, timedelta

class SecretRotator:
    def __init__(self, api_base, token):
        self.api_base = api_base
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    
    def rotate_secret(self, secret_id, new_value):
        """Rotate a secret value"""
        url = f"{self.api_base}/secrets/{secret_id}"
        data = {'value': new_value}
        
        response = requests.put(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def get_secret_shares(self, secret_id):
        """Get all shares for a secret"""
        url = f"{self.api_base}/secrets/{secret_id}/shares"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()['data']['shares']
    
    def notify_share_recipients(self, secret_id, secret_name):
        """Notify all recipients of secret rotation"""
        shares = self.get_secret_shares(secret_id)
        
        for share in shares:
            recipient_id = share['recipient_id']
            message = f"Secret '{secret_name}' has been rotated. Please update your applications."
            
            # Send notification (implementation depends on notification system)
            self.send_notification(recipient_id, message)
    
    def rotate_with_notification(self, secret_id, secret_name, new_value):
        """Rotate secret and notify all recipients"""
        print(f"Rotating secret: {secret_name}")
        
        # Rotate the secret
        result = self.rotate_secret(secret_id, new_value)
        
        # Notify all recipients
        self.notify_share_recipients(secret_id, secret_name)
        
        # Log the rotation
        self.log_rotation(secret_id, secret_name)
        
        return result

# Usage example
if __name__ == "__main__":
    rotator = SecretRotator(
        api_base=os.environ['KEYORIX_SERVER'].rstrip('/') + "/api/v1",
        token=os.environ['KEYORIX_TOKEN']
    )
    
    # Rotate database password
    new_password = generate_secure_password()
    rotator.rotate_with_notification(
        secret_id=123,
        secret_name="Production Database Password",
        new_value=new_password
    )
```

## Troubleshooting Workflows

### Workflow 11: Debugging Access Issues

**Scenario**: User reports they cannot access a shared secret.

**Diagnostic Steps**:
```bash
# 1. Verify the secret exists (metadata only, no value)
keyorix secret info --id 123

# 2. Check who has access, and how it was granted
keyorix secret access --id 123
keyorix share list --secret-id 123

# 3. Check the user's roles, and a specific permission
keyorix rbac list-user-roles --user john.doe@company.com
keyorix rbac check-permission --user john.doe@company.com --permission secrets.read

# 4. Review recent failed events for the secret and the user (user id 789)
keyorix audit search \
  --resource-type secret --resource-id 123 \
  --user-id 789 \
  --success false \
  --since 2026-01-01T00:00:00Z
keyorix secret audit --id 123

# 5. Check for account issues (suspended, locked, ...)
keyorix user get --email john.doe@company.com
```

### Workflow 12: Performance Investigation

**Scenario**: Slow response times when accessing shared secrets.

**Investigation Steps**:
```bash
# 1. Check the server you are talking to and its version
keyorix status
keyorix system info

# 2. Look at read activity per project over the last day
keyorix usage show --days 1

# 3. Look for bursts of sharing events
keyorix audit search --action secret.shared --limit 200 --since 2026-01-01T00:00:00Z
```

For latency and database-level metrics use the server's Prometheus metrics
endpoint; the CLI has no `monitor` or slow-query command.

---

*These workflows provide practical examples for common secret sharing scenarios. Adapt them to your specific environment and requirements.*

*Last updated: October 10, 2026*
*Version: 1.1.0*
