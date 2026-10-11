# Secret Sharing User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Sharing Secrets](#sharing-secrets)
4. [Managing Permissions](#managing-permissions)
5. [Group Sharing](#group-sharing)
6. [Accessing Shared Secrets](#accessing-shared-secrets)
7. [Self-Management](#self-management)
8. [Security Best Practices](#security-best-practices)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

## Introduction

Secret sharing in Keyorix allows you to securely collaborate by giving other users controlled access to your secrets. This feature enables teams to work together while maintaining security and auditability.

### Key Features
- **Secure Sharing**: End-to-end encryption maintained during sharing
- **Permission Control**: Grant read-only or read-write access
- **Group Support**: Share with entire teams or groups
- **Audit Trail**: Complete logging of all sharing activities
- **Self-Management**: Users can remove themselves from shares
- **Real-time Updates**: Changes are immediately reflected across all interfaces

### Who Can Share Secrets?
- **Secret Owners**: Can share their secrets with others
- **Users with Write Permission**: Can modify shared secret content (but not sharing settings)
- **Users with Read Permission**: Can view shared secrets but cannot modify them

### Shares and project roles: how they combine

A user's access to a secret is the **union** of every path that grants it: being the
owner, a direct share, a group share, a per-secret ACL, and a role on the secret's
project. A share *adds* a path; **revoking it removes only that path.**

The recipient of a user share must already be a member of the secret's project (hold
a role scoped to it). If that role already grants read (every built-in project role,
including `project_viewer`, does), the recipient keeps reading the secret after the
share is revoked — the share was not what gave them access. To end their access,
also remove the role (`keyorix rbac remove-role`). A `write` share is not a reliable
way to give a read-only role edit rights (see #2941). `keyorix secret access` lists
owner and share access only, not role-derived access.

## Getting Started

### Prerequisites
- Active Keyorix account
- Appropriate permissions to access secrets
- Knowledge of usernames or group names you want to share with

### Accessing the Sharing Interface

#### Web Interface
1. Navigate to your secrets list
2. Click on the secret you want to share
3. Look for the "Share" button or tab
4. Shared secrets will show a sharing indicator (👥 icon)

#### CLI Interface
```bash
# List available sharing commands
keyorix share --help

# View your current shares
keyorix shares list
```

#### API Interface
See the [API Documentation](SECRET_SHARING_API.md) for programmatic access.

## Sharing Secrets

### Basic Secret Sharing

#### Via Web Interface
1. **Select Secret**: Navigate to the secret you want to share
2. **Click Share**: Click the "Share" button
3. **Choose Recipient**: Enter the username or select from suggestions
4. **Set Permission**: Choose "Read" or "Write" permission
5. **Confirm**: Click "Share Secret" to complete

#### Via CLI
```bash
# Share a secret with read permission
keyorix secret share --id 123 --recipient john.doe --permission read

# Share a secret with write permission
keyorix secret share --id 123 --recipient jane.smith --permission write
```

#### Via API
```bash
curl -X POST "https://api.keyorix.com/api/v1/secrets/123/share" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": 456,
    "permission": "read"
  }'
```

### Understanding Permissions

#### Read Permission
**What recipients can do:**
- View secret name, type, and metadata
- Access the secret value
- View secret version history
- See when the secret was last updated

**What recipients cannot do:**
- Modify the secret value
- Update metadata or tags
- Share the secret with others
- Delete the secret

#### Write Permission
**What recipients can do:**
- Everything from read permission
- Update the secret value
- Modify metadata and tags
- Create new versions of the secret

**What recipients cannot do:**
- Delete the secret
- Change sharing permissions
- Share with others (only owners can share)

### Sharing Multiple Secrets

#### Bulk Sharing (Web Interface)
1. Select multiple secrets using checkboxes
2. Click "Bulk Actions" → "Share Selected"
3. Choose recipients and permissions
4. Confirm the bulk share operation

#### Batch Sharing (CLI)
```bash
# Share multiple secrets with the same user
for secret_id in 123 456 789; do
  keyorix secret share --id $secret_id --recipient john.doe --permission read
done
```

## Managing Permissions

### Viewing Current Shares

#### List Shares for a Secret
```bash
# CLI
keyorix secret shares --id 123

# API
curl -X GET "https://api.keyorix.com/api/v1/secrets/123/shares" \
  -H "Authorization: Bearer your-token"
```

#### List All Your Shares
```bash
# CLI
keyorix shares list

# API
curl -X GET "https://api.keyorix.com/api/v1/shares" \
  -H "Authorization: Bearer your-token"
```

### Updating Permissions

#### Upgrade Permission (Read → Write)
```bash
# CLI
keyorix shares update --id 456 --permission write

# API
curl -X PUT "https://api.keyorix.com/api/v1/shares/456" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"permission": "write"}'
```

#### Downgrade Permission (Write → Read)
```bash
# CLI
keyorix shares update --id 456 --permission read
```

### Revoking Access

#### Remove Specific User Access
```bash
# CLI
keyorix shares revoke --id 456

# API
curl -X DELETE "https://api.keyorix.com/api/v1/shares/456" \
  -H "Authorization: Bearer your-token"
```

#### Remove All Shares for a Secret
```bash
# Get all shares for the secret
keyorix secret shares --id 123 --format json | \
  jq -r '.shares[].id' | \
  xargs -I {} keyorix shares revoke --id {}
```

## Group Sharing

### Understanding Groups
Groups allow you to share secrets with multiple users at once. When you share with a group:
- All current group members gain access immediately
- New group members automatically gain access
- Removed group members automatically lose access
- Permission level applies to all group members

### Sharing with Groups

#### Via Web Interface
1. Click "Share" on your secret
2. Select "Group" as recipient type
3. Choose the group from the dropdown
4. Set the permission level
5. Confirm the share

#### Via CLI
```bash
# Share with a group
keyorix secret share --id 123 --group developers --permission read
```

#### Via API
```bash
curl -X POST "https://api.keyorix.com/api/v1/secrets/123/share" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": 10,
    "is_group": true,
    "permission": "read"
  }'
```

### Managing Group Shares

#### List Group Shares
```bash
# CLI - filter for group shares only
keyorix shares list --groups-only

# API - filter response for group shares
curl -X GET "https://api.keyorix.com/api/v1/shares?recipient_type=group" \
  -H "Authorization: Bearer your-token"
```

#### Update Group Permissions
```bash
# Update permission for entire group
keyorix shares update --id 456 --permission write
```

### Group Membership Changes

When group membership changes:
- **User Added**: Automatically gains access to all secrets shared with the group
- **User Removed**: Automatically loses access to all group-shared secrets
- **Group Deleted**: All shares with that group are automatically revoked

## Accessing Shared Secrets

### Finding Shared Secrets

#### Web Interface
- Shared secrets appear in your main secrets list
- Look for the sharing indicator (👥 icon)
- Use the "Shared with me" filter to see only shared secrets
- Owner information is displayed for each shared secret

#### CLI Interface
```bash
# List all secrets shared with you
keyorix shared-secrets list

# Filter by permission level
keyorix shared-secrets list --permission write

# Filter by owner
keyorix shared-secrets list --owner admin
```

### Working with Shared Secrets

#### Viewing Shared Secret Details
```bash
# Get secret information
keyorix secret get --id 123

# View secret value (if you have read permission)
keyorix secret value --id 123

# View secret versions
keyorix secret versions --id 123
```

#### Modifying Shared Secrets (Write Permission Required)
```bash
# Update secret value
keyorix secret update --id 123 --value "new-secret-value"

# Update metadata
keyorix secret update --id 123 --metadata key=value

# Add tags
keyorix secret update --id 123 --tags production,database
```

### Understanding Sharing Context

When viewing a shared secret, you'll see:
- **Owner Information**: Who owns the secret
- **Your Permission Level**: What you can do with the secret
- **Share Date**: When it was shared with you
- **Last Modified**: When the secret was last updated
- **Version History**: All versions (if you have read access)

## Self-Management

### Removing Yourself from Shares

Sometimes you may want to remove yourself from a shared secret:

#### Via Web Interface
1. Navigate to the shared secret
2. Click "Remove Access" or "Leave Share"
3. Confirm the action

#### Via CLI
```bash
# Remove yourself from a specific secret
keyorix secret self-remove --id 123
```

#### Via API
```bash
curl -X DELETE "https://api.keyorix.com/api/v1/secrets/123/self-share" \
  -H "Authorization: Bearer your-token"
```

### Managing Your Shared Secrets View

#### Organizing Shared Secrets
- **Filter by Owner**: See secrets from specific users
- **Filter by Permission**: Show only read or write access secrets
- **Sort by Date**: Order by when secrets were shared with you
- **Search**: Find specific shared secrets by name or content

#### Notifications
Configure notifications for:
- New secrets shared with you
- Permission changes on shared secrets
- Secrets being unshared from you
- Updates to shared secrets you're watching

## Security Best Practices

### For Secret Owners

#### 1. Principle of Least Privilege
- Grant the minimum permission level required
- Regularly review and audit who has access
- Remove access when no longer needed

#### 2. Regular Access Reviews
```bash
# Monthly review of all your shares
keyorix shares list --format table

# Check specific high-value secrets
keyorix secret shares --id 123
```

#### 3. Monitor Access Patterns
- Review audit logs regularly
- Watch for unusual access patterns
- Set up alerts for sensitive secrets

#### 4. Use Groups Wisely
- Share with groups rather than individual users when possible
- Keep group membership up to date
- Use descriptive group names

### For Recipients

#### 1. Respect Access Levels
- Don't attempt to exceed your permission level
- Report any access issues to the secret owner
- Use shared secrets responsibly

#### 2. Secure Your Account
- Use strong authentication
- Keep your credentials secure
- Report suspicious activity immediately

#### 3. Clean Up Access
- Remove yourself from shares you no longer need
- Notify owners if you no longer require access
- Keep your profile information current

### General Security

#### 1. Audit Trail Monitoring
```bash
# View recent sharing activities
keyorix audit logs --type sharing --recent

# Check access to specific secrets
keyorix audit logs --secret-id 123
```

#### 2. Encryption Verification
- All shared secrets maintain end-to-end encryption
- Keys are never shared in plaintext
- Revoked users cannot decrypt previously shared secrets

#### 3. Network Security
- Always use HTTPS for web access
- Use secure networks when accessing shared secrets
- Consider VPN for sensitive operations

## Troubleshooting

### Common Issues

#### "Permission Denied" Errors
**Problem**: Cannot access a shared secret
**Solutions**:
1. Verify you have the correct permission level
2. Check if the share has been revoked
3. Confirm the secret still exists
4. Contact the secret owner

#### "Share Already Exists" Errors
**Problem**: Cannot create a share that already exists
**Solutions**:
1. Check existing shares for the secret
2. Update the existing share instead of creating new one
3. Verify recipient information is correct

#### "User Not Found" Errors
**Problem**: Cannot share with specified user
**Solutions**:
1. Verify the username is correct
2. Check if the user account is active
3. Ensure the user has access to the system
4. Try using user ID instead of username

### Performance Issues

#### Slow Loading of Shared Secrets
**Solutions**:
1. Use pagination for large lists
2. Apply filters to reduce result sets
3. Check network connectivity
4. Clear browser cache (web interface)

#### API Rate Limiting
**Problem**: Too many requests error
**Solutions**:
1. Implement exponential backoff
2. Reduce request frequency
3. Use batch operations when available
4. Contact support for rate limit increases

### Getting Help

#### Self-Service Resources
- Check the [API Documentation](SECRET_SHARING_API.md)
- Review [Security Considerations](security/architecture.md)
- Browse [Workflow Examples](SECRET_SHARING_WORKFLOWS.md)

#### Support Channels
- **Documentation**: Check this guide and API docs
- **Community Forum**: Ask questions and share experiences
- **Support Tickets**: For technical issues and bugs
- **Emergency Contact**: For security incidents

## FAQ

### General Questions

**Q: Can I share a secret with someone who doesn't have a Keyorix account?**
A: No, all recipients must have active Keyorix accounts to receive shared secrets.

**Q: What happens if I delete a secret that's shared with others?**
A: The secret is deleted for everyone, including all users it was shared with. They will lose access immediately.

**Q: Can recipients share secrets with others?**
A: No, only the original owner can share secrets with additional users or modify sharing permissions.

**Q: Is there a limit to how many people I can share a secret with?**
A: There are reasonable limits to prevent abuse. Contact support if you need to share with a large number of users.

### Permission Questions

**Q: What's the difference between read and write permissions?**
A: Read permission allows viewing the secret and its metadata. Write permission additionally allows modifying the secret value and metadata.

**Q: Can I give someone permission to share my secrets?**
A: No, sharing permissions cannot be delegated. Only the original owner can manage sharing.

**Q: How do I know what permission level I have for a shared secret?**
A: Your permission level is displayed in the secret details and in the shared secrets list.

### Security Questions

**Q: Are shared secrets encrypted?**
A: Yes, all secrets maintain end-to-end encryption even when shared. Each recipient gets their own encrypted copy.

**Q: Can Keyorix staff see my shared secrets?**
A: No, Keyorix uses end-to-end encryption. Staff cannot see secret contents, only metadata like sharing relationships.

**Q: What happens if someone's account is compromised?**
A: Immediately revoke all shares with that user and report the incident. Change any secrets they had access to.

**Q: Can I see who has accessed my shared secrets?**
A: Yes, audit logs show all access attempts and successful accesses to your shared secrets.

### Technical Questions

**Q: Can I automate sharing through the API?**
A: Yes, the full sharing functionality is available through the REST API. See the API documentation for details.

**Q: Do shared secrets count against my storage quota?**
A: Secrets count against the owner's quota, not the recipients' quotas.

**Q: Can I share secrets across different environments?**
A: Yes, sharing works across all environments within the same Keyorix instance.

**Q: What happens during system maintenance?**
A: Shared secrets remain accessible during maintenance. Sharing operations may be temporarily unavailable during updates.

---

*Last updated: July 22, 2025*
*Version: 1.0.0*