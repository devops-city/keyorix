# Secret Sharing API Documentation

## Overview

The Secret Sharing API allows users to securely share secrets with other users or groups while maintaining fine-grained permission control. This document provides comprehensive information about all sharing-related endpoints, request/response formats, and usage examples.

## Authentication

All sharing endpoints require authentication via Bearer token:

```
Authorization: Bearer <your-token>
```

## Base URL

```
https://your-keyorix-instance.com/api/v1
```

## Endpoints

### 1. Share a Secret

Share a secret with a user or group.

**Endpoint:** `POST /secrets/{id}/share`

**Parameters:**
- `id` (path, required): Secret ID to share

**Request Body:**
```json
{
  "recipient_id": 123,
  "is_group": false,
  "permission": "read"
}
```

**Request Fields:**
- `recipient_id` (integer, required): ID of the user or group to share with
- `is_group` (boolean, optional): Whether the recipient is a group (default: false)
- `permission` (string, required): Permission level ("read" or "write")

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Secret shared successfully",
  "data": {
    "id": 456,
    "secret_id": 123,
    "owner_id": 1,
    "recipient_id": 123,
    "is_group": false,
    "permission": "read",
    "created_at": "2025-07-22T10:30:00Z",
    "updated_at": "2025-07-22T10:30:00Z"
  }
}
```

**Error Responses:**
- `400 Bad Request`: Invalid request data
- `403 Forbidden`: Insufficient permissions. `message` says why when the share
  itself is refused: only the owner can share; the owner is not a member of the
  secret's project; or the recipient (user or group) is not a member of it.
- `404 Not Found`: Secret not found
- `409 Conflict`: Share already exists

A share applies only to members of the secret's project. For them, the
effective permission on the secret is the higher of their project role and the
share, with one limit: a `write` share elevates only three actions on that
secret — `PUT /api/v1/secrets/{id}` (value and metadata; not a change to
`expiration`, `clear_expiration` or `max_reads`), `PUT .../tags` and
`PATCH .../description`, and `POST .../rotate` (gRPC: `UpdateSecret`). Every
other `secrets.write` route (suspend, resume, move, rollback,
transfer-ownership, classification, auto-rotate, dependencies, version
comments, share, restore, `/shares/{id}`, project-level bulk routes) answers
`403` for a share-only caller, with `message` "A share on this secret only lets
you update its value and metadata or rotate it. ..." where the gate consulted
the share. A share never grants delete, `secrets.manage` or re-sharing.
Each elevated action is audited as `share_access_elevated` once it succeeds
(action, secret, share id, actor); refusals and failures write nothing. See the
[user guide](SECRET_SHARING_USER_GUIDE.md#how-a-share-combines-with-a-project-role).

**Example:**
```bash
curl -X POST "https://api.keyorix.com/api/v1/secrets/123/share" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": 456,
    "is_group": false,
    "permission": "read"
  }'
```

### 2. List Secret Shares

Get all shares for a specific secret.

**Endpoint:** `GET /secrets/{id}/shares`

**Parameters:**
- `id` (path, required): Secret ID

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "shares": [
      {
        "id": 456,
        "secret_id": 123,
        "owner_id": 1,
        "recipient_id": 789,
        "is_group": false,
        "permission": "read",
        "created_at": "2025-07-22T10:30:00Z",
        "updated_at": "2025-07-22T10:30:00Z"
      }
    ],
    "total": 1
  }
}
```

**Example:**
```bash
curl -X GET "https://api.keyorix.com/api/v1/secrets/123/shares" \
  -H "Authorization: Bearer your-token"
```

### 3. Update Share Permission

Update the permission level for an existing share.

**Endpoint:** `PUT /shares/{id}`

**Parameters:**
- `id` (path, required): Share ID

**Request Body:**
```json
{
  "permission": "write"
}
```

**Request Fields:**
- `permission` (string, required): New permission level ("read" or "write")

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Share permission updated successfully",
  "data": {
    "id": 456,
    "secret_id": 123,
    "owner_id": 1,
    "recipient_id": 789,
    "is_group": false,
    "permission": "write",
    "created_at": "2025-07-22T10:30:00Z",
    "updated_at": "2025-07-22T11:00:00Z"
  }
}
```

**Example:**
```bash
curl -X PUT "https://api.keyorix.com/api/v1/shares/456" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"permission": "write"}'
```

### 4. Revoke Share

Remove access to a shared secret.

**Endpoint:** `DELETE /shares/{id}`

**Parameters:**
- `id` (path, required): Share ID

**Response (204 No Content):**
No response body.

**Example:**
```bash
curl -X DELETE "https://api.keyorix.com/api/v1/shares/456" \
  -H "Authorization: Bearer your-token"
```

### 5. List User Shares

Get all shares created by the current user.

**Endpoint:** `GET /shares`

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `page_size` (integer, optional): Items per page (default: 20, max: 100)
- `secret_id` (integer, optional): Filter by secret ID
- `permission` (string, optional): Filter by permission level

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "shares": [
      {
        "id": 456,
        "secret_id": 123,
        "secret_name": "Database Password",
        "owner_id": 1,
        "recipient_id": 789,
        "recipient_name": "john.doe",
        "is_group": false,
        "permission": "read",
        "created_at": "2025-07-22T10:30:00Z",
        "updated_at": "2025-07-22T10:30:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 20,
    "total_pages": 1
  }
}
```

**Example:**
```bash
curl -X GET "https://api.keyorix.com/api/v1/shares?page=1&page_size=10" \
  -H "Authorization: Bearer your-token"
```

### 6. List Shared Secrets

Get all secrets shared with the current user.

**Endpoint:** `GET /shared-secrets`

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `page_size` (integer, optional): Items per page (default: 20, max: 100)
- `permission` (string, optional): Filter by permission level
- `owner_id` (integer, optional): Filter by owner ID

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "secrets": [
      {
        "id": 123,
        "name": "Database Password",
        "type": "password",
        "owner_id": 1,
        "owner_name": "admin",
        "permission": "read",
        "share_id": 456,
        "shared_at": "2025-07-22T10:30:00Z",
        "project_id": 1,
        "environment": "prod"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 20,
    "total_pages": 1
  }
}
```

**Example:**
```bash
curl -X GET "https://api.keyorix.com/api/v1/shared-secrets?permission=write" \
  -H "Authorization: Bearer your-token"
```

### 7. Remove Self from Share

Allow users to remove themselves from a shared secret.

**Endpoint:** `DELETE /secrets/{id}/self-share`

**Parameters:**
- `id` (path, required): Secret ID

**Response (204 No Content):**
No response body.

**Example:**
```bash
curl -X DELETE "https://api.keyorix.com/api/v1/secrets/123/self-share" \
  -H "Authorization: Bearer your-token"
```

### 8. Search Share Recipients in a Project

Find the users a secret in a project can be shared with. This is what the web
Share dialog uses. It needs only a role in the project that allows sharing, so a
**project-only admin** (`project_admin` of the project, no global role) can find
recipients. `GET /users` needs the global `users.read` permission.

**Endpoint:** `GET /projects/{id}/share-recipients`

**Who may call it:** a caller with `secrets.write` at the project's scope who is a
member of the project (the same rule that lets a secret's owner share it), or a
holder of the global `users.read` permission (global admins keep their access).
Machine identities may not.

**Parameters:**
- `id` (path, required): project ID (the secret's `project_id`)
- `q` (query, optional): case-insensitive prefix of the username, of the display
  name (or of any word in it), or of the email when emails are visible (see
  below). Empty lists every recipient.
- `page` (query, optional, default 1), `page_size` (query, optional, default 20, max 100)

**What it returns:** only **active members** of the project, meaning users who hold
a live role in it directly or through a group, and whose account is not deleted,
deactivated, suspended or deprovisioned. These are exactly the users a share can
go to. Results are ordered by username. Each row has `id`, `username` and
`display_name`. `email` is included, and matched by `q`, only if you hold
`users.read` at the project's scope, which every built-in project role does. A
caller who cannot already see members' emails never gets them here.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "recipients": [
      {"id": 2, "username": "alice", "display_name": "Alice", "email": "alice@example.com"}
    ],
    "total": 1,
    "page": 1,
    "page_size": 20
  }
}
```

**Refusal (403):** every refusal carries the same message, whether or not the
project exists:
```json
{
  "success": false,
  "error": "Forbidden",
  "message": "You can only search for share recipients in a project where you can share secrets: that needs a role in this project that allows sharing (for example project_admin). Ask a project admin to give you a role in the project.",
  "code": 403
}
```

**Example:**
```bash
curl "https://api.keyorix.com/api/v1/projects/7/share-recipients?q=al&page_size=8" \
  -H "Authorization: Bearer your-token"
```

## Group Sharing

### Share with Group

To share a secret with a group, set `is_group: true` in the share request:

```json
{
  "recipient_id": 10,
  "is_group": true,
  "permission": "read"
}
```

When sharing with a group:
- All group members automatically gain access
- Permission level applies to all group members
- Adding/removing users from the group automatically grants/revokes access

## Permission Levels

### Read Permission
- View secret metadata (name, type, tags, etc.)
- Access secret value
- View secret versions
- Cannot modify secret content
- Cannot share with others
- Cannot change permissions

### Write Permission
- All read permissions
- Update secret value
- Update secret metadata
- Create new versions
- Cannot delete the secret
- Cannot change sharing permissions (only owner can)

### Owner Permission
- All write permissions
- Delete the secret
- Share with others
- Modify sharing permissions
- Revoke shares
- Transfer ownership (if implemented)

## Error Handling

### Common Error Codes

**400 Bad Request**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request data",
    "details": {
      "field": "permission",
      "issue": "must be 'read' or 'write'"
    }
  }
}
```

**401 Unauthorized**
```json
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Authentication required"
  }
}
```

**403 Forbidden**
```json
{
  "success": false,
  "error": {
    "code": "INSUFFICIENT_PERMISSIONS",
    "message": "You don't have permission to perform this action"
  }
}
```

**404 Not Found**
```json
{
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Secret not found"
  }
}
```

**409 Conflict**
```json
{
  "success": false,
  "error": {
    "code": "SHARE_EXISTS",
    "message": "Secret is already shared with this user"
  }
}
```

## Rate Limiting

API endpoints are rate limited to prevent abuse:
- **Standard endpoints**: 100 requests per minute per user
- **List endpoints**: 50 requests per minute per user
- **Share creation**: 20 requests per minute per user

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642694400
```

## Pagination

List endpoints support pagination:

**Request:**
```
GET /api/v1/shares?page=2&page_size=10
```

**Response:**
```json
{
  "data": {
    "shares": [...],
    "total": 45,
    "page": 2,
    "page_size": 10,
    "total_pages": 5
  }
}
```

## Filtering and Sorting

### Supported Filters

**Shares endpoint (`/shares`):**
- `secret_id`: Filter by secret ID
- `permission`: Filter by permission level
- `recipient_type`: Filter by recipient type ("user" or "group")

**Shared secrets endpoint (`/shared-secrets`):**
- `permission`: Filter by permission level
- `owner_id`: Filter by owner ID
- `project_id`: Filter by project
- `type`: Filter by secret type

### Sorting

Add `sort` parameter with field name:
```
GET /api/v1/shares?sort=created_at&order=desc
```

Supported sort fields:
- `created_at`
- `updated_at`
- `secret_name`
- `recipient_name`
- `permission`

## Webhooks

Configure webhooks to receive notifications about sharing events:

### Supported Events
- `share.created`: New share created
- `share.updated`: Share permission updated
- `share.revoked`: Share access revoked
- `share.accessed`: Shared secret accessed

### Webhook Payload Example
```json
{
  "event": "share.created",
  "timestamp": "2025-07-22T10:30:00Z",
  "data": {
    "share_id": 456,
    "secret_id": 123,
    "secret_name": "Database Password",
    "owner_id": 1,
    "recipient_id": 789,
    "permission": "read",
    "is_group": false
  }
}
```

## SDK Examples

### JavaScript/Node.js
```javascript
const KeyorixClient = require('@keyorix/client');

const client = new KeyorixClient({
  baseURL: 'https://api.keyorix.com',
  token: 'your-api-token'
});

// Share a secret
const share = await client.shares.create({
  secretId: 123,
  recipientId: 456,
  permission: 'read'
});

// List shared secrets
const sharedSecrets = await client.sharedSecrets.list({
  page: 1,
  pageSize: 10
});

// Update share permission
await client.shares.update(share.id, {
  permission: 'write'
});

// Revoke share
await client.shares.delete(share.id);
```

### Python
```python
from keyorix import KeyorixClient

client = KeyorixClient(
    base_url='https://api.keyorix.com',
    token='your-api-token'
)

# Share a secret
share = client.shares.create(
    secret_id=123,
    recipient_id=456,
    permission='read'
)

# List shared secrets
shared_secrets = client.shared_secrets.list(
    page=1,
    page_size=10
)

# Update share permission
client.shares.update(share['id'], permission='write')

# Revoke share
client.shares.delete(share['id'])
```

### Go
```go
package main

import (
    "github.com/keyorix/go-client"
)

func main() {
    client := keyorix.NewClient(&keyorix.Config{
        BaseURL: "https://api.keyorix.com",
        Token:   "your-api-token",
    })

    // Share a secret
    share, err := client.Shares.Create(&keyorix.ShareRequest{
        SecretID:    123,
        RecipientID: 456,
        Permission:  "read",
    })

    // List shared secrets
    secrets, err := client.SharedSecrets.List(&keyorix.ListOptions{
        Page:     1,
        PageSize: 10,
    })

    // Update share permission
    err = client.Shares.Update(share.ID, &keyorix.UpdateShareRequest{
        Permission: "write",
    })

    // Revoke share
    err = client.Shares.Delete(share.ID)
}
```

## Best Practices

### Security
1. **Principle of Least Privilege**: Grant minimum required permissions
2. **Regular Audits**: Review and audit shares regularly
3. **Time-bound Access**: Consider implementing expiration dates
4. **Monitor Access**: Use audit logs to monitor secret access

### Performance
1. **Pagination**: Use appropriate page sizes for list operations
2. **Filtering**: Apply filters to reduce response sizes
3. **Caching**: Cache frequently accessed share information
4. **Batch Operations**: Group multiple operations when possible

### Error Handling
1. **Retry Logic**: Implement exponential backoff for retries
2. **Graceful Degradation**: Handle API failures gracefully
3. **Logging**: Log all API interactions for debugging
4. **Validation**: Validate input before making API calls

## Changelog

### Version 1.0.0 (2025-07-22)
- Initial release of Secret Sharing API
- Support for user and group sharing
- Permission management (read/write)
- Self-removal functionality
- Comprehensive audit logging