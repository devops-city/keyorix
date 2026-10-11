# Keyorix System Setup Guide

This guide covers the complete setup and configuration of the Keyorix secrets management system.

These are all **host-side** operations -- they run as `keyorix-server admin <cmd>`, not the CLI
(`keyorix`). The CLI is REST-only and never touches the config file, keys, or database directly
(ADR-108). To bootstrap the first admin account and default workspace over the network once the
server is running, see [`QUICK_START.md`](QUICK_START.md)'s `keyorix system init --server` step.

## 🚀 Quick Start

### 1. Initialize the System
```bash
# Initialize with default settings (config, encryption *directories*, database, logging)
keyorix-server admin init

# Generate the actual encryption key material -- `admin init` only creates the
# key directories, it does not generate keys. The server refuses to start
# without this step.
keyorix-server admin encryption init
```

### 2. Validate the Setup
```bash
# Check system configuration
keyorix-server admin validate

# Audit file permissions
keyorix-server admin audit

# Check encryption status
keyorix-server admin encryption status
```

### 3. Start Using Keyorix
Your system is now ready for secure secret management!

## 📋 Complete Setup Process

### Step 1: System Initialization

The `keyorix-server admin init` command creates all necessary files and directories:

```
📁 Project Structure After Init:
├── keyorix.yaml          # Main configuration (0600)
├── keyorix_template.yaml # Template file (0644)
├── keys/
│   ├── kek.salt          # KEK derivation salt (0600)
│   └── dek.key           # Wrapped Data Encryption Key (0600)
├── keyorix.db           # SQLite database (0600)
├── keyorix.log          # Application logs (0644)
└── certs/                # TLS certificates (if enabled)
    ├── server.crt        # Certificate (0600)
    └── server.key        # Private key (0600)
```

### Step 2: Configuration Overview

The `keyorix.yaml` configuration includes:

```yaml
# Server settings
server:
  http:
    enabled: true
    port: "8080"
  grpc:
    enabled: true
    port: "9090"

# Storage and encryption
storage:
  type: sqlite  # options: sqlite, postgres
  database:
    # SQLite (default — zero infrastructure required)
    path: "keyorix.db"
    # PostgreSQL (recommended for production):
    # type: postgres
    # dsn: "host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require"
    # Or use KEYORIX_DB_PASSWORD env var for the password field.
  encryption:
    enabled: true
    dek_path: "keys/dek.key"
    salt_path: "keys/kek.salt"

# Security policies
security:
  enable_file_permission_check: true
  auto_fix_file_permissions: false
  insecure_allow_unsafe_file_permissions: false   # deprecated alias: allow_unsafe_file_permissions
```

### Step 3: Security Validation

The system performs comprehensive security checks:

- ✅ **File Permissions**: All critical files have 0600 permissions
- ✅ **File Ownership**: Files are owned by the current user
- ✅ **Encryption Keys**: KEK/DEK files exist and are valid (32 bytes)
- ✅ **Database Access**: Database file is accessible
- ✅ **Configuration**: Config file is valid and complete

## 🔧 Advanced Configuration

### Selective Component Initialization

Initialize only specific components:

```bash
# Encryption only
keyorix-server admin init --encryption

# Database only
keyorix-server admin init --database

# Multiple components
keyorix-server admin init --encryption --database --logging
```

### Custom Configuration Paths

```bash
# Use custom config file location
keyorix-server admin init --config /path/to/my-config.yaml

# Validate custom config
keyorix-server admin validate --config /path/to/my-config.yaml
```

### Overwrite Existing Config (Dangerous)

```bash
# Overwrite an existing config file
keyorix-server admin init --overwrite-existing

# ⚠️ WARNING: This will overwrite the existing configuration file!
```

## 🔐 Encryption Management

### Initialize Encryption Separately
```bash
# Initialize encryption keys
keyorix-server admin encryption init

# Check encryption status
keyorix-server admin encryption status

# Rotate encryption keys
keyorix-server admin encryption rotate --confirm

# Validate encryption setup
keyorix-server admin encryption validate

# Fix key file permissions
keyorix-server admin encryption fix-perms
```

### Encryption Features
- **AES-256-GCM**: Industry-standard authenticated encryption
- **Key Management**: Separate KEK and DEK with rotation support
- **Chunked Encryption**: Support for large secrets
- **Key Versioning**: Track key versions for rotation
- **Secure Storage**: Keys stored with 0600 permissions

## 🛡️ Security Best Practices

### 1. File Permissions
```bash
# Regular permission audits
keyorix-server admin audit

# Automatic permission fixing (if needed)
keyorix-server admin validate --fix
```

### 2. Key Management
```bash
# Regular key rotation
keyorix-server admin encryption rotate --confirm

# Backup key material before rotation (the KEK is passphrase-derived, never on disk)
cp keys/kek.salt keys/kek.salt.backup.$(date +%s)
cp keys/dek.key keys/dek.key.backup.$(date +%s)
```

### 3. System Validation
```bash
# Always validate before starting
keyorix-server admin validate

# Check encryption status
keyorix-server admin encryption status
```

### 4. Production Deployment
- Enable file permission checks
- Use TLS for all network communications
- Store keys in secure, backed-up locations
- Monitor file permissions regularly
- Use strong authentication mechanisms

## 🔍 Troubleshooting

### Common Issues and Solutions

#### 1. Permission Denied Errors
```bash
# Check current permissions
keyorix-server admin audit

# Fix permissions automatically
keyorix-server admin validate --fix

# Manual permission fix
chmod 0600 keyorix.yaml keys/*.key keyorix.db
```

#### 2. Missing Configuration
```bash
# Recreate configuration
keyorix-server admin init

# Overwrite a corrupted config
keyorix-server admin init --overwrite-existing
```

#### 3. Encryption Key Issues
```bash
# Regenerate encryption keys
keyorix-server admin encryption init

# Check key status
keyorix-server admin encryption status

# Validate key files
keyorix-server admin encryption validate
```

#### 4. Database Issues
```bash
# Reinitialize database
keyorix-server admin init --database

# Check database permissions
ls -la keyorix.db
```

### Debug Mode
```bash
# Enable debug logging
export KEYORIX_DEBUG=true
keyorix-server admin init
```

## 📊 System Status Commands

### Comprehensive Status Check
```bash
# System validation
keyorix-server admin validate

# Encryption status
keyorix-server admin encryption status

# File permission audit
keyorix-server admin audit
```

### Expected Output (Healthy System)
```
🔍 Validating Keyorix System
============================
🔍 Startup Validation Results
============================
Configuration: ✅
Permissions:   ✅
Encryption:    ✅
Database:      ✅

🎉 All validations passed!
```

## 🚀 Next Steps

After successful system initialization:

1. **Start the Server**: Configure and start HTTP/gRPC servers
2. **Bootstrap the Admin Account**: `keyorix system init --server <url>` from the CLI (see
   [`QUICK_START.md`](QUICK_START.md))
3. **Create Secrets**: Begin storing and managing secrets
4. **Set Up Users**: Configure authentication and authorization
5. **Monitor System**: Regular validation and auditing
6. **Backup Strategy**: Implement key and database backup procedures

## 📚 Additional Resources

- **Encryption Guide**: `internal/encryption/README.md`
- **Configuration Reference**: `keyorix_template.yaml`
- **Migrating from the old CLI**: [`docs/cli-migration.md`](docs/cli-migration.md)

## 🆘 Support

If you encounter issues:

1. Run `keyorix-server admin validate` for detailed diagnostics
2. Check file permissions with `keyorix-server admin audit`
3. Verify encryption setup with `keyorix-server admin encryption status`
4. Review configuration in `keyorix.yaml`
5. Check logs in `keyorix.log`

The system provides comprehensive error messages and recovery suggestions for most common issues.
