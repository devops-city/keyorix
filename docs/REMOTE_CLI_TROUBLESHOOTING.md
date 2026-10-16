# Remote CLI Troubleshooting Guide

This guide helps you diagnose and resolve common issues when using the Keyorix CLI with remote servers.

## Quick Diagnostics

Start with `keyorix doctor`. It is read-only and checks, in order: the configuration the CLI
would use, that the server answers, the TLS chain and its expiry, version compatibility, clock
skew against the server, that your token is accepted, and the audit chain's integrity. Each
problem comes with the next step:

```bash
keyorix doctor
keyorix doctor -o json    # for scripts; exits non-zero if any check failed
```

For a short look at just the server URL and login state:

```bash
# Also tests remote connectivity; exits non-zero on unhealthy/unreachable/unconfigured,
# so it's safe to script against
keyorix status

# Show a saved setting, e.g. the CA file for a private-CA server
keyorix config get ca_file
```

## Common Issues

### 1. Connection Refused

**Error:** `connection refused` or `no route to host`

**Causes:**
- Server is not running
- Incorrect server URL
- Network connectivity issues
- Firewall blocking connection

**Solutions:**

1. **Verify server URL:**
   ```bash
   keyorix config status
   # Check if the URL is correct
   ```

2. **Test basic connectivity:**
   ```bash
   curl -I https://your-server-url/api/v1/health
   ```

3. **Check network connectivity:**
   ```bash
   ping your-server-domain
   ```

4. **Update server URL if incorrect:**
   ```bash
   keyorix config set-remote --url https://correct-server-url.com
   ```

### 2. Authentication Failures

**Error:** `authentication failed` or `invalid API key`

**Causes:**
- Invalid or expired API key
- API key not set
- Wrong authentication method

**Solutions:**

1. **Check authentication status:**
   ```bash
   keyorix auth status
   ```

2. **Re-authenticate:**
   ```bash
   keyorix auth logout
   keyorix auth login
   ```

3. **Verify API key format:**
   - API keys should be alphanumeric strings
   - Check for extra spaces or characters

4. **Test with curl:**
   ```bash
   curl -H "Authorization: Bearer YOUR_API_KEY" \
        https://your-server-url/api/v1/health
   ```

### 3. Timeout Issues

**Error:** `context deadline exceeded` or `request timeout`

**Causes:**
- Slow network connection
- Server overloaded
- Timeout settings too low

**Solutions:**

1. **Increase timeout in configuration:**
   ```yaml
   # keyorix.yaml
   storage:
     remote:
       timeout_seconds: 60  # Increase from default 30
   ```

2. **Check response time:**
   ```bash
   keyorix status
   # Prints "Response Time: <duration>" for the last health check
   ```

3. **Check server performance:**
   ```bash
   curl -w "@curl-format.txt" -o /dev/null -s https://your-server-url/api/v1/health
   ```

### 4. Circuit Breaker Open

**Error:** `circuit breaker is open, service unavailable`

**Causes:**
- Multiple consecutive failures
- Server temporarily unavailable
- Network instability

**Solutions:**

1. **Wait for circuit breaker to reset (30 seconds):**
   ```bash
   sleep 30
   keyorix status
   ```

2. **Check server health:**
   ```bash
   curl https://your-server-url/api/v1/health
   ```

3. **Switch to local mode temporarily:**
   ```bash
   keyorix config use-local
   # Work locally until server is available
   ```

### 5. TLS/SSL Certificate Issues

**Error:** `certificate verify failed` or `x509: certificate signed by unknown authority`

**Causes:**
- Self-signed certificates
- Expired certificates
- Certificate authority not trusted

**Solutions:**

1. **For development/testing only - disable TLS verification:**
   ```yaml
   # keyorix.yaml
   storage:
     remote:
       tls_verify: false  # NOT recommended for production
   ```

2. **Add certificate to system trust store:**
   ```bash
   # On macOS
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem
   
   # On Linux
   sudo cp cert.pem /usr/local/share/ca-certificates/
   sudo update-ca-certificates
   ```

3. **Use proper certificates in production**

### 6. Configuration Issues

**Error:** `failed to load configuration` or `invalid configuration`

**Causes:**
- Malformed YAML
- Missing required fields
- File permissions

**Solutions:**

1. **Validate YAML syntax:**
   ```bash
   # Use online YAML validator or
   python -c "import yaml; yaml.safe_load(open('keyorix.yaml'))"
   ```

2. **Check file permissions:**
   ```bash
   ls -la keyorix.yaml
   chmod 600 keyorix.yaml
   ```

3. **Reset to default configuration:**
   ```bash
   mv keyorix.yaml keyorix.yaml.backup
   keyorix config use-local
   ```

### 7. Environment Variable Issues

**Error:** `api_key is required` when using `${VARIABLE}` syntax

**Causes:**
- Environment variable not set
- Incorrect variable name
- Shell not expanding variables

**Solutions:**

1. **Check environment variable:**
   ```bash
   echo $KEYORIX_API_KEY
   ```

2. **Set environment variable:**
   ```bash
   export KEYORIX_API_KEY="your-api-key"
   ```

3. **Verify variable expansion:**
   ```bash
   keyorix config status
   # Should show the actual key, not ${VARIABLE}
   ```

## Performance Issues

### Slow Response Times

**Symptoms:**
- Commands take a long time to complete
- Frequent timeouts

**Diagnostics:**

1. **Measure response time:**
   ```bash
   keyorix status
   ```

2. **Check network latency:**
   ```bash
   ping your-server-domain
   ```

**Solutions:**

1. **Enable caching (automatic for GET requests)**

2. **Use connection pooling (enabled by default)**

3. **Increase timeout if needed:**
   ```yaml
   storage:
     remote:
       timeout_seconds: 60
   ```

### High Memory Usage

**Symptoms:**
- CLI consuming excessive memory
- System slowdown

**Solutions:**

1. **Clear cache by restarting CLI**

2. **Reduce cache size (if configurable in future versions)**

## Network Diagnostics

### Test Network Connectivity

```bash
# Basic connectivity
ping your-server-domain

# HTTP connectivity
curl -I https://your-server-url

# DNS resolution
nslookup your-server-domain

# Port connectivity
telnet your-server-domain 443
```

### Test API Endpoints

```bash
# Health check
curl https://your-server-url/api/v1/health

# Authentication test
curl -H "Authorization: Bearer YOUR_API_KEY" \
     https://your-server-url/api/v1/secrets

# Full request test
curl -X POST \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"name":"test","type":"password","value":"test"}' \
     https://your-server-url/api/v1/secrets
```

## Logging and Debugging

### Enable Debug Mode

```bash
# Set debug environment variable
export KEYORIX_DEBUG=true

# Run commands with verbose output
keyorix status
```

### Check System Logs

```bash
# On macOS
tail -f /var/log/system.log | grep keyorix

# On Linux
journalctl -f | grep keyorix
```

### Network Traffic Analysis

```bash
# Monitor network traffic (requires root)
sudo tcpdump -i any host your-server-domain

# Or use Wireshark for GUI analysis
```

## Recovery Procedures

### Complete Reset

If all else fails, reset the CLI to default state:

```bash
# Backup current configuration
cp keyorix.yaml keyorix.yaml.backup

# Remove configuration
rm keyorix.yaml

# Reset to local mode
keyorix config use-local

# Verify operation
keyorix status
```

### Emergency Local Mode

If remote server is completely unavailable:

```bash
# Switch to local mode immediately
keyorix config use-local

# Verify local operation
keyorix secret list

# Continue working locally until remote is restored
```

### Restore from Backup

```bash
# Restore configuration
cp keyorix.yaml.backup keyorix.yaml

# Test restored configuration
keyorix config status
keyorix status
```

## Getting Help

### Collect Diagnostic Information

Before seeking help, collect this information:

```bash
# System information
uname -a
keyorix --version

# Configuration
keyorix config status

# Connection test
keyorix status

# Error messages (run failing command with debug)
KEYORIX_DEBUG=true keyorix your-failing-command
```

### Contact Support

Include the diagnostic information above when contacting support:

- GitHub Issues: [repository-url]/issues
- Documentation: [docs-url]
- Community: [community-url]

## Prevention

### Best Practices

1. **Monitor server health regularly**
2. **Use proper TLS certificates**
3. **Rotate API keys periodically**
4. **Keep configuration files secure**
5. **Test connectivity before important operations**
6. **Have local backup strategy**

### Monitoring

Set up monitoring for:
- Server availability
- API response times
- Certificate expiration
- API key usage

### Backup Strategy

1. **Regular configuration backups**
2. **Local database backups**
3. **API key secure storage**
4. **Disaster recovery plan**