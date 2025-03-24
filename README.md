# Setting up HumHub on NixOS - Secure Installation Guide

This guide will walk you through setting up HumHub, an open-source social networking platform, on NixOS with enhanced security measures. This configuration follows security best practices and ensures that all packages are downloaded from the official source.

## Prerequisites

- A NixOS system
- Root access or sudo privileges
- Basic understanding of NixOS configuration

## Step 1: Set Up Secure Secrets Management

1. First, set up agenix for secure secret management:

```bash
# Install agenix
nix-shell -p nixpkgs.agenix

# Generate an SSH key for encryption if you don't have one
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_agenix -C "agenix key"

# Create a secrets directory
mkdir -p /etc/nixos/secrets
```

2. Create the secret file for MySQL password:

```bash
# Generate a strong random password
openssl rand -base64 32 > /tmp/mysql-password

# Encrypt it with agenix (replace with your public key)
agenix -e /etc/nixos/secrets/humhub-mysql-password.age -i ~/.ssh/id_ed25519_agenix
# Enter the password when prompted or paste from /tmp/mysql-password

# Clean up
shred -u /tmp/mysql-password
```

3. Create a keys.nix file to specify which keys can decrypt the secrets:

```nix
# /etc/nixos/secrets/keys.nix
let
  admin = "ssh-ed25519 AAAAC3NzaC1..."; # Replace with your public key
  system = "ssh-ed25519 AAAAC3NzaC1..."; # Replace with your server's key
in
{
  "humhub-mysql-password.age" = [ admin system ];
  "humhub-db-passphrase.age" = [ admin system ];
}
```

## Step 2: Apply the NixOS Configuration

1. Copy the provided Nix configuration to your `/etc/nixos/humhub.nix` file and import it in your main configuration:

```nix
# In your main configuration.nix
{ config, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
    ./humhub.nix  # Import the HumHub configuration
    # Add agenix module
    "${builtins.fetchTarball "https://github.com/ryantm/agenix/archive/main.tar.gz"}/modules/age.nix"
  ];
  
  # Point to your keys file
  age.identityPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];
  
  # Rest of your system configuration
}
```

2. Before applying, make these important customizations:
   - Change `humhub.example.com` to your actual domain name
   - Ensure your secrets are properly configured
   - Adjust PHP and MySQL settings based on your server resources
   - Review the security settings and add any additional measures specific to your environment

3. Create the backup passphrases:

```bash
# Generate backup passphrases
openssl rand -base64 32 | agenix -e /etc/nixos/secrets/humhub-passphrase.age
openssl rand -base64 32 | agenix -e /etc/nixos/secrets/humhub-db-passphrase.age

# Create directories for the passphrase files
sudo mkdir -p /etc/borgbackup
```

4. Apply the configuration:

```bash
sudo nixos-rebuild switch
```

## Step 2: Complete the Web-Based Setup

1. Once the configuration is applied, HumHub files will be downloaded to `/var/www/humhub`.

2. Navigate to your domain in a web browser (e.g., `https://humhub.example.com`).

3. You'll be presented with the HumHub web installer. Follow these steps:

   a. **Welcome**: Click "Next" to begin the installation.
   
   b. **System Check**: The installer will verify that your system meets all requirements. If any issues are found, resolve them before continuing.
   
   c. **Database Configuration**:
      - Database Host: `localhost`
      - Database Name: `humhub`
      - Database Username: `humhub`
      - Database Password: The password you set in the configuration (`humhub_password` by default)
   
   d. **Create Admin Account**: Set up your administrator account.
   
   e. **Sample Data**: Choose whether to install sample data.
   
   f. **Settings**: Configure basic site settings like name and description.

4. After completing the web setup, you'll have a fully functional HumHub installation.

## Step 3: Post-Installation Configuration

### Setting Up Cron Jobs

HumHub requires regular cron jobs for proper functionality. Add the following to your NixOS configuration:

```nix
services.cron = {
  enable = true;
  systemCronJobs = [
    "* * * * * nginx cd /var/www/humhub && php yii queue/run >/dev/null 2>&1"
    "* * * * * nginx cd /var/www/humhub && php yii cron/run >/dev/null 2>&1"
  ];
};
```

### Mail Configuration

To enable email functionality, configure the mail settings in the HumHub admin panel or directly in the configuration file at `/var/www/humhub/protected/config/common.php`.

### Performance Tuning

For better performance on production systems:

1. Enable Redis for caching by adding to your NixOS configuration:

```nix
services.redis.enable = true;

services.phpfpm.pools.humhub.phpOptions = ''
  extension = ${pkgs.phpExtensions.redis}/lib/php/extensions/redis.so
'';
```

2. Then configure Redis in HumHub's configuration:

```php
// In /var/www/humhub/protected/config/common.php
'components' => [
    'cache' => [
        'class' => 'yii\redis\Cache',
        'redis' => [
            'hostname' => 'localhost',
            'port' => 6379,
            'database' => 0,
        ]
    ],
]
```

## Additional Security Hardening

### Setting Up a Web Application Firewall (WAF)

For enhanced security, add ModSecurity to your Nginx configuration:

```nix
services.nginx = {
  # ... existing config ...
  
  additionalModules = with pkgs.nginxModules; [ modsecurity ];
  
  virtualHosts."humhub.example.com" = {
    # ... existing config ...
    
    extraConfig = ''
      # ModSecurity configuration
      modsecurity on;
      modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
    '';
  };
};

# In system.activationScripts:
system.activationScripts.setupModSecurity = ''
  mkdir -p /etc/nginx/modsecurity
  cat > /etc/nginx/modsecurity/main.conf << EOF
  Include /etc/nginx/modsecurity/modsecurity.conf
  Include /etc/nginx/modsecurity/crs-setup.conf
  Include /etc/nginx/modsecurity/rules/*.conf
  EOF
  
  # Basic ModSecurity configuration
  cat > /etc/nginx/modsecurity/modsecurity.conf << EOF
  SecRuleEngine On
  SecRequestBodyAccess On
  SecResponseBodyAccess On
  SecResponseBodyMimeType text/plain text/html text/xml application/json
  SecResponseBodyLimit 1024
  SecDebugLog /var/log/nginx/modsecurity_debug.log
  SecDebugLogLevel 0
  SecAuditEngine RelevantOnly
  SecAuditLog /var/log/nginx/modsecurity_audit.log
  SecAuditLogParts ABIJDEFHZ
  EOF
  
  # Download OWASP CRS rules
  if [ ! -d /etc/nginx/modsecurity/rules ]; then
    mkdir -p /etc/nginx/modsecurity/rules
    ${pkgs.curl}/bin/curl -sSL https://github.com/coreruleset/coreruleset/archive/v3.3.2.tar.gz | ${pkgs.gnutar}/bin/tar xz -C /tmp/
    cp -R /tmp/coreruleset-3.3.2/rules/* /etc/nginx/modsecurity/rules/
    cp /tmp/coreruleset-3.3.2/crs-setup.conf.example /etc/nginx/modsecurity/crs-setup.conf
    rm -rf /tmp/coreruleset-3.3.2
  fi
'';
```

### Enable Process and Network Monitoring

Add intrusion detection with OSSEC:

```nix
services.ossec = {
  enable = true;
  rootcheck.enable = true;
  activeResponse.enable = true;
  emailNotifications.enable = true;
  emailNotifications.email = "admin@example.com"; # Change to your email
};
```

## Secure Maintenance

### Secure Updates

To update HumHub safely:

1. Back up your database and files using borgbackup (already set up):
```bash
# Manual backup before update
sudo systemctl start borgbackup-job-humhub.service
sudo systemctl start borgbackup-job-humhub-db.service
```

2. Download and verify the latest version from the official source:
```bash
# Create temporary update directory with restricted permissions
sudo mkdir -p /tmp/humhub-update
sudo chmod 700 /tmp/humhub-update
cd /tmp/humhub-update

# Download with secure TLS settings
sudo wget --https-only --secure-protocol=TLSv1_2 \
  https://download.humhub.com/downloads/install/humhub-latest.zip

# Download checksum if available
sudo wget --https-only --secure-protocol=TLSv1_2 \
  https://download.humhub.com/downloads/install/humhub-latest.zip.sha256
  
# Verify checksum if available
if [ -f humhub-latest.zip.sha256 ]; then
  echo "Verifying checksum..."
  sha256sum -c humhub-latest.zip.sha256
  if [ $? -ne 0 ]; then
    echo "Checksum verification failed! Aborting update."
    exit 1
  fi
fi

# Unzip with restricted permissions
sudo unzip -q humhub-latest.zip
cd humhub-*
```

3. Apply the update with proper file permissions:
```bash
# Stop services first
sudo systemctl stop phpfpm-humhub

# Use rsync to preserve permissions and ownership
su

### Troubleshooting

- **Permission Issues**: If you encounter permission problems, ensure the correct ownership:
  ```bash
  sudo chown -R nginx:nginx /var/www/humhub
  sudo chmod -R 755 /var/www/humhub
  sudo chmod -R 775 /var/www/humhub/protected/runtime
  sudo chmod -R 775 /var/www/humhub/protected/modules
  sudo chmod -R 775 /var/www/humhub/uploads
  ```

- **Log Files**: Check logs for errors:
  ```bash
  sudo tail -f /var/log/nginx/error.log
  sudo journalctl -u phpfpm-humhub
  sudo cat /var/www/humhub/protected/runtime/logs/app.log
  ```

## Conclusion
You now have a fully functional HumHub social network running on NixOS. Explore the admin panel to customize your social network, install modules, and adjust settings to your requirements.
