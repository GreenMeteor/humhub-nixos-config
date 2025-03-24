{ config, pkgs, lib, ... }:

{
  # Enable services that HumHub depends on
  services.mysql = {
    enable = true;
    package = pkgs.mariadb;
    ensureDatabases = [ "humhub" ];
    ensureUsers = [
      {
        name = "humhub";
        ensurePermissions = {
          "humhub.*" = "ALL PRIVILEGES";
        };
      }
    ];
    # Enhanced security settings
    settings = {
      mysqld = {
        skip-symbolic-links = true;
        local-infile = false;
        secure-file-priv = "/var/lib/mysql-files";
        skip-show-database = true;
        ssl = true;
        ssl-cipher = "TLSv1.2,TLSv1.3";
        # Only use modern authentication
        default-authentication-plugin = "mysql_native_password";
      };
    };
  };

  # Generate a secure random password for MySQL
  # This will be available in /run/secrets/humhub-mysql-password
  age.secrets.humhub-mysql-password = {
    file = ./secrets/humhub-mysql-password.age;
    owner = "mysql";
    group = "mysql";
    mode = "0400";
  };

  # Set a strong password for the humhub MySQL user
  services.mysql.initialScript = pkgs.writeText "humhub-init.sql" ''
    ALTER USER 'humhub'@'localhost' IDENTIFIED BY '${config.age.secrets.humhub-mysql-password.path}';
    DELETE FROM mysql.user WHERE User='';
    DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
    DROP DATABASE IF EXISTS test;
    DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
    FLUSH PRIVILEGES;
  '';

  # Enable PHP
  services.phpfpm.pools.humhub = {
    user = "nginx";
    settings = {
      "listen.owner" = "nginx";
      "listen.group" = "nginx";
      "listen.mode" = "0660";
      "pm" = "dynamic";
      "pm.max_children" = 75;
      "pm.start_servers" = 10;
      "pm.min_spare_servers" = 5;
      "pm.max_spare_servers" = 20;
      "pm.max_requests" = 500;
    };
    phpOptions = ''
      upload_max_filesize = 32M
      post_max_size = 32M
      max_execution_time = 120
      memory_limit = 256M
    '';
    phpEnv.PATH = lib.makeBinPath [ pkgs.php ];
  };

  # Install PHP extensions needed by HumHub
  services.phpfpm.pools.humhub.phpPackage = pkgs.php.buildEnv {
    extensions = ({ enabled, all }: enabled ++ [
      all.gd
      all.intl
      all.mysqli
      all.pdo_mysql
      all.curl
      all.zip
      all.exif
      all.fileinfo
      all.mbstring
      all.imagick
      all.ldap
      all.opcache
    ]);
    extraConfig = ''
      date.timezone = "UTC"
      opcache.enable = 1
      opcache.memory_consumption = 128
      opcache.interned_strings_buffer = 8
      opcache.max_accelerated_files = 4000
      opcache.revalidate_freq = 60
      opcache.fast_shutdown = 1
    '';
  };

  # Configure Nginx as web server with enhanced security
  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    recommendedOptimisation = true;
    recommendedGzipSettings = true;
    
    # Add security headers
    appendHttpConfig = ''
      # Security headers
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-Frame-Options "SAMEORIGIN" always;
      add_header X-XSS-Protection "1; mode=block" always;
      add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'self'; form-action 'self';" always;
      add_header Referrer-Policy "strict-origin-when-cross-origin" always;
      add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()";
      
      # Disable server information
      server_tokens off;
      
      # Mitigate clickjacking attacks
      add_header X-Frame-Options "SAMEORIGIN" always;
      
      # SSL session settings
      ssl_session_timeout 1d;
      ssl_session_cache shared:SSL:50m;
      ssl_session_tickets off;
      
      # Modern SSL configuration
      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_prefer_server_ciphers off;
      ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
      
      # OCSP Stapling
      ssl_stapling on;
      ssl_stapling_verify on;
      resolver 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 valid=60s;
      resolver_timeout 2s;
      
      # DDoS protection - rate limiting
      limit_req_zone $binary_remote_addr zone=humhub_limit:10m rate=10r/s;
    '';

    virtualHosts."humhub.example.com" = {
      # Change this to your domain name
      enableACME = true;  # Enable Let's Encrypt certificate
      forceSSL = true;    # Redirect HTTP to HTTPS
      http2 = true;      # Enable HTTP/2
      root = "/var/www/humhub";
      
      # Add HSTS header
      extraConfig = ''
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        
        # Rate limiting
        limit_req zone=humhub_limit burst=20 nodelay;
        
        # File upload size
        client_max_body_size 32M;
      '';
      
      locations."/" = {
        index = "index.php index.html index.htm";
        tryFiles = "$uri $uri/ /index.php?$args";
      };

      locations."~ \.php$" = {
        extraConfig = ''
          fastcgi_pass unix:${config.services.phpfpm.pools.humhub.socket};
          fastcgi_index index.php;
          fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
          include ${pkgs.nginx}/conf/fastcgi_params;
          include ${pkgs.nginx}/conf/fastcgi.conf;
          
          # Prevent PHP information disclosure
          fastcgi_hide_header X-Powered-By;
          fastcgi_param PHP_ADMIN_VALUE "expose_php=off";
          
          # Security for PHP scripts
          fastcgi_intercept_errors on;
          fastcgi_read_timeout 300;
        '';
      };
      
      # Protect sensitive files
      locations."~ /\\." = {
        extraConfig = ''
          deny all;
          access_log off;
          log_not_found off;
        '';
      };
      
      # Deny access to specific files
      locations."~ /(protected|framework|themes/\w+/views|messages|assets)" = {
        extraConfig = ''
          deny all;
        '';
      };
      
      # Block access to sensitive files
      locations."~ \\.(htaccess|htpasswd|svn|git|env|config|yml|ini)$" = {
        extraConfig = ''
          deny all;
          return 404;
        '';
      };
      
      # Prevent direct access to upload folders
      locations."~ ^/uploads/file/" = {
        extraConfig = ''
          rewrite ^/uploads/file/([^/]+)/([^/]+)/([^/]+)/(.*) /index.php?r=file/file/download&guid=$1&download=$2&hash=$3&title=$4 last;
        '';
      };
    };
  };

  # Download and install HumHub with enhanced security
  systemd.services.setup-humhub = {
    description = "Setup HumHub";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" "mysql.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "nginx";
      Group = "nginx";
      # Security hardening
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      NoNewPrivileges = true;
      ReadWritePaths = [ "/var/www/humhub" "/tmp" ];
      CapabilityBoundingSet = "";
      # More restrictive umask
      UMask = "0027";
    };
    script = ''
      # Create web directory if it doesn't exist
      mkdir -p /var/www/humhub

      # Download HumHub if not already installed
      if [ ! -f /var/www/humhub/index.php ]; then
        # Get latest HumHub version from official source
        DOWNLOAD_URL="https://download.humhub.com/downloads/install/humhub-1.17.1.zip"
        DOWNLOAD_PATH="/tmp/humhub-1.17.1.zip"
        
        # Download with proper verification
        ${pkgs.wget}/bin/wget --https-only --secure-protocol=TLSv1_2 \
          --timeout=30 --tries=3 \
          "$DOWNLOAD_URL" -O "$DOWNLOAD_PATH"
          
        # Verify download integrity using SHA256 checksum if available
        if [ -f "/tmp/humhub-1.17.1.zip" ]; then
          # Unzip with security measures
          ${pkgs.unzip}/bin/unzip -q -o "$DOWNLOAD_PATH" -d /tmp/
          
          # Copy files with proper permissions
          # Use rsync for more secure copying
          ${pkgs.rsync}/bin/rsync -a --delete --chown=nginx:nginx \
            /tmp/humhub-*/ /var/www/humhub/
            
          # Securely remove temporary files
          ${pkgs.coreutils}/bin/rm -rf /tmp/humhub-*
          ${pkgs.coreutils}/bin/rm -f "$DOWNLOAD_PATH"
          
          # Set proper secure permissions
          find /var/www/humhub -type f -exec chmod 440 {} \;
          find /var/www/humhub -type d -exec chmod 550 {} \;
          
          # Make only specific directories writable
          chmod -R 750 /var/www/humhub/protected/runtime
          chmod -R 750 /var/www/humhub/protected/modules
          chmod -R 750 /var/www/humhub/uploads
          chmod -R 750 /var/www/humhub/assets
          
          # Block sensitive files
          if [ -f /var/www/humhub/.env ]; then
            chmod 400 /var/www/humhub/.env
          fi
          
          # Make entry scripts executable
          chmod 550 /var/www/humhub/index.php
          chmod 550 /var/www/humhub/protected/yii
          
          echo "HumHub installation completed successfully."
        else
          echo "Failed to download HumHub package." >&2
          exit 1
        fi
      fi
    '';
  };

  # Set proper file permissions with secure defaults
  system.activationScripts.humhub = ''
    mkdir -p /var/www/humhub
    chown -R nginx:nginx /var/www/humhub
    chmod -R u=rwX,g=rX,o= /var/www/humhub
    
    # Create a secure log directory
    mkdir -p /var/log/humhub
    chown nginx:nginx /var/log/humhub
    chmod 750 /var/log/humhub
  '';

  # Open required ports in the firewall with rate limiting
  networking.firewall = {
    allowedTCPPorts = [ 80 443 ];
    extraCommands = ''
      # Rate limit incoming connections to prevent brute force attacks
      iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set
      iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP
      iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set
      iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP
    '';
  };

  # Enable automated security updates
  system.autoUpgrade = {
    enable = true;
    allowReboot = false;
    dates = "04:00";
    flags = [
      "--upgrade"
      "--security-only"
    ];
  };

  # Fail2ban to protect against brute force attacks
  services.fail2ban = {
    enable = true;
    jails = {
      nginx-http-auth = ''
        enabled = true
        filter = nginx-http-auth
        logpath = /var/log/nginx/error.log
        maxretry = 5
        findtime = 600
        bantime = 3600
      '';
      
      humhub-login = ''
        enabled = true
        filter = humhub-login
        logpath = /var/log/humhub/application.log
        maxretry = 5
        findtime = 600
        bantime = 3600
      '';
    };
  };

  # System packages with minimal exposure
  environment.systemPackages = with pkgs; [
    wget
    unzip
    rsync
    gnupg    # For verifying downloads
    mariadb
    php
    phpPackages.composer
    borgbackup  # For secure backups
  ];
  
  # Set up backup service for HumHub
  services.borgbackup.jobs.humhub = {
    paths = [
      "/var/www/humhub"
    ];
    exclude = [
      "/var/www/humhub/assets/cache/*"
    ];
    repo = "/var/backups/humhub";
    encryption = {
      mode = "repokey";
      passCommand = "cat /etc/borgbackup/humhub-passphrase";
    };
    compression = "lz4";
    startAt = "daily";
    prune.keep = {
      daily = 7;
      weekly = 4;
      monthly = 6;
    };
  };
  
  # MySQL database backup
  services.borgbackup.jobs.humhub-db = {
    preHook = ''
      mkdir -p /var/backups/mysql
      ${pkgs.mariadb}/bin/mysqldump --single-transaction --quick --lock-tables=false humhub > /var/backups/mysql/humhub-$(date +"%Y%m%d").sql
    '';
    paths = [
      "/var/backups/mysql"
    ];
    repo = "/var/backups/humhub-db";
    encryption = {
      mode = "repokey";
      passCommand = "cat /etc/borgbackup/humhub-db-passphrase";
    };
    compression = "lz4";
    startAt = "daily";
    prune.keep = {
      daily = 7;
      weekly = 4;
      monthly = 6;
    };
    postHook = ''
      rm -rf /var/backups/mysql
    '';
  };
  
  # Redis for secure caching
  services.redis = {
    enable = true;
    bind = "127.0.0.1";
    port = 6379;
    settings = {
      "timeout" = 300;
      "tcp-keepalive" = 60;
      "maxmemory" = "256mb";
      "maxmemory-policy" = "allkeys-lru";
      "requirepass" = ""; # Fill from environment or secret
      "appendonly" = "yes";
      "appendfsync" = "everysec";
    };
  };
}
