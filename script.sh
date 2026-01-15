#!/bin/bash

# ==============================================================================
# MASTER SECURITY DEPLOYMENT SCRIPT (Weeks 1-7)
# Author: Aayusha Linbu (Automated)
# Description: Converts a fresh Ubuntu Server into a Hardened Bastion Node.
# ==============================================================================

# --- [ CONFIGURATION SECTION ] ---
# REPLACE THESE VALUES BEFORE RUNNING!

# 1. Your Management Workstation Public Key (Open PowerShell: type $env:USERPROFILE\.ssh\id_ed25519.pub)
YOUR_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE/hlzT6INJEbF3JqeXn1AwRtCXeLzoy/5j5gA67OI9O week4_hardening"

# 2. Your Trusted Management IP (The IP of your Windows/Host machine on the Host-Only network)
TRUSTED_IP="192.168.56.1"

# 3. Email Alerting Credentials (Week 5)
GMAIL_USER="testmodel1254@gmail.com"
GMAIL_APP_PASS="okvylobujuwdgvwj"

# 4. User Configuration
ENTRY_USER="aayusha"
ADMIN_USER="master_admin"
ADMIN_PASS="SecurePass123!" # Change this immediately after login!

# ==============================================================================

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./deploy_defense.sh)"
  exit
fi

echo "[*] Starting Comprehensive Security Deployment..."

# --- WEEK 1: INFRASTRUCTURE & NETWORKING ---
echo "--- [Week 1] Fixing Netplan & Networking ---"

# Fix Netplan for enp0s3 and enp0s8
cat > /etc/netplan/00-installer-config.yaml <<EOF
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: true
      dhcp6: true
EOF

chmod 600 /etc/netplan/00-installer-config.yaml
netplan generate
netplan apply
echo "[+] Netplan configured."

# --- WEEK 3: PERFORMANCE TOOLS ---
echo "--- [Week 3] Installing Benchmarking Tools ---"
apt update -y
apt install -y stress-ng fio btop
echo "[+] Performance tools installed."

# --- WEEK 4: RBAC & IDENTITY HARDENING ---
echo "--- [Week 4] Implementing Enterprise RBAC & SSH Hardening ---"

# 1. Create Master Admin (Tier 2)
if id "$ADMIN_USER" &>/dev/null; then
    echo "User $ADMIN_USER already exists."
else
    useradd -m -s /bin/bash $ADMIN_USER
    echo "$ADMIN_USER:$ADMIN_PASS" | chpasswd
    usermod -aG sudo $ADMIN_USER
    echo "[+] Master Admin created."
fi

# 2. Create SSH Users Group (Tier 1)
groupadd -f ssh-users
usermod -aG ssh-users $ENTRY_USER

# 3. Demote Entry User (Remove from Sudo)
deluser $ENTRY_USER sudo
echo "[+] RBAC Hierarchy enforced."

# 4. Install SSH Key for Entry User
mkdir -p /home/$ENTRY_USER/.ssh
echo "$YOUR_PUBLIC_KEY" >> /home/$ENTRY_USER/.ssh/authorized_keys
chown -R $ENTRY_USER:$ENTRY_USER /home/$ENTRY_USER/.ssh
chmod 700 /home/$ENTRY_USER/.ssh
chmod 600 /home/$ENTRY_USER/.ssh/authorized_keys
echo "[+] SSH Keys deployed."

# 5. Harden SSH Config (The Kill Switch)
# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Apply Hardening
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Add AllowGroups if not present
if ! grep -q "AllowGroups" /etc/ssh/sshd_config; then
    echo "AllowGroups ssh-users" >> /etc/ssh/sshd_config
fi

systemctl restart ssh
echo "[+] SSH Protocol Hardened (Passwords Disabled)."

# 6. Forensic Integrity
if systemctl is-active --quiet rsyslog; then
    chattr +a /var/log/auth.log
    echo "[+] Immutable attribute (+a) applied to auth.log."
else
    apt install -y rsyslog
    systemctl enable --now rsyslog
    touch /var/log/auth.log
    chattr +a /var/log/auth.log
    echo "[+] Rsyslog installed and Integrity applied."
fi

# 7. Firewall (UFW)
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow from $TRUSTED_IP to any port 22 proto tcp
# Force enable without prompt
echo "y" | ufw enable
echo "[+] Firewall Perimeter Activated."

# --- WEEK 5: ACTIVE DEFENSE & TELEMETRY ---
echo "--- [Week 5] Deploying Active Defense & Monitoring ---"

# 1. Install Packages
apt install -y apparmor-utils fail2ban postfix mailutils libsasl2-modules

# 2. AppArmor
aa-enforce /usr/sbin/tcpdump
echo "[+] AppArmor Profiles Enforced."

# 3. Fail2Ban Configuration
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
findtime = 600
EOF

systemctl restart fail2ban
echo "[+] Fail2Ban IPS Active."

# 4. Postfix SMTP Relay (Gmail)
# Configure SASL Password
echo "[smtp.gmail.com]:587 $GMAIL_USER:$GMAIL_APP_PASS" > /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd

# Configure main.cf via postconf
postconf -e 'relayhost = [smtp.gmail.com]:587'
postconf -e 'smtp_sasl_auth_enable = yes'
postconf -e 'smtp_sasl_security_options = noanonymous'
postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
postconf -e 'smtp_tls_security_level = encrypt'
postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'

systemctl restart postfix
echo "[+] Postfix SMTP Pipeline Configured."

# 5. Autonomous Monitoring Script
cat > /usr/local/bin/week5-monitor.sh <<'EOF'
#!/bin/bash
THRESHOLD=80
LOGfile="/var/log/system_monitor.csv"

# Initialize CSV if missing
if [ ! -f "$LOGfile" ]; then
    echo "Timestamp,CPU_Load,RAM_Usage" > $LOGfile
fi

while true; do
    # Calculate CPU (Idle inverted)
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}')
    # Calculate RAM %
    RAM=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$TIMESTAMP,$CPU,$RAM" >> $LOGfile

    # Alert Logic (Use bc for float comparison)
    IS_HIGH=$(echo "$CPU > $THRESHOLD" | bc -l)
    if [ "$IS_HIGH" -eq 1 ]; then
        echo "High CPU Load Detected: $CPU%" | mail -s "CRITICAL ALERT: CPU SPIKE" root
        sleep 300
    fi
    sleep 5
done
EOF

chmod +x /usr/local/bin/week5-monitor.sh

# 6. Monitoring Service
cat > /etc/systemd/system/week5-monitor.service <<EOF
[Unit]
Description=Week 5 Advanced Resource Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/week5-monitor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now week5-monitor.service
echo "[+] Autonomous Monitoring Daemon Started."

# --- WEEK 6: FINAL AUDIT TOOLS ---
echo "--- [Week 6] Installing Final Audit Tools ---"
apt install -y lynis
echo "[+] Lynis Installed."

# --- CONCLUSION ---
echo "=========================================================="
echo "Deployment Complete."
echo "1. Master Admin: $ADMIN_USER (Password: $ADMIN_PASS)"
echo "2. Entry User: $ENTRY_USER (SSH Key Only)"
echo "3. Firewall: Active (Only $TRUSTED_IP allowed on port 22)"
echo "4. Logs: Immutable"
echo "5. IPS: Active"
echo "=========================================================="