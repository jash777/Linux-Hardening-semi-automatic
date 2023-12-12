#!/bin/bash

# Function to check if a package is installed

# Function to handle errors
exit_on_error() {
    echo "$1"
    exit 1
}


is_installed() {
    dpkg -l "$1" &> /dev/null
}

echo "Checking and installing Lynis and Ansible as needed"
sudo apt update -y

# Check if Lynis is installed, install if not
if is_installed lynis; then
    echo "Lynis is already installed."
else
    sudo apt install lynis -y
fi

# Check if Ansible is installed, install if not
if is_installed ansible; then
    echo "Ansible is already installed."
else
    sudo apt install ansible -y
fi

echo "Applying semi-auto hardening from dev-sec.io playbook"
if ansible-galaxy install dev-sec.os-hardening; then
    echo "Successfully installed dev-sec.os-hardening"
else
    echo "Failed to install dev-sec.os-hardening. Exiting."
    exit 1
fi

# Retrieve the primary IP address of the server
server_ip=$(hostname -I | awk '{print $1}')
if [ -z "$server_ip" ]; then
    echo "Failed to obtain server IP. Exiting."
    exit 1
fi

echo "Server IP is: $server_ip"
echo "Applying rules with server IP"

# Create an inventory file
echo "$server_ip" > inventory

cat <<EOF > hardening.yaml
---
- name: Harden Linux
  hosts: localhost  # Using the server's primary IP address
  become: true

  roles:
    - dev-sec.os-hardening
EOF

# Run the playbook with the new inventory
if ansible-playbook hardening.yaml; then
    echo "Ansible playbook executed successfully."
else
    echo "Failed to execute Ansible playbook. Exiting."
    exit 1
fi

echo "Generating Lynis Report"
#if sudo lynis audit system; then
#    echo "Lynis report generated successfully."
#else
#    echo "Failed to generate Lynis report. Exiting."
#    exit 1
#fi

# Apply iptables rules and show confirmation after each rule

sudo apt install iptables -y

## insatalling iptables-persitent
# Pre-seed answers for iptables-persistent installation
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections

# Install iptables-persistent non-interactively
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent || exit_on_error "Failed to install iptables-persistent"

# Flush existing rules to start clean
sudo iptables -F

# Set default chain policies
sudo iptables -P INPUT DROP
echo "Default policy set: DROP all incoming traffic"
sudo iptables -P FORWARD DROP
echo "Default policy set: DROP all forwarded traffic"
sudo iptables -P OUTPUT DROP
echo "Default policy set: DROP all outgoing traffic"

# Allow established and related connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
echo "Rule added: Allow established and related incoming connections"


# Allow loopback interface
sudo iptables -A INPUT -i lo -j ACCEPT
echo "Rule added: Allow all incoming traffic on loopback interface"
sudo iptables -A OUTPUT -o lo -j ACCEPT
echo "Rule added: Allow all outgoing traffic on loopback interface"

# SSH - Adjust the port if you use a non-standard port
SSH_PORT=22
sudo iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport $SSH_PORT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow basic internet connectivity (HTTP and HTTPS)
sudo iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Allow DNS resolution (necessary for many network interactions)
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Drop invalid packets
sudo iptables -A INPUT -m state --state INVALID -j DROP
echo "Rule added: Drop all invalid packets"

# Drop packets with bogus TCP flags
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
echo "Rule added: Drop packets with ALL NONE TCP flags"
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
echo "Rule added: Drop packets with ALL ALL TCP flags"

# DDoS Protection
# Limit connections per source IP
sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above 50 -j DROP
echo "DDoS Protection: Limit connections per source IP"

# Limit RST packets
sudo iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
sudo iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
echo "DDoS Protection: Limit RST packets"

# Limit new TCP connections
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
echo "DDoS Protection: Limit new TCP connections"

# Block Ping (ICMP Echo Requests)
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
echo "Rule added: Block Ping (ICMP Echo Requests)"

# Limit ICMP requests
sudo iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j ACCEPT
sudo iptables -A INPUT -p icmp -j DROP
echo "Rule added: Limit ICMP requests"

# Block fragmented packets
sudo iptables -A INPUT -f -j DROP
echo "Rule added: Block fragmented packets"

# Block traffic from private subnets (spoofing)
sudo iptables -A INPUT -s 10.0.0.0/8 -j DROP
sudo iptables -A INPUT -s 172.16.0.0/12 -j DROP
sudo iptables -A INPUT -s 192.168.0.0/16 -j DROP
echo "Rule added: Block traffic from private subnets (spoofing)"
echo " Saving iptable rules"

# Saving rules
sudo netfilter-persistent save
echo " Updated Iptable Rules"
sudo iptables -L -v
echo "All iptables rules have been applied successfully."

## end of iptable rules

## installing malware scan
echo "rkhunter malware installer"
sudo apt install rkhunter -y

##installing apt listchange
echo " installing apt-lischanges "
sudo apt-get install apt-listchanges -y

# Set Banner Text
banner_text="Authorized users only. All activity may be monitored and reported."

# Update /etc/issue
echo "$banner_text" | sudo tee /etc/issue

# Update /etc/issue.net
echo "$banner_text" | sudo tee /etc/issue.net

# Modify /etc/ssh/sshd_config to set Banner
sudo sed -i '/^#Banner none/c\Banner /etc/issue.net' /etc/ssh/sshd_config

# Restart SSH service to apply changes
sudo systemctl restart ssh

# Function to update or add a configuration in sshd_config
update_sshd_config() {
    local key="$1"
    local value="$2"
    local file="/etc/ssh/sshd_config"

    # If the configuration exists, change it; otherwise, append it
    if grep -q "^#*$key" "$file"; then
        sudo sed -i "s/^#*$key.*/$key $value/" "$file"
    else
        echo "$key $value" | sudo tee -a "$file"
    fi
}

# Update SSH configurations
update_sshd_config "AllowTcpForwarding" "no"
update_sshd_config "ClientAliveCountMax" "2"
update_sshd_config "Compression" "no"
update_sshd_config "LogLevel" "VERBOSE"
update_sshd_config "MaxAuthTries" "3"
update_sshd_config "MaxSessions" "2"
update_sshd_config "TCPKeepAlive" "no"
update_sshd_config "X11Forwarding" "no"
update_sshd_config "AllowAgentForwarding" "no"

# Restart SSH service to apply changes
sudo systemctl restart ssh

echo "SSH configuration updated and service restarted."

# 2. Install debsums and apt-show-versions
sudo apt-get install -y debsums apt-show-versions || exit_on_error "Failed to install debsums and apt-show-versions"

# 3. Change permission of sudoers directory
sudo chmod 750 /etc/sudoers.d || exit_on_error "Failed to change permissions of /etc/sudoers.d"

# 4. Disable USB Storage Drivers
echo "blacklist usb-storage" | sudo tee /etc/modprobe.d/blacklist-usbstorage.conf || exit_on_error "Failed to blacklist usb-storage"

# 5. Purge Old/Removed Packages
sudo apt-get purge -y $(dpkg --list | grep '^rc' | awk '{print $2}') || exit_on_error "Failed to purge old/removed packages"

# 6. Postfix Configuration
sudo postconf -e "smtpd_banner = \$myhostname ESMTP" || exit_on_error "Failed to set smtpd_banner"
sudo postconf -e "disable_vrfy_command = yes" || exit_on_error "Failed to disable vrfy_command"

# 7. Install and configure acct and sysstat
sudo apt-get install -y acct sysstat || exit_on_error "Failed to install acct and sysstat"

# Configure sysstat and enable it
echo "ENABLED=\"true\"" | sudo tee /etc/default/sysstat || exit_on_error "Failed to configure sysstat"

# Restart sysstat to apply changes
sudo service sysstat restart || exit_on_error "Failed to restart sysstat service"

# Install libpam-tmpdir
sudo apt-get install libpam-tmpdir -y || exit_on_error "Failed to install libpam-tmpdir"

# Install fail2ban
sudo apt-get install fail2ban -y || exit_on_error "Failed to install fail2ban"

# Add legal banner to /etc/issue and /etc/issue.net
echo "Unauthorized access is prohibited" | sudo tee /etc/issue /etc/issue.net || exit_on_error "Failed to add legal banner"

# Install file integrity tool
sudo apt-get install aide -y || exit_on_error "Failed to install AIDE"

# Update sysctl values
sudo sysctl -w net.ipv4.conf.all.rp_filter=1 || exit_on_error "Failed to update sysctl values"

# Install unattended-upgrades
sudo apt-get install unattended-upgrades -y || exit_on_error "Failed to install unattended-upgrades"

# Enable and configure unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades || exit_on_error "Failed to configure unattended-upgrades"

# Set password hashing rounds in /etc/login.defs
echo "Setting password hashing rounds..."
echo "SHA_CRYPT_MIN_ROUNDS=5000" | sudo tee -a /etc/login.defs
echo "SHA_CRYPT_MAX_ROUNDS=10000" | sudo tee -a /etc/login.defs || exit_on_error "Failed to set password hashing rounds"

# Set password expiration dates in /etc/login.defs
echo "Setting password expiration..."
echo "PASS_MAX_DAYS=90" | sudo tee -a /etc/login.defs
echo "PASS_MIN_DAYS=10" | sudo tee -a /etc/login.defs
echo "PASS_WARN_AGE=7" | sudo tee -a /etc/login.defs || exit_on_error "Failed to set password expiration dates"

# Copy /etc/fail2ban/jail.conf to jail.local
echo "Copying fail2ban jail.conf to jail.local..."
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || echo "Failed to copy fail2ban configuration"

# Final statement before Lynis audit
echo "Script execution completed. Proceeding to Lynis audit..."

# Lynis audit
echo "Running Lynis audit..."
sudo lynis audit system || echo "Lynis audit encountered issues"

# End of script
echo "Script and Lynis audit finished."



