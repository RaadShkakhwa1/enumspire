import os

# ---------------------------------------------------------
# THE KNOWLEDGE BASE (ENUMERATION_MAP)
# ---------------------------------------------------------
ENUMERATION_MAP = {
    "ftp": {
        "ports": [21],
        "objective": "Checking for anonymous login and exposed files.",
        "execution_templates": [
            "nmap --script ftp-anon -p {port} {target_ip}",
            "lftp {target_ip}"
        ]
    },
    "ssh": {
        "ports": [22],
        "objective": "Identifying authentication methods and banner grabbing.",
        "execution_templates": [
            "netexec ssh {target_ip}",
            "ssh -v {target_ip}"
        ]
    },
    "telnet": {
        "ports": [23],
        "objective": "Banner grabbing and checking for unencrypted legacy access.",
        "execution_templates": [
            "nmap --script telnet-encryption,telnet-ntlm-info -p {port} {target_ip}",
            "nc -vn {target_ip} {port}"
        ]
    },
    "smtp": {
        "ports": [25, 465, 587],
        "objective": "Testing for open relays and enumerating valid users (VRFY/EXPN).",
        "execution_templates": [
            "nmap --script smtp-enum-users,smtp-open-relay -p {port} {target_ip}",
            "smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t {target_ip}"
        ]
    },
    "http": {
        "ports": [80, 443, 8080, 8000],
        "objective": "Discovering hidden directories, files, and virtual hosts.",
        "execution_templates": [
            "ffuf -w {wordlist} -u http://{target_ip}:{port}/FUZZ -t {threads}",
            "feroxbuster -u http://{target_ip}:{port} -w {wordlist} -t {threads}"
        ]
    },
    "pop3_imap": {
        "ports": [110, 143, 993, 995],
        "objective": "Checking for plaintext authentication and email extraction.",
        "execution_templates": [
            "nmap --script pop3-capabilities,imap-capabilities -p {port} {target_ip}",
            "netexec pop3 {target_ip}"
        ]
    },
    "nfs": {
        "ports": [111, 2049],
        "objective": "Identifying exported network shares and mount permissions.",
        "execution_templates": [
            "showmount -e {target_ip}",
            "nmap --script nfs-ls,nfs-showmount -p {port} {target_ip}"
        ]
    },
    "smb": {
        "ports": [139, 445],
        "objective": "Mapping shares, null sessions, and permissions.",
        "execution_templates": [
            "netexec smb {target_ip} --shares -u '' -p ''",
            "smbmap -H {target_ip}"
        ]
    },
    "ipmi": {
        "ports": [623],
        "objective": "Extracting BMC password hashes (IPMI 2.0 cipher zero vulnerability).",
        "execution_templates": [
            "nmap --script ipmi-version,ipmi-cipher-zero -p {port} -sU {target_ip}",
            "msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {target_ip}; run; exit'"
        ]
    },
    "docker_api": {
        "ports": [2375, 2376],
        "objective": "Interacting with exposed Docker daemons to list containers or escalate privileges.",
        "execution_templates": [
            "nmap -p {port} --script docker-version {target_ip}",
            "docker -H tcp://{target_ip}:{port} ps -a"
        ]
    },
    "mysql": {
        "ports": [3306],
        "objective": "Testing for empty passwords and extracting database schemas.",
        "execution_templates": [
            "nmap --script mysql-info,mysql-empty-password -p {port} {target_ip}",
            "mysql -h {target_ip} -u root"
        ]
    },
    "rdp": {
        "ports": [3389],
        "objective": "Evaluating Network Level Authentication (NLA) and encryption capabilities.",
        "execution_templates": [
            "nmap --script rdp-enum-encryption,rdp-ntlm-info -p {port} {target_ip}",
            "netexec rdp {target_ip}"
        ]
    },
    "vnc": {
        "ports": [5900, 5901, 5902],
        "objective": "Checking for unauthenticated access and server information.",
        "execution_templates": [
            "nmap --script vnc-info,vnc-title -p {port} {target_ip}"
        ]
    },
    "winrm": {
        "ports": [5985, 5986],
        "objective": "Identifying remote management authentication methods.",
        "execution_templates": [
            "netexec winrm {target_ip}",
            "nmap --script winrm-auth -p {port} {target_ip}"
        ]
    },
    "redis": {
        "ports": [6379],
        "objective": "Testing for unauthenticated database access and extracting system info.",
        "execution_templates": [
            "nmap --script redis-info -p {port} {target_ip}",
            "redis-cli -h {target_ip} info"
        ]
    },
    "mongodb": {
        "ports": [27017],
        "objective": "Testing for unauthenticated database access and listing collections.",
        "execution_templates": [
            "nmap -p {port} --script mongodb-info,mongodb-databases {target_ip}",
            "mongo --host {target_ip}"
        ]
    }
}

# ---------------------------------------------------------
# THE ENGINE
# ---------------------------------------------------------
def generate_cascade_commands(target_ip, open_services, workspace_dir, wordlist_path, threads):
    """Generates the run_enum.sh bash script based on discovered services."""
    script_path = f"{workspace_dir}/run_enum.sh"
    commands_generated = 0
    
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# Auto-generated enumeration script for {target_ip}\n\n")
        
        # If open_services is a single module string (from the -m flag)
        if isinstance(open_services, dict) and 0 in open_services:
            services_to_process = {0: open_services[0]}
        else:
            services_to_process = open_services
            
        for port, service in services_to_process.items():
            module_key = service.lower()
            
            if module_key in ENUMERATION_MAP:
                module = ENUMERATION_MAP[module_key]
                f.write(f"# --- Target: Port {port} ({module_key.upper()}) ---\n")
                
                for cmd in module['execution_templates']:
                    # Safely inject all the user's CLI flags into the string
                    formatted_cmd = cmd.replace("{target_ip}", target_ip) \
                                       .replace("{port}", str(port)) \
                                       .replace("{wordlist}", wordlist_path) \
                                       .replace("{threads}", str(threads))
                    f.write(f"{formatted_cmd}\n")
                
                f.write("\n")
                commands_generated += 1
                
    if commands_generated > 0:
        os.chmod(script_path, 0o755)
        print(f"[*] CASCADE COMPLETE: Auto-execution script created at {script_path}")
    else:
        print("[-] No actionable services matched in the knowledge base.")
        if os.path.exists(script_path):
            os.remove(script_path)
