import os

def generate_cascade_commands(target_ip, services_dict, workspace_dir, wordlist="/usr/share/wordlists/dirb/common.txt", threads=40):
    """
    Takes the parsed services and generates a bash script with specific tool commands.
    """
    script_path = os.path.join(workspace_dir, "run_enum.sh")
    
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# Auto-generated enumeration script for {target_ip}\n\n")
        
        for port, service in services_dict.items():
            service_name = service.lower()
            
            if service_name == 'http' or service_name == 'https':
                f.write(f"# —— Target: Port {port} (HTTP/HTTPS) ——\n")
                f.write(f"ffuf -w {wordlist} -u http://{target_ip}:{port}/FUZZ -t {threads}\n")
                f.write(f"feroxbuster -u http://{target_ip}:{port} -w {wordlist} -t {threads}\n\n")
                
            elif service_name == 'smb':
                f.write(f"# —— Target: Port {port} (SMB) ——\n")
                f.write(f"smbclient -N -L \\\\\\\\{target_ip}\n")
                f.write(f"smbmap -H {target_ip}\n")
                f.write(f"enum4linux -a {target_ip}\n\n")
                
            elif service_name == 'ftp':
                f.write(f"# —— Target: Port {port} (FTP) ——\n")
                f.write(f"nmap -sV -sC -p {port} {target_ip}\n")
                f.write(f"ftp {target_ip} {port}\n\n")
                
            elif service_name == 'ssh':
                f.write(f"# —— Target: Port {port} (SSH) ——\n")
                f.write(f"nmap -p {port} --script ssh-auth-methods,ssh2-enum-algos {target_ip}\n")
                f.write(f"ssh {target_ip} -p {port}\n\n")
                
            else:
                # The Professional Fallback: Deep Nmap scan for unknown services
                f.write(f"# —— Target: Port {port} ({service_name.upper()}) ——\n")
                f.write(f"nmap -sV -sC -A -p {port} {target_ip}\n\n")
                
    # Automatically make the generated bash script executable
    os.chmod(script_path, 0o755)
    print(f"[*] CASCADE COMPLETE: Auto-execution script created at {script_path}")
