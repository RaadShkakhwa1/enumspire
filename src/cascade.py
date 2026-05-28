import os

def generate_cascade_commands(target_ip, services_dict, workspace_dir, wordlist, threads, no_ping, dry_run=False):
    print(f"\n[*] Initiating Phase 3: Generating cascade commands for {len(services_dict)} services...")
    
    script_path = os.path.join(workspace_dir, "run_enum.sh")
    
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# Auto-generated enumeration script for {target_ip}\n\n")
        
        for port, service in services_dict.items():
            service_lower = service.lower() if service else "unknown"
            print(f" [+] Mapping templates for port {port} ({service_lower})")
            
            # HTTP / Web
            if "http" in service_lower or "www" in service_lower:
                cmd = f"gobuster dir -u http://{target_ip}:{port} -w {wordlist} -t {threads} -o {workspace_dir}/http_{port}_gobuster.txt"
                f.write(f"# HTTP Enumeration for port {port}\n")
                f.write(f"{cmd}\n\n")
                
            # SMB / Windows
            elif "smb" in service_lower or "microsoft-ds" in service_lower or "netbios" in service_lower:
                cmd = f"enum4linux -a {target_ip} > {workspace_dir}/smb_{port}_enum4linux.txt"
                f.write(f"# SMB Enumeration for port {port}\n")
                f.write(f"{cmd}\n\n")
                
            # FTP
            elif "ftp" in service_lower:
                cmd = f"nmap -p {port} --script ftp-anon {target_ip} -oN {workspace_dir}/ftp_{port}_anon.txt"
                f.write(f"# FTP Enumeration for port {port}\n")
                f.write(f"{cmd}\n\n")
                
            else:
                f.write(f"# No specific automated template available for {service_lower} on port {port}\n\n")
                
    # Make the generated script executable
    os.chmod(script_path, 0o755)
    
    print(f"[*] CASCADE COMPLETE: Auto-execution script created at {script_path}")
    
    if dry_run:
        print("[!] DRY RUN MODE: Script was generated but will not be executed automatically.")
    else:
        print("[*] To execute the targeted enumeration attacks, run:")
        print(f"    ./{script_path}")
