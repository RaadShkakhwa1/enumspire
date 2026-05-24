#!/usr/bin/env python3
import argparse
import os
import sys

# ---------------------------------------------------------
# ENGINE IMPORTS - Fully Connected!
# ---------------------------------------------------------
from discovery import execute_rustscan
from deep_scan import execute_nmap
from cascade import generate_cascade_commands

def print_banner():
    """Displays the professional tool banner."""
    print("""
    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗███████╗██████╗ ██╗██████╗ ███████╗
    ██╔════╝████╗  ██║██║   ██║████╗ ████║██╔════╝██╔══██╗██║██╔══██╗██╔════╝
    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║███████╗██████╔╝██║██████╔╝█████╗  
    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║╚════██║██╔═══╝ ██║██╔══██╗██╔══╝  
    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████║██║     ██║██║  ██║███████╗
    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
    =========================================================================
                 Automated Reconnaissance & Enumeration Pipeline
    =========================================================================
    """)

def get_arguments():
    """Captures and formats the command-line flags."""
    parser = argparse.ArgumentParser(
        description="EnumSpire: Automated Reconnaissance and Enumeration Pipeline",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Required Target
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP address, domain, or CIDR range")
    
    # Execution Modifiers
    parser.add_argument("-p", "--ports", dest="ports", help="Specify ports to scan (e.g., 80,443). Skips RustScan phase.")
    parser.add_argument("-m", "--module", dest="module", help="Run templates for a specific service only (e.g., smb, http)")
    parser.add_argument("-Pn", "--no-ping", dest="noping", action="store_true", help="Treat the host as online (skip ICMP ping)")
    
    # Advanced Options
    parser.add_argument("-w", "--wordlist", dest="wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Custom wordlist for fuzzing")
    parser.add_argument("--threads", dest="threads", default="40", help="Number of concurrent threads for brute-forcing tools (default: 40)")
    parser.add_argument("-x", "--exclude", dest="exclude", help="Comma-separated IPs to exclude from the scan")
    
    # Output and Logging
    parser.add_argument("-o", "--output", dest="output", help="Custom output directory path")
    parser.add_argument("-r", "--report", dest="report", action="store_true", help="Generate a Markdown executive summary report (Coming Soon)")
    parser.add_argument("-s", "--stealth", dest="stealth", action="store_true", help="Run scans slower (T2) to evade basic detection")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable detailed console output")
    
    return parser.parse_args()

def validate_inputs(args):
    """Guardrails: Prevents the script from crashing due to user error."""
    if not os.path.exists(args.wordlist):
        print(f"[!] FATAL ERROR: The wordlist path '{args.wordlist}' does not exist.")
        print("[!] Please check your path and try running Enumspire again.")
        sys.exit(1)

def main():
    print_banner()
    
    # 1. Capture and Validate Flags
    args = get_arguments()
    validate_inputs(args)
    
    target_ip = args.target
    
    # 2. Configure the Output Directory
    if args.output:
        workspace_dir = args.output
    else:
        workspace_dir = f"Enumspire_{target_ip.replace('.', '_')}"
        
    if not os.path.exists(workspace_dir):
        os.makedirs(workspace_dir)
        if args.verbose:
            print(f"[*] Created workspace directory: {workspace_dir}")

    # 3. WIRING: The Single Module Override (-m)
    if args.module:
        print(f"[*] Module flag detected. Skipping network scanning.")
        print(f"[*] Generating execution templates for: {args.module.upper()}")
        
        target_service = args.module.lower()
        
        if args.ports:
            # If user provides custom ports, use them
            services_dict = {int(port): target_service for port in args.ports.split(',')}
        else:
            # Small override dict for common tools, then fallback to Linux native lookup
            default_ports = {'http': 80, 'https': 443, 'smb': 445} 
            
            if target_service in default_ports:
                mapped_port = default_ports[target_service]
            else:
                try:
                    # Automatically query the Linux /etc/services database
                    mapped_port = socket.getservbyname(target_service)
                except OSError:
                    print(f"[!] Warning: Unknown service '{target_service}'. Defaulting to port 80.")
                    print(f"[!] Hint: Use -p to manually specify the port.")
                    mapped_port = 80
                    
            services_dict = {mapped_port: target_service}
            
        generate_cascade_commands(target_ip, services_dict, workspace_dir, args.wordlist, args.threads)
        
        print("[*] Single module execution complete. Check your run_enum.sh file.")
        sys.exit(0)

    # 4. WIRING: The Specific Ports Override (-p)
    if args.ports:
        print(f"[*] Port flag detected. Skipping RustScan.")
        open_ports = args.ports
    else:
        print(f"[*] Initiating Phase 1: RustScan against {target_ip}...")
        open_ports = execute_rustscan(target_ip)

    # 5. WIRING: The Nmap Modifiers & Execution
        if open_ports:
            if args.verbose:
                print(f"[*] Initiating Phase 2: Nmap deep-scan on ports: {open_ports}...")
            
            # Build the base Nmap command list
        nmap_command = ["nmap", "-p", open_ports, "-sV", "-sC"]

        # 1. Handle the -s (Stealth) timing flag
        if args.stealth:
            print("[+] Stealth mode enabled (-T2)")
            nmap_command.insert(1, "-T2")
        else:
            nmap_command.insert(1, "-T4")

        # 2. The User Choice Logic (-Pn)
        if args.noping:
            print("[+] No-Ping mode enabled (-Pn)")
            nmap_command.insert(1, "-Pn")

        # 3. Handle exclusions if they exist
        if getattr(args, 'exclude', None):
            print(f"[+] Excluding IPs: {args.exclude}")
            nmap_command.insert(1, args.exclude)
            nmap_command.insert(1, "--exclude")

        # 4. Append target last
        nmap_command.append(args.target)
            
            # Save the output as XML for parsing
            nmap_xml_path = os.path.join(workspace_dir, "nmap_scan.xml")
            nmap_command.extend(["-oX", nmap_xml_path])
            
            if args.verbose:
                print(f"[*] Executing Nmap Command: {' '.join(nmap_command)}")
                
            try:
                subprocess.run(nmap_command, check=True)
            except subprocess.CalledProcessError:
                print("[!] Error: Nmap scan failed or was interrupted.")
                sys.exit(1)
            
            # Parse the XML to find specific services
            services_dict = {}
            if os.path.exists(nmap_xml_path):
                try:
                    tree = ET.parse(nmap_xml_path)
                    root = tree.getroot()
                    
                    for port in root.findall('.//port'):
                        portid = port.get('portid')
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            service = port.find('service')
                            if service is not None and service.get('name'):
                                services_dict[portid] = service.get('name')
                except ET.ParseError:
                    pass # Empty or broken XML handles gracefully
                    
            if not services_dict:
                print("[-] Nmap did not return any identifiable services to enumerate.")
                sys.exit(0)
                
            # Trigger the Cascade Builder with all user arguments
            generate_cascade_commands(
                target_ip=args.target, 
                services_dict=services_dict, 
                workspace_dir=workspace_dir, 
                wordlist=args.wordlist, 
                threads=args.threads,
                no_ping=args.no_ping
            )
        
        # Build the dynamic Nmap command list
        nmap_command = ["nmap", "-p", open_ports, "-sV", "-sC"]
        
        if args.stealth:
            print("[+] Stealth mode enabled (-T2)")
            nmap_command.insert(1, "-T2")
        else:
            nmap_command.insert(1, "-T4")

        if args.noping:
            print("[+] No-Ping mode enabled (-Pn)")
            nmap_command.insert(1, "-Pn")

        if args.exclude:
            print(f"[+] Excluding IPs: {args.exclude}")
            # Insert exclude flags 
            nmap_command.insert(1, args.exclude)
            nmap_command.insert(1, "--exclude")
            
        nmap_command.append(target_ip)
        
        if args.verbose:
            print(f"[*] Executing Nmap Command: {' '.join(nmap_command)}")
            
        # Execute the scan AND capture the returned XML data dictionary
        parsed_services = execute_nmap(nmap_command, workspace_dir)
        
        # 6. WIRING: Pass parsed data and variables to Cascade Generator
        if parsed_services:
            print(f"\n[*] Initiating Phase 3: Generating specific enumeration commands...")
            if args.wordlist != "/usr/share/wordlists/dirb/common.txt":
                print(f"[+] Injecting custom wordlist: {args.wordlist}")
                
            generate_cascade_commands(target_ip, parsed_services, workspace_dir, args.wordlist, args.threads)
        else:
            print("[-] Nmap did not return any identifiable services to enumerate.")
            
        # 7. WIRING: The Markdown Report Flag (-r)
        if args.report:
            print(f"[*] Markdown Executive Summary module is under construction.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user (Ctrl+C). Exiting...")
        sys.exit(0)
