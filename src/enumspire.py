#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import xml.etree.ElementTree as ET
from cascade import generate_cascade_commands

def print_banner():
    banner = """
    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗██████╗ ██╗██████╗ ██████╗ ███████╗
    ██╔════╝████╗  ██║██║   ██║████╗ ████║██╔══██╗██║██╔══██╗██╔══██╗██╔════╝
    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝██║██████╔╝██████╔╝█████╗  
    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔═══╝ ██║██╔══██╗██╔══██╗██╔══╝  
    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║     ██║██║  ██║██║  ██║███████╗
    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    """
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="EnumSpire: Automated Reconnaissance Pipeline")
    
    # Execution Modifiers
    parser.add_argument("-t", "--target", required=True, help="Target IP address or domain")
    parser.add_argument("-p", "--ports", dest="ports", help="Specify ports to scan (e.g., 80,443).")
    parser.add_argument("-m", "--module", dest="module", help="Run templates for a specific service only")
    parser.add_argument("-Pn", "--no-ping", dest="noping", action="store_true", help="Treat the host as online")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Custom wordlist")
    parser.add_argument("--threads", type=int, default=40, help="Threads for brute-forcing")
    parser.add_argument("-x", "--exclude", dest="exclude", help="Comma-separated IPs to exclude")
    parser.add_argument("-o", "--output", dest="output", help="Custom output directory")
    parser.add_argument("-s", "--stealth", dest="stealth", action="store_true", help="Run scans slower (T2)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed console output")
    
    # Debugging Flag
    parser.add_argument("--dry-run", action="store_true", help="DEBUG: Print commands without executing them")

    args = parser.parse_args()
    target_ip = args.target
    workspace_dir = args.output if args.output else f"Enumspire_{target_ip.replace('.', '_')}"

    if not os.path.exists(workspace_dir):
        os.makedirs(workspace_dir)

    # 5. WIRING: The Nmap Modifiers & Execution
    if args.ports:
        open_ports = args.ports
    else:
    print("[*] Initiating Phase 1: RustScan...")
    # Your original subprocess.run(['rustscan', '-a', target_ip ...]) code goes here
    # open_ports = <output from rustscan>

    if args.verbose or args.dry_run:
        print(f"[*] Initiating Phase 2: Nmap deep-scan on ports: {open_ports}...")
    
    nmap_command = ["nmap", "-p", open_ports, "-sV", "-sC"]

    # Insert flags at index 1
    if args.stealth:
        if args.verbose or args.dry_run: print("[+] Stealth mode enabled (-T2)")
        nmap_command.insert(1, "-T2")
    else:
        nmap_command.insert(1, "-T4")

    if args.noping:
        if args.verbose or args.dry_run: print("[+] No-Ping mode enabled (-Pn)")
        nmap_command.insert(1, "-Pn")

    if args.exclude:
        if args.verbose or args.dry_run: print(f"[+] Excluding IPs: {args.exclude}")
        nmap_command.insert(1, args.exclude)
        nmap_command.insert(1, "--exclude")

    # Append target last
    nmap_command.append(target_ip)
    
    # Save output as XML
    nmap_xml_path = os.path.join(workspace_dir, "nmap_scan.xml")
    nmap_command.extend(["-oX", nmap_xml_path])
    
    services_dict = {}

    if args.dry_run:
        print("\n[DEBUG] --- DRY RUN MODE TRIGGERED ---")
        print(f"[DEBUG] Final Nmap Command: {' '.join(nmap_command)}")
        print("[DEBUG] Bypassing subprocess execution...")
        print("[DEBUG] Injecting mock HTTP and SMB services for Phase 3 testing...")
        services_dict = {"80": "http", "445": "microsoft-ds"}
    else:
        if args.verbose:
            print(f"[*] Executing Command: {' '.join(nmap_command)}")
        try:
            subprocess.run(nmap_command, check=True)
        except subprocess.CalledProcessError:
            print("[!] Error: Nmap scan failed.")
            sys.exit(1)
            
        # XML Parsing
        if os.path.exists(nmap_xml_path):
            try:
                tree = ET.parse(nmap_xml_path)
                for port in tree.findall('.//port'):
                    if port.find('state').get('state') == 'open':
                        service = port.find('service')
                        if service is not None:
                            services_dict[port.get('portid')] = service.get('name')
            except ET.ParseError:
                print("[!] Error parsing Nmap XML output.")
                
    if not services_dict:
        print("[-] Nmap did not return any identifiable services to enumerate.")
        sys.exit(0)
            
    # Trigger Cascade
    generate_cascade_commands(
        target_ip=target_ip, 
        services_dict=services_dict, 
        workspace_dir=workspace_dir, 
        wordlist=args.wordlist, 
        threads=args.threads,
        no_ping=args.noping,
        dry_run=args.dry_run
    )

if __name__ == "__main__":
    main()
