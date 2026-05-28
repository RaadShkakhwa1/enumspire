#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import shutil
import xml.etree.ElementTree as ET

# Import your Cascade engine
try:
    from cascade import generate_cascade_commands
except ImportError:
    print("[-] Error: cascade.py not found. Make sure it is in the same directory.")
    sys.exit(1)

def print_banner():
    banner = """
 ███████╗███╗   ██╗██╗   ██╗███╗   ███╗██████╗ ███████╗██████╗ ██╗██████╗ ███████╗
 ██╔════╝████╗  ██║██║   ██║████╗ ████║██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝
 █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝███████╗██████╔╝██║██████╔╝█████╗  
 ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔═══╝ ╚════██║██╔═══╝ ██║██╔══██╗██╔══╝  
 ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║     ███████║██║     ██║██║  ██║███████╗
 ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
                 Automated Reconnaissance & Enumeration Pipeline
    """
    print(banner)

def main():
    print_banner()

    # --- FULL PROFESSIONAL HELP MENU ---
    parser = argparse.ArgumentParser(
        description="EnumSpire - Automated Reconnaissance",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Core Options
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--ports", help="Manually specify ports (e.g., 80,443)")
    parser.add_argument("-Pn", dest="skip_ping", action="store_true", help="Skip host discovery (treat as online)")
    parser.add_argument("-U", "--udp", action="store_true", help="Include UDP scan (Requires sudo/root)")
    parser.add_argument("--speed", choices=["T3", "T4", "T5"], default="T4", help="Nmap timing template (Default: T4)")
    
    # Cascade / Enumeration Options
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Path to wordlist for directory busting (Default: dirb/common.txt)")
    parser.add_argument("-T", "--threads", default=50, type=int, help="Number of threads for enumeration tools (Default: 50)")
    parser.add_argument("--no-cascade", action="store_true", help="Halt pipeline after Nmap deep-scan (Skip Phase 3)")
    
    # Utility Options
    parser.add_argument("--format", choices=["txt", "md"], default="txt", help="Generate a final summary report in the specified format")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    
    args = parser.parse_args()
    target_ip = args.target

    # Create output directory based on the target IP
    out_dir = f"Enumspire_{target_ip.replace('.', '_')}"
    if not args.dry_run:
        os.makedirs(out_dir, exist_ok=True)

    # ---------------------------------------------------------
    # PHASE 1: Port Discovery (RustScan with Nmap Fallback)
    # ---------------------------------------------------------
    if args.ports:
        open_ports = args.ports
    else:
        if shutil.which("rustscan") is None:
            print("[!] Warning: RustScan is not installed.")
            print(f"[*] Falling back to standard Nmap for full port sweep against {target_ip} (This will take longer)...")
            open_ports = "-"  
        else:
            print(f"[*] Initiating Phase 1: RustScan against {target_ip}...")
            rustscan_cmd = f"rustscan -a {target_ip} -g"
            
            if args.dry_run:
                print(f"[DRY-RUN] Would execute: {rustscan_cmd}")
                open_ports = "22,80,443" 
            else:
                process = subprocess.run(rustscan_cmd, shell=True, capture_output=True, text=True)
                if "[" in process.stdout and "]" in process.stdout:
                    open_ports = process.stdout.split("[")[1].split("]")[0]
                    print(f"[+] RustScan discovered open ports: {open_ports}")
                else:
                    print("[-] RustScan did not find any open ports or failed to execute.")
                    sys.exit(0)

    # ---------------------------------------------------------
    # PHASE 2: Service Enumeration (Nmap)
    # ---------------------------------------------------------
    print(f"[*] Initiating Phase 2: Nmap deep-scan on ports: {open_ports} ...")
    xml_file = os.path.join(out_dir, "nmap_scan.xml")
    
    # Build the Nmap command dynamically with timing speed
    nmap_command = ["nmap", "-sV", "-sC", f"-{args.speed}", "-p", open_ports]
    
    if args.skip_ping:
        nmap_command.append("-Pn")
        
    # UDP Safety Check
    if args.udp:
        if os.geteuid() == 0:
            nmap_command.append("-sU")
        else:
            print("[!] Warning: UDP scan requires sudo privileges. Skipping UDP portion.")
            
    nmap_command.extend(["-oX", xml_file, target_ip])
    
    if args.dry_run:
        print(f"[DRY-RUN] Would execute: {' '.join(nmap_command)}")
    else:
        subprocess.run(nmap_command)
        print(f"[+] Nmap scan complete. Results saved to {xml_file}")

        # ---------------------------------------------------------
        # PHASE 3: XML Parsing & Cascade Handoff
        # ---------------------------------------------------------
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            parsed_services = {}
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_num = port.get("portid")
                    service_elem = port.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    parsed_services[port_num] = service_name
            
            if not parsed_services:
                print("[-] Nmap did not return any identifiable services to enumerate.")
                sys.exit(0)
            
            # --- SOC Reporting Format Engine ---
            report_file = os.path.join(out_dir, f"summary.{args.format}")
            with open(report_file, "w") as f:
                if args.format == "md":
                    f.write(f"# EnumSpire Scan Report: {target_ip}\n\n")
                    f.write("| Port | Service |\n|---|---|\n")
                    for port, svc in parsed_services.items():
                        f.write(f"| {port} | {svc} |\n")
                else:
                    f.write(f"EnumSpire Scan Report: {target_ip}\n")
                    f.write("-" * 30 + "\n")
                    for port, svc in parsed_services.items():
                        f.write(f"Port {port}: {svc}\n")
            print(f"[+] Generated SOC summary report: {report_file}")
            
            # --- Modular Execution Halt ---
            if args.no_cascade:
                print(f"[*] --no-cascade enabled. Halting pipeline before Phase 3.")
                print("[+] EnumSpire pipeline complete!")
                sys.exit(0)
                
            print(f"[*] Initiating Phase 3: Handing off {len(parsed_services)} services to Cascade...")
            
            generate_cascade_commands(
                target_ip, 
                parsed_services, 
                out_dir, 
                args.wordlist, 
                args.threads, 
                args.skip_ping
            )
            
            print("[+] EnumSpire pipeline complete! Check your output folder for the execution script.")
            
        except FileNotFoundError:
            print("[-] Error: Nmap XML file not found. Scan may have failed.")
        except Exception as e:
            print(f"[-] Error parsing Nmap results: {e}")

if __name__ == "__main__":
    main()
