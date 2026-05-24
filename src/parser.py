import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    """Extracts ports and service names from the Nmap XML output."""
    services = {}
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall('host'):
            for ports in host.findall('ports'):
                for port in ports.findall('port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        portid = int(port.get('portid'))
                        service = port.find('service')
                        if service is not None:
                            service_name = service.get('name')
                            services[portid] = service_name
                            
        return services
    except Exception as e:
        print(f"[!] Error parsing Nmap XML: {e}")
        return {}
