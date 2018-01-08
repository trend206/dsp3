import re
import ipaddress

from dsp3.models.manager import Manager

ruleXML = ""


with open('usecases/ips.txt') as f:
    ips = f.readlines()

for ip in ips:
    ip = ip.split(';')[0].strip()

    if "/" in ip:
        ip_addr = ipaddress.ip_network(ip)
        address = ip_addr.network_address.exploded
        if ip_addr.prefixlen == 16:
            pattern = re.compile("\d+\d{1,3}.\d{1,3}")
            ip_addr = re.search(pattern, address).group(0)
        elif ip_addr.prefixlen == 24:
            pattern = re.compile("\d{1,3}.\d{1,3}.\d{1,3}")
            ip_addr = re.search(pattern, address).group(0)
    else:
        ip_addr = ipaddress.ip_address(ip)


    rule = '<rule pat="X-Forwarded-For: %s" cmask="0x3" ctest="0x1">\n' % ip_addr
    rule = rule + 'drop "Found IP from Block List in XFF Header"\n'
    rule = rule + "</rule>\n"
    ruleXML = ruleXML + rule


dsm = Manager(username='username', password='password', tenant='ACME Corp')
result = dsm.dpi_rule_save("Web Server Common", "Block-X-Forward-List", True, True, "CUSTOM_XML", "DROP_CLOSE",
                           "ANY_PATTERNS_FOUND", "NORMAL", "DROP_CLOSE", "MEDIUM", ruleXML)
dsm.end_session()
print(result)
