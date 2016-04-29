from collections import namedtuple
import re
import subprocess


def pinger(dest, count=1, pad_addr=True):
    regex_dst_ip = re.compile('(?<!reply from )(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    regex_dst_wsn = re.compile('w[dnv]-[\w\d]{12}', re.IGNORECASE)
    regex_dst_stats = re.compile('Minimum = (\d)*ms, Maximum = (\d)*ms, Average = (\d)*ms', re.IGNORECASE)
    Ping = namedtuple('Ping', ['addr', 'wsn', 'stats', 'count', 'reply'])
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW    
    ip_display_fmt = '{:03d}.{:03d}.{:03d}.{:03d}'
    cmd_text = ['ping', '-n', str(count), '-w', '100', dest]
    ip = wsn = stats = addr = addr_padded = ''
    try:
        proc_ping = subprocess.Popen(
                                     cmd_text
                                     ,stdout=subprocess.PIPE
                                     ,stderr=subprocess.PIPE
                                     ,startupinfo=startupinfo
                                     )
    except: #ping command failed to run
        reply = None
    else: #ping command ran to completion
        output = proc_ping.communicate()[0].decode('utf8')
        if proc_ping.returncode == 0: #received reply
            reply = True
            stats = tuple(int(stat) for stat in regex_dst_stats.search(output).group(1,2,3))
        else: #no reply received
            reply = False
    finally:
        #if given ip address, create string with padded zero octets (better sorting)
        if regex_dst_ip.search(dest):
            addr_padded = ip_display_fmt.format(*[int(octet) for octet in dest.split('.')]) #pad octets with leading zeroes
        else: #look for address in output instead
            wsn = dest
            ip_match = regex_dst_ip.search(output)
            if ip_match:
                addr = ip_match.group()
                addr_padded = ip_display_fmt.format(*[int(octet) for octet in addr.split('.')]) #pad octets with leading zeroes
        if pad_addr:
            addr = max([addr, addr_padded], key=len)
        else:
            addr = min([addr, addr_padded], key=len)
        return Ping(addr, wsn, stats, count, reply)
