import pyshark
import os

file_used = 'DNS.txt'

def transl_type(qr_type):
    if (qr_type == '1'): return 'A'
    return 'AAAA'

def write_format(filename):
    with open(filename, 'a') as f:
        for key, val in resolved_domains.items():
            f.write(f"\t- ({val['count']})  {key}\n\t\t -type:")
            for types in val['type']:
                f.write(f"{transl_type(types)} ")
            if val['soa']: f.write(f"-SOA:{val['soa']} ")
            if val['error'] != 0: f.write(f" -error:{val['error']} ")
            f.write(f"-port:{val['port']}\n")
        f.write(f"Summary : resolved: {resolved}, add. RR: {add_rr}, ")
        for dns_query_type, count in dns_queries.items():
            f.write(f"type:{transl_type(dns_query_type)} : {count} ")
        f.write("\n\n")

summary_soa = dict()
summary_addRR = 0
summary_domain = {'Message':{'WiFi':dict(), 'Ethernet':dict()}, 
                  'CallAudio':{'WiFi':dict(), 'Ethernet':dict()}, 
                  'CallVideo':{'WiFi':dict(), 'Ethernet':dict()}
                  }
    
                  
summary_resolved = {'Message':0, 'CallAudio':0, 'CallVideo':0}

for i in ['Message', 'CallAudio', 'CallVideo']:
    for k in ['WiFi', 'Ethernet']:
        with open(file_used, 'a') as f:
            f.write(f'------------------ {i} - {k} ------------------\n\n')
        directory = f'..\{i}\{k}\packets'
        list_files = os.listdir(directory)
        summary_domain[i][k]['nmb_files'] = len(list_files)
        for filename in list_files:
            path = os.path.join(directory, filename)
            if not os.path.isfile(path): continue
            with open(file_used, 'a') as f:
                f.write(f'> filename: {filename}\n')
                
            cap = pyshark.FileCapture(path, display_filter='dns')
            resolved_domains = dict()
            dns_queries = {'1': 0, '28': 0}
            add_rr = 0
            resolved = 0
            for packet in cap:
                if not packet.dns.flags_response.int_value: continue
                
                answ = packet.dns

                
                if answ.qry_name in resolved_domains: 
                    resolved_domains[answ.qry_name]['count'] += 1
                    resolved_domains[answ.qry_name]['type'].append(answ.qry_type)
                    if not resolved_domains[answ.qry_name]['soa']: 
                        resolved_domains[answ.qry_name]['soa'] = answ.get_field('soa.mname')
                else: resolved_domains[answ.qry_name] = {'count': 1, 'type':[answ.qry_type], 
                            'soa':answ.get_field('soa.mname'), 'port':packet.udp.dstport, 'error': 0}
                
                if answ.get_field('flags.rcode').int_value: 
                    resolved_domains[answ.qry_name]['error'] = answ.get_field('flags.rcode').showname_value
                    continue   #When error : doesn't count as resolved nor in the type count.
                
                soa = resolved_domains[answ.qry_name]['soa']
                if soa != None:
                    if soa in summary_soa: summary_soa[soa] += 1
                    else: summary_soa[soa] = 1

                if answ.qry_name in summary_domain[i][k]: summary_domain[i][k][answ.qry_name] += 1
                else: summary_domain[i][k][answ.qry_name] = 1

                dns_queries[answ.qry_type] += 1
                add_rr += answ.get_field("count.add_rr").int_value
                summary_addRR += add_rr
                resolved += 1
                summary_resolved[i] += 1
            write_format(file_used)


with open(file_used, 'a') as f:
    f.write(f'------------------ SUMMARY ------------------\n|\n')
    f.write('|\tAll the SOAs> ')
    for soa in summary_soa: f.write(f"\n|\t\t({summary_soa[soa]}) {soa}")
    f.write(f'\n|\tAdditionnal RR count> {summary_addRR}')
    for keysit, valsit in summary_domain.items(): 
        f.write(f'\n|\tDomain names in {keysit}>')
        for keycon, valcon in valsit.items():
            f.write(f'\n|\t   >>>{keycon}')
            nmb_files = valcon['nmb_files']
            count_domains = 0
            for key, val in sorted(valcon.items(), key=lambda x: x[1], reverse=True):
                if key == 'nmb_files': continue
                count_domains += val
                f.write(f"\n|\t\t\t({val}) {key}")
            f.write(f"\n|\t\t\t\tMean of domain names resolved: {count_domains / nmb_files}")
    f.write('\n|\n------------------ END SUMMARY ------------------')

