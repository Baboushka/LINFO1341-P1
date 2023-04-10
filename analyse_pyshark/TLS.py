import pyshark
import os
from datetime import datetime

def time_difference(packet_time, before):
    packet_datetime = datetime.fromisoformat(packet_time.replace("(UTC)", "").strip())
    return packet_datetime - before

situations = ['Message\WiFi', 'Message\Ethernet',
              'CallAudio\WiFi', 'CallAudio\Ethernet',
              'CallVideo\WiFi', 'CallVideo\Ethernet']

summary_issuers = dict()
summary_subjects = dict()
summary_cipher = dict()         #dict de tous les ciphers utilisés et leurs nombres
TTLs = list()               #liste de toutes les durées de certificats


for situation in situations:
    with open('TLS.txt', 'a') as f:
        f.write(f'------------------ {situation} ------------------\n\n')
    directory = f'..\{situation}\packets'
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if not os.path.isfile(path): continue
        
        with open('TLS.txt', 'a') as f:
            f.write(f'> filename: {filename}\n')
        
        cap = pyshark.FileCapture(path, display_filter='tls')
        versions = {'TLS 1.2': 0, 'TLS 1.0': 0}
        contents = {'Application Data':0, 'Change Cipher Spec':0, 'Handshake':0}


        f = open('TLS.txt', 'a')
        for packet in cap:
            try: 
                tls = packet.tls
                
                record_versions = [field.showname_value.split('(')[0][0:-1] for field in tls.record_version.all_fields]
                for v in record_versions: versions[v] += 1    #Compte les versions

                content_type = [field.showname_value.split('(')[0][0:-1] for field in tls.record_content_type.all_fields]
                for c in content_type: contents[c] += 1
                hs_types = [field.showname_value.split('(')[0][0:-1] for field in tls.handshake_type.all_fields]

                for i in range(len(hs_types)):
                    
                    if hs_types[i] == 'Client Hello': 
                        min_version = tls.record_version.showname_value.split('(')[0][0:-1]
                        max_version = tls.handshake_version.showname_value.split('(')[0][0:-1]
                        f.write(f"\t- {hs_types[i]} -min:{min_version} -max:{max_version}\n")
                        try: 
                            supported_versions = [field.showname_value.split('(')[0][0:-1] for field in tls.get("handshake.extensions.supported_version").all_fields]
                            f.write(f"\t     -supported extension:{supported_versions}\n")
                        except: f.write(f"\t     -No supported extension\n")

                    elif hs_types[i] == 'Server Hello':    
                        cipher = tls.handshake_ciphersuite.showname_value.split('(')[0][0:-1]
                        if cipher in summary_cipher: summary_cipher[cipher] += 1
                        else: summary_cipher[cipher] = 1
                        f.write(f"\t- {hs_types[i]} - {record_versions[0]} -cipher: {cipher} \n") 

                    elif hs_types[i] == 'Certificate':  
                        f.write(f"\t- {hs_types[i]} - {record_versions[0]}\n") 
                        certificates_times = [field.get_default_value() for field in tls.x509af_utctime.all_fields]
                        issuers_and_subjects = [field.showname_value.split('=')[1].rstrip(")") for field in tls.x509if_rdnsequence_item.all_fields if 'id-at-commonName' in field.showname_value]
                        for i in range(len(tls.handshake_certificate_length.all_fields)):
                            issuer = issuers_and_subjects[2*i]
                            subject = issuers_and_subjects[2*i+1]
                            if issuer in summary_issuers: summary_issuers[issuer] += 1
                            else: summary_issuers[issuer] = 1
                            if subject in summary_subjects: summary_subjects[subject] += 1
                            else: summary_subjects[subject] = 1
                            ttl = time_difference(certificates_times[2*i+1], packet.sniff_time)
                            TTLs.append(ttl.total_seconds())
                            f.write(f"\t     {i+1} -TTL:{ttl} -issuer:{issuer} -subject:{subject}\n")
            except: continue

        f.write('Summary: -versions> ')
        for version in versions: f.write(f"{version} : {versions[version]}  ")
        f.write('\n         -content> ')
        for content in contents: f.write(f"{content} : {contents[content]}  ")
        f.write('\n\n')

    f.close()

with open('TLS.txt', 'a') as f:
    f.write(f'\n\n------------------ SUMMARY ------------------\n|\n')
    f.write('|\tAll the issuers> ')
    for issuer, count in sorted(summary_issuers.items(), key=lambda x: x[1], reverse=True): 
        f.write(f"\n|\t\t({count}) {issuer}")
    f.write('\n|\tAll the subjects> ')
    for subject, count in sorted(summary_subjects.items(), key=lambda x: x[1], reverse=True): 
        f.write(f"\n|\t\t({count}) {subject}")
    f.write('\n|\tAll the cipher used> ')
    for cipher in summary_cipher: f.write(f"\n|\t\t({summary_cipher[cipher]}) {cipher}")
    f.write('\n|\n------------------ END SUMMARY ------------------')


moyenne = sum(TTLs) / len(TTLs)
print(f"min : {min(TTLs)}")
print(f"max : {max(TTLs)}")

duration = datetime.fromtimestamp(moyenne).strftime('%d days %H hours %M minutes %S seconds')
print(duration)