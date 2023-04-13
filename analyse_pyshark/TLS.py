import pyshark
import os
from datetime import datetime, timedelta

def time_difference(packet_time, before):
    packet_datetime = datetime.fromisoformat(packet_time.replace("(UTC)", "").strip())
    return packet_datetime - before

summary_issuers = {'Message':dict(), 
                  'CallAudio':dict(), 
                  'CallVideo':dict()
                  }

summary_subjects = {'Message':dict(), 
                  'CallAudio':dict(), 
                  'CallVideo':dict()
                  }

summary_cipher = dict()         #dict de tous les ciphers utilisés et leurs nombres
TTLs = list()               #liste de toutes les durées de certificats


for i in ['Message', 'CallAudio', 'CallVideo']:
    for k in ['WiFi', 'Ethernet', '4G']:
        with open('TLS.txt', 'a') as f:
            f.write(f'------------------ {i} - {k} ------------------\n\n')
        directory = f'..\{i}\{k}\packets'
        for filename in os.listdir(directory):
            path = os.path.join(directory, filename)
            if not os.path.isfile(path): continue
            
            with open('TLS.txt', 'a') as f:
                f.write(f'> filename: {filename}\n')
            
            cap = pyshark.FileCapture(path, display_filter='tls')
            versions = {'TLS 1.3':0, 'TLS 1.2': 0, 'TLS 1.0': 0}
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

                    for hs_idx in range(len(hs_types)):
                        
                        if hs_types[hs_idx] == 'Client Hello': 
                            min_version = tls.record_version.showname_value.split('(')[0][0:-1]
                            max_version = tls.handshake_version.showname_value.split('(')[0][0:-1]
                            f.write(f"\t- {hs_types[hs_idx]} -min:{min_version} -max:{max_version}")
                            try: 
                                supported_versions = [field.showname_value.split('(')[0][0:-1] for field in tls.get("handshake.extensions.supported_version").all_fields]
                                f.write(f" -supported extension:{supported_versions}")
                            except: f.write(f" -No supported extension")
                            f.write("\n")

                        elif hs_types[hs_idx] == 'Server Hello':    
                            cipher = tls.handshake_ciphersuite.showname_value.split('(')[0][0:-1]
                            if cipher in summary_cipher: summary_cipher[cipher] += 1
                            else: summary_cipher[cipher] = 1
                            f.write(f"\t- {hs_types[hs_idx]} - {record_versions[0]} -cipher: {cipher} \n") 

                            if tls.get('handshake.extensions.supported_version') != None:
                                f.write(f"\t\t -supported extension:{tls.get('handshake.extensions.supported_version').showname_value.split('(')[0][0:-1]}\n") 
                                versions['TLS 1.3'] += 1
                                versions['TLS 1.2'] -= 1

                        elif hs_types[hs_idx] == 'Certificate':  
                            f.write(f"\t- {hs_types[hs_idx]} - {record_versions[0]}\n") 
                            certificates_times = [field.get_default_value() for field in tls.x509af_utctime.all_fields]
                            issuers_and_subjects = [field.showname_value.split('=')[1].rstrip(")") for field in tls.x509if_rdnsequence_item.all_fields if 'id-at-commonName' in field.showname_value]
                            
                            for cert_idx in range(len(tls.handshake_certificate_length.all_fields)):
                                
                                issuer = issuers_and_subjects[2*cert_idx]
                                subject = issuers_and_subjects[2*cert_idx+1]

                                if issuer in summary_issuers[i]: summary_issuers[i][issuer] += 1
                                else: summary_issuers[i][issuer] = 1
        
                                if subject in summary_subjects[i]: summary_subjects[i][subject] += 1
                                else: summary_subjects[i][subject] = 1
                                
                                ttl = time_difference(certificates_times[2*cert_idx+1], packet.sniff_time)
                                TTLs.append(ttl)
                                f.write(f"\t     {cert_idx+1} -TTL:{ttl} -issuer:{issuer} -subject:{subject}\n")
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
    for keycon, valcon in summary_issuers.items():
        f.write(f'\n|\t   >>>{keycon}')
        for key, val in sorted(valcon.items(), key=lambda x: x[1], reverse=True):
            f.write(f"\n|\t\t\t({val}) {key}")

    f.write('\n|\tAll the subjects> ')
    for keycon, valcon in summary_subjects.items():
        f.write(f'\n|\t   >>>{keycon}')
        for key, val in sorted(valcon.items(), key=lambda x: x[1], reverse=True):
            f.write(f"\n|\t\t\t({val}) {key}")

    f.write('\n|\tAll the cipher used> ')
    for key, val in sorted(summary_cipher.items(), key=lambda x: x[1], reverse=True): f.write(f"\n|\t\t({val}) {key}")

    f.write('\n|\n------------------ END SUMMARY ------------------')



total_seconds = sum([ttl.total_seconds() for ttl in TTLs])
average_seconds = int(total_seconds/len(TTLs))
average_delta = timedelta(seconds=average_seconds, microseconds=0)
print(f"\nMean TTL: {average_delta}\n")