import pyshark
import os


situations = ['Message\WiFi', 'Message\Ethernet', 'Message\\4G',
              'CallAudio\WiFi', 'CallAudio\Ethernet', 'CallAudio\\4G',
              'CallVideo\WiFi', 'CallVideo\Ethernet', 'CallVideo\\4G']


quic_version = dict()
extensions = dict()
servers = dict()

for situation in situations:
    directory = f'..\{situation}\packets'
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if not os.path.isfile(path): continue
               
        cap = pyshark.FileCapture(path, display_filter='quic')
        for packet in cap:
            if not packet.quic.header_form.int_value: continue
            version = packet.quic.version.int_value
            if version in quic_version: quic_version[version] += 1
            else: quic_version[version] = 1
            print(filename)
                
            try:
                for extension in [field.showname_value.split('(')[0][0:-1] for field in packet.quic.tls_handshake_extension_type.all_fields]:
                    if extension in extensions: extensions[extension] += 1
                    else: extensions[extension] = 1

                for server in [field.showname_value.split('(')[0][0:-1] for field in packet.quic.tls_handshake_extensions_server_name.all_fields]:
                    if server in servers: servers[server] += 1
                    else: servers[server] = 1
            except: continue


with open('QUIC.txt', 'a') as f:
    f.write(f'\n\n------------------ SUMMARY ------------------\n|\n')
    f.write('|\tQUIC versions used> ')
    for key, val in quic_version.items(): f.write(f"\n|\t\t({val}) version {key}")
    f.write('\n|\tAll the extensions used in QUIC handshake> ')
    for key, val in sorted(extensions.items(), key=lambda x: x[1], reverse=True): f.write(f"\n|\t\t({val}) {key}")
    f.write('\n|\tserver name of SNI extension> ')
    for key, val in sorted(servers.items(), key=lambda x: x[1], reverse=True): f.write(f"\n|\t\t({val}) {key}")
    f.write('\n|\n------------------ END SUMMARY ------------------')