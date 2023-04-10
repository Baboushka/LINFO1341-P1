import pyshark
import os


situations = ['Message\WiFi', 'Message\Ethernet',
              'CallAudio\WiFi', 'CallAudio\Ethernet',
              'CallVideo\WiFi', 'CallVideo\Ethernet']


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
                
            try:
                for extension in [field.showname_value.split('(')[0][0:-1] for field in packet.quic.tls_handshake_extension_type.all_fields]:
                    if extension in extensions: extensions[extension] += 1
                    else: extensions[extension] = 1

                for server in [field.showname_value.split('(')[0][0:-1] for field in packet.quic.tls_handshake_extensions_server_name.all_fields]:
                    print(server)
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





# 'connection_number', 'dcid', 'field_names', 'fixed_bit', 'get', 'get_field', 
# 'get_field_by_showname', 'get_field_value', 'has_field', 'header_form', 
# 'layer_name', 'packet_length', 'pretty_print', 'raw_mode', 'remaining_payload',
# 'short', 'spin_bit
# ['', 'connection_number', 'packet_length', 'header_form', 'fixed_bit', 'long_packet_type', 
#  'long_reserved', 'packet_number_length', 'version', 'dcil', 'dcid', 'scil', 'token_length',
#    'length', 'packet_number', 'payload', 'frame', 'frame_type', 'crypto_offset',
#    'crypto_length', 'crypto_crypto_data', 'padding_length', 'crypto_fragments', 
#    'crypto_fragment', 'crypto_fragment_count', 'tls_handshake', 'tls_handshake_type'
#    , 'tls_handshake_length', 'tls_handshake_version', 'tls_handshake_random', 
#    'tls_handshake_session_id_length', 'tls_handshake_cipher_suites_length',
#      'tls_handshake_ciphersuites', 'tls_handshake_ciphersuite', 
#      'tls_handshake_comp_methods_length', 'tls_handshake_comp_methods', 
#      'tls_handshake_comp_method', 'tls_handshake_extensions_length',
#        'tls_handshake_extension_type', 'tls_handshake_extension_len', 
#        'tls_compress_certificate_algorithms_length', 'tls_compress_certificate_algorithm',
#          'tls_extension_psk_ke_modes_length', 'tls_extension_psk_ke_mode', 
#          'tls_handshake_extensions_key_share_client_length', 
#          'tls_handshake_extensions_key_share_group', 

#          'tls_handshake_extensions_key_share_key_exchange_length', 
#          'tls_handshake_extensions_key_share_key_exchange', 
#          'tls_handshake_extensions_alps_len', 'tls_handshake_extensions_alps_alpn_list', 
#          'tls_handshake_extensions_alps_alpn_str_len', 'tls_handshake_extensions_alps_alpn_str'
#          , 'tls_handshake_extensions_server_name_list_len', 
#          'tls_handshake_extensions_server_name_type', 
#          'tls_handshake_extensions_server_name_len', 
#          'tls_handshake_extensions_server_name', 
#          'tls_handshake_extensions_supported_groups_length', 
#          'tls_handshake_extensions_supported_groups', 
#          'tls_handshake_extensions_supported_group', 'tls_handshake_sig_hash_alg_len',
#            'tls_handshake_sig_hash_algs', 'tls_handshake_sig_hash_alg', 'tls_handshake_sig_hash_hash', 
#            'tls_handshake_sig_hash_sig', 'tls_parameter_type', 'tls_parameter_length', 
#            'tls_parameter_value', 
# 'tls_parameter_initial_source_connection_id', 'tls_parameter_google_initial_rtt', 
# 'tls_parameter_max_idle_timeout', 'tls_parameter_initial_max_stream_data_bidi_remote', 
# 'tls_parameter_initial_max_data', 'tls_parameter_vi_chosen_version', 'tls_parameter_vi_other_version',
#  'tls_parameter_initial_max_streams_bidi', 'tls_parameter_max_udp_payload_size',
#    'tls_parameter_initial_max_stream_data_uni', 'tls_parameter_initial_max_streams_uni',
#      'tls_parameter_max_datagram_frame_size', 'tls_parameter_google_quic_version', 
#      'tls_parameter_initial_max_stream_data_bidi_local', 'tls_handshake_extensions_alpn_len',
#        'tls_handshake_extensions_alpn_list', 'tls_handshake_extensions_alpn_str_len',
#          'tls_handshake_extensions_alpn_str', 'tls_handshake_extensions_supported_versions_len',
#            'tls_handshake_extensions_supported_version', 'tls_handshake_extensions_psk_identities_length',
#              'tls_handshake_extensions_psk_identity_identity_length', 
# 'tls_handshake_extensions_psk_identity_identity', 'tls_handshake_extensions_psk_identity_obfuscated_ticket_age',
#  'tls_handshake_extensions_psk_binders_len', 'tls_handshake_extensions_psk_binders', 'tls_handshake_ja3_full',
#    'tls_handshake_ja3']
# ['', 'connection_number', 'packet_length', 'header_form', 'fixed_bit', 'long_packet_type',
#   'long_reserved', 'packet_number_length', 'version', 'dcil', 'scil', 'scid', 'token_length', 'length', 
#   'packet_number', 'payload', 'frame', 'frame_type', 'ack_largest_acknowledged', 'ack_ack_delay',
#     'ack_ack_range_count', 'ack_first_ack_range', 'crypto_offset', 'crypto_length', 'crypto_crypto_data', 
#     'tls_handshake', 'tls_handshake_type', 'tls_handshake_length', 'tls_handshake_version',
#       'tls_handshake_random', 'tls_handshake_session_id_length', 'tls_handshake_ciphersuite', 
#       'tls_handshake_comp_method', 'tls_handshake_extensions_length', 'tls_handshake_extension_type',
#       'tls_handshake_extension_len', 'tls_handshake_extensions_supported_version', 
# 'tls_handshake_extensions_key_share_selected_group', 'tls_handshake_ja3s_full', 'tls_handshake_ja3s',
#  'padding_length']
