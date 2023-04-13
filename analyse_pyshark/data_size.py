import pyshark
import os

payload_sizes = { 'Message':{'WiFi':dict(), 'Ethernet':dict(), '4G':dict()},
                  'CallAudio':{'WiFi':dict(), 'Ethernet':dict(), '4G':dict()}, 
                  'CallVideo':{'WiFi':dict(), 'Ethernet':dict(), '4G':dict()}
                  }

for i in ['Message']:
    for k in ['WiFi', 'Ethernet', '4G']:
        directory = f'..\{i}\{k}\packets'
        list_files = os.listdir(directory)
        nmb_files = len(list_files)
        for filename in list_files:
            path = os.path.join(directory, filename)
            if not os.path.isfile(path): continue
            print(filename)
            capmsg = pyshark.FileCapture(path, display_filter='tcp')
            count = 0
            for packet in capmsg:
                count += 1
                if not packet.tcp.has_field('payload'): continue
                if filename in payload_sizes[i][k]: payload_sizes[i][k][filename] += int(packet.tcp.get('payload').size)
                else: payload_sizes[i][k][filename] = int(packet.tcp.get('payload').size)
            payload_sizes[i][k][filename] /= float(capmsg[count-1].frame_info.time_relative) 


for i in ['CallAudio', 'CallVideo']:
    for k in ['WiFi', 'Ethernet', '4G']:
        directory = f'..\\1minCall\{i}\{k}\packets'
        list_files = os.listdir(directory)
        nmb_files = len(list_files)
        for filename in list_files:
            path = os.path.join(directory, filename)
            if not os.path.isfile(path): continue
            
            capcall = pyshark.FileCapture(path, display_filter='udp')
            count = 0
            for packet in capcall:
                count += 1
                if filename in payload_sizes[i][k]: payload_sizes[i][k][filename] += int(packet.udp.payload.size)
                else: payload_sizes[i][k][filename] = int(packet.udp.payload.size)
            payload_sizes[i][k][filename] /= float(capcall[count-1].frame_info.time_relative) 
            

with open('data_size.txt', 'a') as f:
    f.write(f"{payload_sizes}")
