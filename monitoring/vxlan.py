#!/usr/bin/env python3

import fcntl
import os
import re
import requests
import socket
import struct
import sys
import threading
import time

class Sensor():
    def __init__(self):
        self.sensor = os.environ.get('SENSOR')
        if not self.sensor:
            raise ValueError('$SENSOR is not set')

        self.ipMatch = '.'.join(['(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)']*4)
        self.isAddr = re.match('\A%s\Z' % self.ipMatch, self.sensor)

        self.lastUpdated = None
        self.addr = None

        self.mutex = threading.Lock()

    def ip(self):
        if self.isAddr:
            return self.sensor

        if self.lastUpdated and time.time() - self.lastUpdated < 60 and self.addr:
            return self.addr

        with self.mutex:
            self.addr = None

            serviceAccountDirectory = '/var/run/secrets/kubernetes.io/serviceaccount'
            with open(os.path.join(serviceAccountDirectory, 'token'), 'r') as fd:
                k8stoken = fd.read().strip()

            # Get metadata about all containers
            metadata = requests.get('https://kubernetes.default.svc.cluster.local/api/v1/pods', verify=os.path.join(serviceAccountDirectory, 'ca.crt'), headers={'Authorization': 'Bearer %s' % k8stoken}).json()

            for pod in metadata['items']:
                if pod['metadata']['labels'].get('run') == self.sensor:
                    print(pod['status'])
                    self.addr = pod['status'].get('podIP')

            if not re.match('\A%s\Z' % self.ipMatch, self.addr):
                # Possible temporary failure
                print('pod %s IP address not found' % self.sensor)
            else:
                self.lastUpdated = time.time()

            print(self.addr)
            return self.addr

def main():
    interface = os.environ.get('INTERFACE')
    if not interface:
        print('$INTERFACE is not set')
        return 1

    try:
        sensor = Sensor()
    except ValueError as e:
        print(str(e))
        return 1

    vni = os.environ.get('VNI')
    if not vni:
        print('$VNI is not set')
        return 1

    try:
        vni = int(vni, 16)
    except ValueError:
        print('$VNI is not parsable as hexadecimal')
        return 1

    if vni & 0xff000000:
        print('$VNI should be no greater than 0xffffff')
        return 1

    ipAddr = fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s', interface.encode('ascii')))[20:24] # SIOCGIFADDR

    sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # ETH_P_ALL
    sniff.bind((interface, 0))

    vxlan = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # VXLAN header
    vxlanHeader  = struct.pack('!L', 0x08000000)
    vxlanHeader += struct.pack('!L', vni << 8)

    while True:
        (data, _) = sniff.recvfrom(65535)

        sensorAddr = sensor.ip()
        if not sensorAddr:
            continue

        ipPacket = data[14:]
        ipHeaderLength = (struct.unpack('B', bytes([data[0]]))[0] & 0x0f) * 4

        srcIP = ipPacket[12:16]
        dstIP = ipPacket[16:20]
        protocol = ipPacket[9]

        if protocol in [6, 17] and len(ipPacket) >= ipHeaderLength+3:
            srcPort = struct.unpack('!H', ipPacket[ipHeaderLength+0:ipHeaderLength+2])[0]
            dstPort = struct.unpack('!H', ipPacket[ipHeaderLength+2:ipHeaderLength+4])[0]

            # No idea what this is but we don't want to report on UDP/16401
            # Nor our own traffic on UDP/4789...
            if protocol == 17 and (srcPort == 16401 or dstPort == 4789):
                continue

            if protocol == 17:
                data = ipPacket[ipHeaderLength+8:]
                if data[:len(vxlanHeader)] == vxlanHeader:
                    continue

            if protocol == 17:
                continue

            print('Got %s byte%s from %s:%s to %s:%s proto %s (VXLAN %s->%s)' % (len(data), len(data) != 1 and 's' or '', socket.inet_ntoa(srcIP), srcPort, socket.inet_ntoa(dstIP), dstPort, protocol, socket.inet_ntoa(ipAddr), sensorAddr))

        vxlan.sendto(vxlanHeader+data, (sensorAddr, 4789))

if __name__ == '__main__':
    sys.exit(main())

