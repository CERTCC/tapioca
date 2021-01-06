#!/usr/bin/env python3.7
# BEGIN LICENSE #
#
# CERT Tapioca
#
# Copyright 2018 Carnegie Mellon University. All Rights Reserved.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
# ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS.
# CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED
# TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY,
# OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON
# UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO
# FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a BSD (SEI)-style license, please see license.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for
# public release and unlimited distribution.  Please see Copyright
# notice for non-US Government use and distribution.
# CERT(R) is registered in the U.S. Patent and Trademark Office by
# Carnegie Mellon University.
#
# DM18-0637
#
# END LICENSE #

import re
import color
import os
import socket

local_prefix = '10.0'

dnsmap = {}
dnsreqs = []
targets = {}

sslversion = None
dtlsversion = None
sslversions = {}
sslhosts = []
dtlsversions = {}
requestedciphers = []
negotiatedciphers = {}
requesteddtlsciphers = []
negotiateddtlsciphers = {}
args = ''
sslpacketcount = 0
dtlspacketcount = 0

mandatory_ciphers = ['TLS_RSA_WITH_AES_128_CBC_SHA']
optional_ciphers = ['TLS_RSA_WITH_AES_128_CBC_SHA',
                    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'
                    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_RSA_WITH_AES_128_CBC_SHA256',
                    'TLS_RSA_WITH_AES_256_CBC_SHA256',
                    ]


regex = {
    'hexval': re.compile(r'.+\((0[xX][0-9a-fA-F]+)\)$'),
}


def get_dns_info(pkt):
    '''
    Populate the DNS map dictionary by looking for DNS responses in each packet
    Populate DNS request list by looking for DNS query in each packet
    dnsmap[IP] = hostname
    '''

    try:
        # The packet has a DNS response
        resp_name = str(pkt.dns.resp_name)
        resp_addr = str(getattr(pkt.dns, 'a', None))
        if not resp_addr:
            # Old version of tshark
            resp_addr = str(pkt.dns.resp_addr)

        if resp_name:
            # There is a DNS response name
            if resp_addr not in dnsmap:
                # Add it to our dictionary if we haven't seen it yet.
                dnsmap[resp_addr] = resp_name
        return
    except AttributeError as e:
        # Not a DNS packet
        pass

    try:
        # The packet has a DNS request
        qry_name = str(pkt.dns.qry_name)
        if qry_name:
            if qry_name not in dnsreqs:
                dnsreqs.append(qry_name)
    except AttributeError as e:
        # Not a DNS packet
        pass


def get_hosts_contacted(pkt):
    '''
    Populate dictionary of hosts contacted, packet by packet
    This uses packet summaries, so full detail is not included
    '''

    try:
        # Get specific packet properties
        protocol = pkt.protocol
        src_addr = pkt.source

        dst_addr = pkt.destination
        if dst_addr.startswith(local_prefix):
            # Don't consider Tapioca-related IPs
            return
        if dst_addr in dnsmap:
            # If we have a DNS entry, use that instead of IP
            dst_addr = dnsmap[dst_addr]

        description = protocol

        if (protocol == 'TCP' or protocol == 'UDP'):

            if pkt.info.split()[0].isdigit():
                # Normal TCP or UDP packet.  We can programmatically get
                # the source and destination ports
                src_port = pkt.info.split()[0]
                dst_port = pkt.info.split()[2]
                description = '%s/%s' % (dst_port, protocol)

        if ':' not in dst_addr:
            # No need to store info for ethernet-level targets
            if dst_addr not in targets:
                # New destination host not yet seen
                targets[dst_addr] = []
                targets[dst_addr].append(description)
            elif description not in targets[dst_addr]:
                # Host already seen, but add new protocol/port/transport
                targets[dst_addr].append(description)

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass


def set_local():
    global local_prefix

    if os.path.exists('tapioca.cfg'):
        with open('tapioca.cfg') as f:
            configlines = f.readlines()
        for line in configlines:
            if line.startswith('internal_subnet'):
                line = line.rstrip()
                local_subnet = line.split('=')[1]
                ip = local_subnet.split('/')[0]
                nums = ip.split('.')
                local_prefix = '.'.join(nums[:2])


def get_hosts_contacted_fullpacket(pkt):
    '''
    Populate dictionary of hosts contacted, packet by packet
    This uses complete packet data, so it can be very slow with large captures!
    '''
    global local_prefix

    try:
        # Get specific packet properties
        transport = pkt.transport_layer
        protocol = pkt.highest_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        if dst_addr.startswith(local_prefix):
            # Don't consider Tapioca-related IPs
            return
        if dst_addr in dnsmap:
            # If we have a DNS entry, use that instead of IP
            dst_addr = dnsmap[dst_addr]
        dst_port = pkt[pkt.transport_layer].dstport

        description = '%s (%s/%s)' % (protocol, dst_port, transport)
        if dst_addr not in targets:
            # New destination host not yet seen
            targets[dst_addr] = []
            targets[dst_addr].append(description)
        elif description not in targets[dst_addr]:
            # Host already seen, but add new protocol/port/transport
            targets[dst_addr].append(description)

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass


def get_host_contacted(pkt):
    '''
    Return host contacted for a single packet
    '''

    try:
        # Get specific packet properties
        transport = pkt.transport_layer
        protocol = pkt.highest_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        if dst_addr.startswith(local_prefix):
            # Don't consider Tapioca-related IPs
            return
        if dst_addr in dnsmap:
            # If we have a DNS entry, use that instead of IP
            dst_addr = dnsmap[dst_addr]

        return get_hostname(dst_addr)

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass


def get_hostname(ip_or_host):
    '''
    Take a host or IP address as input, and return a hostname
    '''
    ip_or_host = str(ip_or_host)
    try:
        socket.inet_aton(ip_or_host)
        # must be just an IP address. Look it up with getfqdn:
        hostname = socket.getfqdn(ip_or_host)
        return hostname
    except socket.error:
        # Not a valid IP address.  Must be a host name.
        return ip_or_host


def clear():
    global targets, dnsmap, dnsreqs, sslversion, sslversions, requestedciphers, \
        negotiatedciphers, requesteddtlsciphers, negotiateddtlsciphers, sslpacketcount, \
        dtlspacketcount, dtlsversion, dtlsversions

    targets = {}
    dnsmap = {}
    dnsreqs = []

    sslversion = None
    sslversions = {}
    requestedciphers = []
    negotiatedciphers = {}
    requesteddtlsciphers = []
    negotiateddtlsciphers = {}
    sslpacketcount = 0
    dtlspacketcount = 0
    dtlsversion = None
    dtlsversions = {}


def get_ssl_info(pkt):
    global sslpacketcount, sslversions, negotiatedciphers

    try:
        # Assume SSLv3 or TLS
        sslpkt = pkt.ssl
        sslpacketcount = sslpacketcount + 1
        handshake = sslpkt.handshake
        if handshake == 'Handshake Protocol: Client Hello':
            # print(pkt)
            maxsslversion = 0
            ciphersuitelist = []
            sslhost = get_host_contacted(pkt)
            for field_line in sslpkt._get_all_field_lines():
                if field_line.startswith('\tVersion: '):
                    intsslversion = extract_intval(field_line)
                    if intsslversion > maxsslversion:
                        # Newer SSL/TLS version than we've seen so far
                        maxsslversion = intsslversion
                        sslversion = extract_property(
                            field_line, 'Version')

                if field_line.startswith('\tCipher Suite: '):
                    ciphersuite = extract_property(
                        field_line, 'Cipher Suite')
                    if ciphersuite not in requestedciphers:
                        requestedciphers.append(ciphersuite)
                    if ciphersuite in mandatory_ciphers:
                        ciphersuite = color.bright(
                            color.green(ciphersuite))
                    elif ciphersuite in optional_ciphers:
                        ciphersuite = color.bright(ciphersuite)
                    ciphersuitelist.append(ciphersuite)
                    # print('%s: %s' %
                    #      (color.bright('Cipher suite'), ciphersuite))

            # Add host to list of hosts contacted per SSL version
            sslversions = addonlynew(
                sslversions, sslversion, sslhost)

            if str(sslversion) == 'TLS 1.2':
                sslversion = color.green(sslversion)
            else:
                sslversion = color.red(sslversion)
            if args.verbose:
                print('Client request handshake with %s: %s' % (sslhost,
                                                                color.bright(sslversion)))
            for ciphersuite in ciphersuitelist:
                if args.verbose:
                    print('%s: %s' %
                          ('Client-supported cipher suite', ciphersuite))

        elif handshake == 'Handshake Protocol: Server Hello':
            sslhost = get_source_host(pkt)
            #print('Server hello!')
            negotiated_ciphersuite = pkt.ssl.handshake_ciphersuite.showname
            negotiated_ciphersuite = extract_notab_property(
                negotiated_ciphersuite, 'Cipher Suite')
            # print('*** Negotiated SSL/TLS ciphersuite: %s' %
            #      negotiated_ciphersuite)
            # if negotiated_ciphersuite not in negotiatedciphers:
            #    negotiatedciphers.append(negotiated_ciphersuite)
            negotiatedciphers = addonlynew(
                negotiatedciphers, negotiated_ciphersuite, sslhost)

            if args.verbose:
                print('Negotiated ciphersuite with %s: %s' %
                      (sslhost, color.bright(negotiated_ciphersuite)))
                print('***********')

    except AttributeError:
        # SSLv2 doesn't have "handshake" structure
        try:
            sslpkt = pkt.ssl
            sslhost = get_host_contacted(pkt)
            if sslpkt.record == 'SSLv2 Record Layer: Client Hello':
                sslversion = 'SSLv2'
                if sslversion not in sslversions:
                    sslversions.append(str(sslversion))
                destination_host = get_host_contacted(pkt)
                if args.verbose:
                    print('Client request handshake with %s: %s' %
                          (destination_host, color.bright(color.red('SSLv2'))))
                for field_line in sslpkt._get_all_field_lines():
                    if field_line.startswith('\tCipher Spec: '):
                        ciphersuite = extract_property(
                            field_line, 'Cipher Spec')
                        if ciphersuite not in requestedciphers:
                            requestedciphers.append(ciphersuite)
                        if ciphersuite in mandatory_ciphers:
                            ciphersuite = color.bright(
                                color.green(ciphersuite))
                        elif ciphersuite in optional_ciphers:
                            ciphersuite = color.bright(ciphersuite)
                        if args.verbose:
                            print('%s: %s' %
                                  ('Client-supported cipher spec', ciphersuite))
            elif sslpkt.record == 'SSLv2 Record Layer: Server Hello':
                negotiated_cipherspec = pkt.ssl.handshake_cipherspec.showname
                negotiated_cipherspec = extract_notab_property(
                    negotiated_cipherspec, 'Cipher Spec')
                if negotiated_cipherspec not in negotiatedciphers:
                    negotiatedciphers.append(negotiated_cipherspec)
                if negotiated_cipherspec not in optional_ciphers and negotiated_cipherspec not in mandatory_ciphers:
                    negotiated_cipherspec = color.red(
                        negotiated_cipherspec)
                destination_host = get_source_host(pkt)
                if args.verbose:
                    print('Negotiated cipherspec with %s: %s' %
                          (destination_host, color.bright(negotiated_cipherspec)))
                    print('***********')
        except AttributeError:
            pass


def get_dtls_info(pkt):
    global dtlspacketcount, dtlsversions, negotiateddtlsciphers

    try:
        dtlspkt = pkt.dtls
        dtlspacketcount = dtlspacketcount + 1
        handshake = dtlspkt.handshake
        if handshake == 'Handshake Protocol: Client Hello':
            dtlshost = get_host_contacted(pkt)
            # print(pkt)
            maxdtlsversion = 0
            ciphersuitelist = []
            destination_host = get_host_contacted(pkt)
            for field_line in dtlspkt._get_all_field_lines():
                if field_line.startswith('\tVersion: '):
                    intdtlsversion = extract_intval(field_line)
                    if intdtlsversion > maxdtlsversion:
                        # Newer DTLS version than we've seen so far
                        maxdtlsversion = intdtlsversion
                        dtlsversion = extract_property(
                            field_line, 'Version')

                if field_line.startswith('\tCipher Suite: '):
                    ciphersuite = extract_property(
                        field_line, 'Cipher Suite')
                    if ciphersuite not in requesteddtlsciphers:
                        requesteddtlsciphers.append(ciphersuite)
                    if ciphersuite in mandatory_ciphers:
                        ciphersuite = color.bright(
                            color.green(ciphersuite))
                    elif ciphersuite in optional_ciphers:
                        ciphersuite = color.bright(ciphersuite)
                    ciphersuitelist.append(ciphersuite)
                    # print('%s: %s' %
                    #      (color.bright('Cipher suite'), ciphersuite))

            # Add host to list of hosts contacted per DTLS version
            dtlsversions = addonlynew(
                dtlsversions, dtlsversion, dtlshost)

            if str(dtlsversion) == 'DTLS 1.2':
                dtlsversion = color.green(dtlsversion)
            else:
                dtlsversion = color.red(dtlsversion)
            if args.verbose:
                print('Client request handshake with %s: %s' % (destination_host,
                                                                color.bright(dtlsversion)))
            for ciphersuite in ciphersuitelist:
                if args.verbose:
                    print('%s: %s' %
                          ('Client-supported cipher suite', ciphersuite))

        elif handshake == 'Handshake Protocol: Server Hello':
            dtlshost = get_source_host(pkt)
            #print('Server hello!')
            negotiated_ciphersuite = pkt.dtls.handshake_ciphersuite.showname
            negotiated_ciphersuite = extract_notab_property(
                negotiated_ciphersuite, 'Cipher Suite')
            # print('*** Negotiated DTLS ciphersuite: %s' %
            #      negotiated_ciphersuite)
            # if negotiated_ciphersuite not in negotiateddtlsciphers:
            #    negotiateddtlsciphers.append(negotiated_ciphersuite)
            negotiateddtlsciphers = addonlynew(
                negotiateddtlsciphers, negotiated_ciphersuite, dtlshost)
            if args.verbose:
                print('Negotiated ciphersuite with %s: %s' %
                      (dtlshost, color.bright(negotiated_ciphersuite)))
                print('***********')

    except AttributeError:
        pass


def extract_intval(line):
    n = re.match(regex['hexval'], line)
    if n:
        # Get the frame address from the backtrace line
        hexval = n.group(1)
        intval = int(hexval, 0)
    return intval


def extract_property(line, value):
    val = line.replace('\t%s: ' % value, '').rstrip()
    if ('(0x' in val):
        head, sep, tail = val.rpartition('(0x')
        val = head.rstrip()
    return val


def extract_notab_property(line, value):
    val = line.replace('%s: ' % value, '').rstrip()
    if ('(0x' in val):
        head, sep, tail = val.rpartition('(0x')
        val = head.rstrip()
    return val


def addonlynew(dictionary, keyname, val):
    # Populate list values in a dict
    # Create empty list of hosts contacted for this DTLS version
    if keyname not in dictionary:
        #print('Creating %[%s]' % (dictionary, keyname))
        vallist = []
        vallist.append(val)
        dictionary[keyname] = vallist
    # SSL version already seen.  Append any new host
    elif val not in dictionary[str(keyname)]:
        dictionary[keyname].append(val)

    return dictionary


def get_source_host(pkt):
    '''
    Get source host for packet
    '''

    try:
        # Get specific packet properties
        transport = pkt.transport_layer
        protocol = pkt.highest_layer
        src_addr = pkt.ip.src
        if src_addr in dnsmap:
            src_addr = dnsmap[src_addr]

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass

    return src_addr
