#!/usr/bin/env python3
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

from __future__ import print_function
import pyshark
import socket
import color
import os
import sys
import re
import argparse
import pickle
import json
import net
from misc import eprint, Logger

local_prefix = '10.0'
report_output = 'crypto.txt'
json_output = 'crypto.json'


def generate_report(app, pcapfile=''):
    '''
    Print report based on collected data
    '''

    global sslpacketcount

    if app.endswith('.pcap'):
        app_or_pcap = 'pcap'
        jsonfile = '%s.%s' % (pcapfile, json_output)
    else:
        app_or_pcap = 'application'
        jsonfile = os.path.join(os.path.dirname(pcapfile), json_output)

    report = {}
    report['app'] = app
    report['testtime'] = os.path.getmtime(pcapfile)
    report['sslversions'] = net.sslversions
    report['requestedciphers'] = net.requestedciphers
    report['negotiatedciphers'] = net.negotiatedciphers
    report['dtlsversions'] = net.dtlsversions
    report['negotiateddtlsciphers'] = net.negotiateddtlsciphers

    seen_mandatory_ciphers = []
    seen_optional_ciphers = []
    seen_other_ciphers = []
    failedtest = False
    failedreasons = []

    print('')
    print('Summary for application: %s' % color.bright(color.cyan(app)))
    print('')

    if net.sslpacketcount > 0:
        print(color.bright('TLS/SSL protocols used:'))
        # For each target (unsorted)

        for sslversion in net.sslversions:
            if sslversion == 'TLS 1.2':
                sslversion = color.bright(color.green(sslversion))
            else:
                failedtest = True
                failedreasons.append(
                    '%s is used, rather than TLS 1.2' % sslversion)
                sslversion = color.bright(color.red(sslversion))
            print(sslversion)
            print(color.bright('Hosts using %s:' %
                               color.decolorize(sslversion)))
            for host in net.sslversions[color.decolorize(sslversion)]:
                print(host)
        print('')

        for ciphersuite in net.requestedciphers:
            if ciphersuite in net.mandatory_ciphers:
                #ciphersuite = color.bright(color.green(ciphersuite))
                seen_mandatory_ciphers.append(ciphersuite)
            elif ciphersuite in net.optional_ciphers:
                #ciphersuite = color.bright(ciphersuite)
                seen_optional_ciphers.append(ciphersuite)
            else:
                #ciphersuite = color.dim(ciphersuite)
                seen_other_ciphers.append(ciphersuite)

        if len(seen_mandatory_ciphers) == 0:
            failedtest = True
            failedreasons.append(
                '%s is not supported by client' % net.mandatory_ciphers[0])

        print(
            color.bright('Observed mandatory ciphers in TLS/SSL client requests:'))
        for cipher in seen_mandatory_ciphers:
            print(color.bright(color.green(cipher)))
        report['seen_mandatory_ciphers'] = seen_mandatory_ciphers
        print('')
        print(
            color.bright('Observed optional ciphers in TLS/SSL client requests:'))
        for cipher in seen_optional_ciphers:
            print(cipher)
        report['seen_optional_ciphers'] = seen_optional_ciphers
        print('')
        print(
            color.bright('Observed other ciphers in TLS/SSL client requests:'))
        for cipher in seen_other_ciphers:
            print(color.dim(cipher))
        report['seen_other_ciphers'] = seen_other_ciphers
        print('')

        print(color.bright('Negotiated TLS/SSL ciphers:'))

        for ciphersuite in net.negotiatedciphers:
            if ciphersuite in net.mandatory_ciphers:
                ciphersuite = color.bright(color.green(ciphersuite))
            elif ciphersuite in net.optional_ciphers:
                pass
                #ciphersuite = color.bright(ciphersuite)
            else:
                ciphersuite = color.dim(ciphersuite)

            print(ciphersuite)
            print(color.bright('Hosts using %s:' %
                               color.decolorize(ciphersuite)))
            for host in net.negotiatedciphers[color.decolorize(ciphersuite)]:
                print(host)
            print('')
        print('')
    else:
        print(color.bright(color.green('No TLS/SSL traffic seen')))
        print('')

    if net.dtlspacketcount > 0:
        print(color.bright('DTLS protocols used:'))

        # For each target (unsorted)
        for dtlsversion in net.dtlsversions:
            if dtlsversion == 'DTLS 1.2':
                dtlsversion = color.bright(color.green(dtlsversion))
            else:
                failedtest = True
                failedreasons.append(
                    '%s is used, rather than DTLS 1.2' % dtlsversion)
                dtlsversion = color.bright(color.red(dtlsversion))
            print(dtlsversion)
            print(color.bright('Hosts using %s:' %
                               color.decolorize(dtlsversion)))
            for host in net.dtlsversions[color.decolorize(dtlsversion)]:
                print(host)
        print('')

        report['dtlsciphers'] = net.requesteddtlsciphers
        for ciphersuite in net.requesteddtlsciphers:
            if ciphersuite in net.mandatory_ciphers:
                #ciphersuite = color.bright(color.green(ciphersuite))
                seen_mandatory_ciphers.append(ciphersuite)
            elif ciphersuite in net.optional_ciphers:
                #ciphersuite = color.bright(ciphersuite)
                seen_optional_ciphers.append(ciphersuite)
            else:
                #ciphersuite = color.dim(ciphersuite)
                seen_other_ciphers.append(ciphersuite)

        if len(seen_mandatory_ciphers) == 0:
            failedtest = True
            failedreasons.append(
                '%s is not supported by client' % net.mandatory_ciphers[0])

        print(
            color.bright('Observed mandatory ciphers in DTLS client requests:'))
        for cipher in seen_mandatory_ciphers:
            print(color.bright(color.green(cipher)))
        print('')
        report['seen_mandatory_dtls_ciphers'] = seen_mandatory_ciphers
        print(
            color.bright('Observed optional ciphers in DTLS client requests:'))
        for cipher in seen_optional_ciphers:
            print(cipher)
        print('')
        report['seen_optional_dtls_ciphers'] = seen_optional_ciphers
        print(color.bright('Observed other ciphers in DTLS client requests:'))
        for cipher in seen_other_ciphers:
            print(color.dim(cipher))
        print('')
        report['seen_other_dtls_ciphers'] = seen_other_ciphers

        print(color.bright('Negotiated DTLS ciphers:'))
        for ciphersuite in net.negotiateddtlsciphers:
            if ciphersuite in net.mandatory_ciphers:
                ciphersuite = color.bright(color.green(ciphersuite))
            elif ciphersuite in net.optional_ciphers:
                pass
                #ciphersuite = color.bright(ciphersuite)
            else:
                ciphersuite = color.dim(ciphersuite)

            print(ciphersuite)
            print(color.bright('Hosts using %s:' %
                               color.decolorize(ciphersuite)))
            for host in net.negotiateddtlsciphers[color.decolorize(ciphersuite)]:
                print(host)
            print('')
        print('')

    else:
        print(color.bright(color.green('No DTLS traffic seen')))

    report['failedtest'] = failedtest
    report['failedreasons'] = failedreasons
    if failedtest:
        print(
            color.bright(color.red('App %s failed crypto checking because:' % app)))
        for reason in failedreasons:
            print(color.bright(color.red(reason)))
    else:
        print(color.bright(color.green('App %s passed crypto checking' % app)))

    # print(report)

    with open(jsonfile, 'w') as fp:
        json.dump(report, fp)


def check_app(app, force=False):
    '''
    Check application based on app name in Tapioca results
    '''

    dnscacheloaded = False
    largewarned = False

    # Get pcap file location
    if app.endswith('.pcap'):
        pcapfile = app
        if os.path.exists(pcapfile):
            sys.stdout = Logger('%s.%s' % (pcapfile, report_output))
    else:
        pcapfile = os.path.join('results', app, 'tcpdump.pcap')
        if os.path.exists(pcapfile):
            sys.stdout = Logger(os.path.join('results', app, report_output))

    if os.path.exists(pcapfile):

        pcapdir = os.path.dirname(pcapfile)
        dnspkl = os.path.join(pcapdir, '.dnsmap.pkl')

        eprint(color.bright('Checking app %s...' % color.cyan(app)))

        if os.path.exists(dnspkl) and not force:
            eprint('Loading cached DNS info...')
            with open(dnspkl, 'rb') as pklhandle:
                try:
                    net.dnsmap = pickle.load(pklhandle)
                    dnscacheloaded = True
                except:
                    pass

        if not dnscacheloaded:
            if os.path.getsize(pcapfile) > 100000000:
                # Over 100MB
                eprint(
                    color.bright(color.yellow('Warning: capture size is large. Please be patient.')))
                largewarned = True

            # Get captured DNS info for IP addresses
            eprint('Getting DNS info...')
            dnspackets = pyshark.FileCapture(
                pcapfile, keep_packets=False, display_filter='dns')
            dnspackets.apply_on_packets(net.get_dns_info, timeout=1000)
            with open(dnspkl, 'wb') as pklhandle:
                pickle.dump(
                    net.dnsmap, pklhandle, protocol=pickle.HIGHEST_PROTOCOL)

        if os.path.getsize(pcapfile) > 100000000 and not largewarned:
            # Over 100MB
            eprint(
                color.bright(color.yellow('Warning: capture size is large. Please be patient.')))
            largewarned = True

        sslpackets = pyshark.FileCapture(
            pcapfile, keep_packets=False, display_filter='ssl')

        eprint('Getting SSL info from capture...')
        # get_indexed_ssl_info(cap)
        sslpackets.apply_on_packets(net.get_ssl_info, timeout=1000)

        dtlspackets = pyshark.FileCapture(
            pcapfile, keep_packets=False, display_filter='dtls')

        eprint('Getting DTLS info from capture...')
        dtlspackets.apply_on_packets(net.get_dtls_info, timeout=1000)

        # Print report
        generate_report(app, pcapfile=pcapfile)

        # Reset globals
        net.clear()


def main():

    parser = argparse.ArgumentParser(
        description='Validate cryptography used by one or more tested application')
    parser.add_argument('app_or_capture', metavar='appname', nargs='?',
                        help='Application name or network capture file')
    parser.add_argument('--verbose', dest='verbose', action='store_true',
                        help='display packet contents')
    parser.add_argument('-f', '--force', dest='force', action='store_true',
                        #                    const=sum, default=max,
                        help='Force re-parsing of capture file')
    args = parser.parse_args()

    app = args.app_or_capture

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

    if args.app_or_capture:
        # Check only one app
        check_app(args.app_or_capture, force=args.force)
    else:
        # Check all apps tested
        for entry in os.listdir('results'):
            if os.path.isdir(os.path.join('results', entry)):
                app = entry
                check_app(app, force=args.force)
            elif os.path.isdir(os.path.join('results', entry.lower())):
                app = entry
                check_app(app, force=args.force)

if __name__ == "__main__":
    main()
