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

from __future__ import print_function
import sys
import os
import pickle
import pyshark
import color
import argparse
import base64
import hashlib
import json
import re
from shutil import copy2
from mitmproxy import io
from misc import eprint, Logger

pcapfile = 'tcpdump.pcap'
fullmitmfile = 'flows.log'
ssltestfile = 'ssltest.log'
report_output = 'search.txt'
json_output = 'search.json'
args = ''

searchterm = ''
verbose = False
found = False
foundunenc = False
foundunprot = False
foundprot = False


def isstr(s):
    str = ''
    try:
        str = s.decode('UTF-8', errors='strict')
        return True
    except UnicodeError:
        return False


def decodecontent(content):
    if isstr(content):
        return content
    else:
        try:
            decoded = content.decode()
            if isstr(decoded):
                return decoded
        except:
            #print('Not a string!')
            return ''


def get_search_results(pkt):
    '''
    Parse through packets that match tshark filter for search
    '''
    global found, foundunenc, searchterm

    # Searches are case insensitive
    pcre = re.compile('(?i)' + searchterm)
    print(color.green(color.bright('Found match in %s packet [%d] (%s):' %
                                   (pcapfile, int(pkt.number), pkt.highest_layer))))
    found = True
    foundunenc = True

    for layer in pkt.layers:
        for field_line in layer._get_all_field_lines():
            if pcre.search(field_line):
                print('%s: %s' % (layer.layer_name, field_line.rstrip()))
                print(
                    color.bright(color.red('%s found in unencrypted %s traffic!' % (searchterm, pkt.highest_layer))))

    if args.verbose:
        print('----- Full packet dump begin -----')
        print(pkt)
        print('----- Full packet dump end -------')


def searchtcpdump(pcapfile, searchterm):
    # Do case insensitve tshark display filter
    matchingpackets = pyshark.FileCapture(
        pcapfile, display_filter='frame matches "(?i)%s"' % searchterm)

    matchingpackets.apply_on_packets(get_search_results, timeout=1000)


def searchmitmflow(flowfile, searchterm):
    global found, foundunprot, foundprot

    # Searches are case insensitive
    pcre = re.compile('(?i)' + searchterm)

    # Create a dictionary of all of the messages in the flow
    with open(flowfile, 'rb') as logfile:
        fr = io.FlowReader(logfile)
        msgnum = 0
        flowdict = {}
        messages = []
        for msg in fr.stream():
            messagedict = {}
            responsedict = {}
            requestdict = {}

            messagedict['msgnum'] = msgnum

            requestdict['uri'] = msg.request.pretty_url
            requestdict['method'] = msg.request.method
            requestdict['scheme'] = msg.request.scheme
            requestdict['headers'] = msg.request.headers
            requestcontent = msg.request.content
            decodedcontent = decodecontent(requestcontent)
            if decodedcontent:
                # mitmproxy found a way to decode the content
                requestdict['content'] = decodedcontent
            else:
                # just take the raw bytes
                requestdict['content'] = requestcontent

            try:
                responsedict['headers'] = msg.response.headers
            except AttributeError:
                responsedict['headers'] = ''
            try:
                responsecontent = msg.response.content
            except AttributeError:
                responsecontent = ''
            try:
                decodedcontent = decodecontent(responsecontent)
                if decodedcontent:
                    # mitmproxy found a way to decode the content
                    responsedict['content'] = decodecontent(responsecontent)
                else:
                    # just take the raw bytes
                    responsedict['content'] = responsecontent

            except AttributeError:
                responsedict['content'] = ''

            messagedict['request'] = requestdict
            messagedict['response'] = responsedict
            # print(messagedict)
            messages.append(messagedict)
            msgnum = msgnum + 1
    flowdict['messages'] = messages

    # Check for matches in the flow dictionary
    for message in flowdict['messages']:
        msgnum = message['msgnum']
        for key in message:

            if key == 'msgnum':
                continue
            else:
                for value in message[key].values():
                    if pcre.search(str(value)):
                        found = True
                        print(color.bright(color.green('Found match for %s in %s message [%s] field [%s]:' %
                                                       (searchterm, flowfile, msgnum + 1, key))))
                        if message['request']['scheme'] == 'https':
                            if flowfile.endswith('ssltest.log'):
                                foundunprot = True
                                print(
                                    color.bright(color.red('%s found in non-validated HTTPS traffic!' % searchterm)))
                            elif flowfile.endswith('flows.log'):
                                foundprot = True
                                color.bright(
                                    '%s found in validated HTTPS traffic' % searchterm)
                        elif message['request']['scheme'] == 'http':
                            foundunenc = True
                            print(
                                color.bright(color.red('%s found in unencrypted HTTP traffic!' % searchterm)))
                        print(str(value))


def check_multi(app, searchterm):

    # As-is
    check_app(app, searchterm)

    # base64
    encsearchterm = base64.b64encode(
        searchterm.encode('ascii')).decode('ascii')
    check_app(app, encsearchterm, 'base64')

    # md5
    encsearchterm = hashlib.md5(searchterm.encode('ascii')).hexdigest()
    check_app(app, encsearchterm, 'md5')

    # sha1
    encsearchterm = hashlib.sha1(searchterm.encode('ascii')).hexdigest()
    check_app(app, encsearchterm, 'sha1')

    # sha256
    #encsearchterm = hashlib.sha256(searchterm.encode('ascii')).hexdigest()
    #check_app(app, encsearchterm)


def print_header(logfile):
    global pcapfile, fullmitmfile, ssltestfile
    traffictype = ''
    logfile = os.path.basename(logfile)
    if logfile == pcapfile:
        traffictype = 'unencrypted'
    elif logfile == fullmitmfile:
        traffictype = 'protected HTTPS'
    elif logfile == ssltestfile:
        traffictype = 'UNPROTECTED HTTPS'
    print(
        color.bright('===== Search hits in %s traffic below =====' % traffictype))


def check_app(app, searchterm, encoding='string'):
    '''
    Check application based on app name in Tapioca results
    '''

    global pcapfile, ssltestfile, fullmitmfile
    global found, foundunprot, foundprot, foundunenc
    ssltesttime = None
    fullmitmtime = None
    pcaptime = None
    appbase = os.path.basename(app)

    # Get pcap file location
    if appbase == ssltestfile or app == fullmitmfile:
        # Check mitmproxy log
        logfile = app
        jsonfile = '%s.%s' % (app, json_output)
        if os.path.exists(logfile):
            if appbase == ssltestfile:
                ssltesttime = os.path.getmtime(app)
            elif appbase == fullmitmfile:
                fullmitmtime = os.path.getmtime(app)
            print_header(logfile)
            print(color.bright('searching %s for %s (%s)') %
                  (color.cyan(logfile), searchterm, encoding))
            searchmitmflow(logfile, searchterm)
            print('')
    elif appbase.endswith('.pcap'):
        # Check tcpdump pcap
        logfile = app
        jsonfile = '%s.%s' % (app, json_output)
        if os.path.exists(logfile):
            pcaptime = os.path.getmtime(app)
            print_header(logfile)
            print(color.bright('searching %s for %s (%s)') %
                  (color.cyan(logfile), searchterm, encoding))
            searchtcpdump(logfile, searchterm)
            print('')
    else:
        # check app (all captures availabale)
        appdir = os.path.join('results', app)
        jsonfile = os.path.join(appdir, json_output)

        # app name, so check all three
        logfile = os.path.join('results', app, pcapfile)
        if os.path.exists(logfile):
            pcaptime = os.path.getmtime(logfile)
            print_header(logfile)
            print(color.bright('searching %s for %s (%s)') %
                  (color.cyan(logfile), searchterm, encoding))
            searchtcpdump(logfile, searchterm)
            print('')

        logfile = os.path.join('results', app, ssltestfile)
        if os.path.exists(logfile):
            ssltesttime = os.path.getmtime(logfile)
            print_header(logfile)
            print(color.bright('searching %s for %s (%s)') %
                  (color.cyan(logfile), searchterm, encoding))
            searchmitmflow(logfile, searchterm)
            print('')

        logfile = os.path.join('results', app, fullmitmfile)
        if os.path.exists(logfile):
            fullmitmtime = os.path.getmtime(logfile)
            print_header(logfile)
            print(color.bright('searching %s for %s (%s)') %
                  (color.cyan(logfile), searchterm, encoding))
            searchmitmflow(logfile, searchterm)
            print('')

        report = {}
        report['app'] = app
        report['pcaptime'] = pcaptime
        report['ssltesttime'] = ssltesttime
        report['fullmitmtime'] = fullmitmtime
        report['searchterm'] = searchterm
        report['found'] = found
        report['foundunenc'] = foundunenc
        report['foundunprot'] = foundunprot
        report['foundprot'] = foundprot

        with open(jsonfile, 'w') as fp:
            json.dump(report, fp)


def get_search_outname(searchterm):
    # Remove non-nice characters, since we're using them in a filename
    report_parts = report_output.split('.')
    outname = report_parts[
        0] + '_' + re.sub(r'\W+', '', searchterm).lower() + '.' + report_parts[-1]
    return outname


def main():
    global args, searchterm

    parser = argparse.ArgumentParser(
        description='Search captured traffic for a pattern')
    parser.add_argument('app_or_capture', metavar='appname',
                        help='Application name or network capture file')
    parser.add_argument(
        'searchterm', type=str, help='String to search for')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='display packet contents')
    parser.add_argument('-m', '--multi', dest='multi', action='store_true',
                        help='search multiple encodings')

    args = parser.parse_args()

    app = args.app_or_capture
    searchterm = args.searchterm
    appdir = os.path.join('results', app)
    search_output = get_search_outname(searchterm)
    if os.path.isdir(appdir):
        sys.stdout = Logger(os.path.join(appdir, search_output))

    if args.app_or_capture:
        # Check only one app
        # Option to use full packets perhaps specified
        if args.multi:
            check_multi(app, searchterm)
        else:
            check_app(app, searchterm)
    else:
        # Check all apps tested
        for entry in os.listdir('results'):
            if os.path.isdir(os.path.join('results', entry)):
                app = entry
                if args.multi:
                    check_multi(app, searchterm)
                else:
                    check_app(app, searchterm)
            elif os.path.isdir(os.path.join('results', entry.lower())):
                app = entry
                if args.multi:
                    check_multi(app, searchterm)
                else:
                    check_app(app, searchterm)
    print('')
    # Flush stdout log file
    sys.stdout = sys.__stdout__
    # Copy log file to universally-named one
    copy2(os.path.join(appdir, search_output),
          os.path.join(appdir, report_output))
    eprint(color.bright('Done!'))


if __name__ == "__main__":
    main()
