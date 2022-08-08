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
#
# Simple script showing how to read a mitmproxy dump file
#

from __future__ import print_function
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
import pprint
import sys
import os
import color
import argparse
import json
from misc import eprint, Logger

report_output = 'ssltest.txt'
json_output = 'ssltest.json'

ssl_passed = []
ssl_failed = []
ssl_notest = []


def check_app(app):
    failedssltest = False
    badrequests = []

    # Get mitmproxy log file location
    if app.endswith('.log'):
        flowfile = app
        jsonfile = '%s.%s' % (flowfile, json_output)
        if os.path.exists(flowfile):
            sys.stdout = Logger('%s.%s' % (flowfile, report_output))
    else:
        flowfile = os.path.join('results', app, 'ssltest.log')
        jsonfile = os.path.join(os.path.dirname(flowfile), json_output)
        if os.path.exists(flowfile):
            sys.stdout = Logger(os.path.join('results', app, report_output))

    if os.path.exists(flowfile):
        badsslmsgs = []

        with open(flowfile, "rb") as logfile:
            freader = io.FlowReader(logfile)
            pp = pprint.PrettyPrinter(indent=4)
            try:
                for msg in freader.stream():
                    scheme = msg.request.scheme
                    if scheme == 'https':
                        failedssltest = True
                        badsslmsgs.append(msg)
                if failedssltest:
                    ssl_failed.append(app)
                    print(
                        color.bright('%s fails to validate SSL certificates properly' % app))
                    print('Offending URIs accessed:')
                    for msg in badsslmsgs:
                        method = msg.request.method
                        uri = msg.request.pretty_url
                        request = '%s %s' % (method, uri)
                        badrequests.append(request)
                        request = color.bright(color.red((request)))
                        print(request)
                else:
                    print('No HTTPS traffic detected for app %s' % app)
                    ssl_passed.append(app)
            except FlowReadException as e:
                print("Flow file corrupted: {}".format(e))

        report = {}
        report['app'] = app
        report['testtime'] = os.path.getmtime(flowfile)
        report['failedtest'] = failedssltest
        report['ssl_failed'] = badrequests

        with open(jsonfile, 'w') as fp:
            json.dump(report, fp)

    else:
        ssl_notest.append(app)


def main():

    parser = argparse.ArgumentParser(
        description='Verify SSL certificate validation for one or more tested application')
    parser.add_argument('app_or_capture', metavar='appname', nargs='?',
                        help='Application name or network capture file')
    args = parser.parse_args()

    app = args.app_or_capture

    if args.app_or_capture:
        check_app(app)
    else:
        for entry in os.listdir('results'):
            if os.path.isdir(os.path.join('results', entry)):
                app = entry
                check_app(app)

        eprint('')
        eprint(color.bright('SSL test summary:'))
        eprint(color.bright(color.red(('Failed:'))))
        for app in ssl_failed:
            eprint(app)
        if ssl_notest:
            eprint(color.bright('Not tested:'))
            for app in ssl_notest:
                eprint(app)
        eprint(color.bright(color.green(('Passed:'))))
        for app in ssl_passed:
            eprint(app)


if __name__ == "__main__":
    main()
