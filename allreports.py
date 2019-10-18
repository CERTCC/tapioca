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
from __future__ import print_function
import os
import fnmatch
import subprocess
import argparse
import color
import json
from misc import eprint


def run_all(app, analyzers):
    for analyzer in analyzers:
        print(
            color.bright('----- Begin %s report for %s -----' % (analyzer, color.cyan(app))))
        subprocess.call(['./%s' % analyzer, app])
        print(
            color.bright('----- End %s report for %s -------' % (analyzer, color.cyan(app))))
        print('')


def runreports(app):
    analyzers = []

    direntries = os.listdir('.')
    direntries.sort()
    for file in direntries:
        if fnmatch.fnmatch(file, 'check*.py') and file != os.path.basename(__file__):
            analyzers.append(file)

    # Check only one app
    run_all(app, analyzers)
    print('')


def getfailures(app):
    #print('allreports.getstatuses called for %s' % app)
    failures = {}
    reportdict = {}
    reportfiles = [
        'ssltest.json',
        'crypto.json',
        'net.json',
    ]

    for reportfile in reportfiles:
        report = reportfile.replace('.json', '')
        reportpath = os.path.join('results', app, reportfile)
        #print('++ allreports.getstatuses looking for %s' % reportpath)
        if os.path.exists(reportpath):
            #print('+++ found %s' % reportpath)
            with open(reportpath) as jsonfile:
                reportdict[report] = json.load(jsonfile)
                #print('Report[%s]: %s' % (report, reportdict[report]))
                try:
                    failures[report] = reportdict[report]['failedtest']
                except KeyError:
                    # json file doesn't have 'failedtest' for some reason
                    pass
                #print('App %s failed %s' % (app, statuses[report]))
                # print(statuses)
    return failures


def getapps():
    applist = []
    for entry in os.listdir('results'):
        if os.path.isdir(os.path.join('results', entry)):
            applist.append(entry)
        elif os.path.isdir(os.path.join('results', entry.lower())):
            applist.append(entry)
    return applist


def main():

    parser = argparse.ArgumentParser(
        description='Run all reports for one or more tested application')
    parser.add_argument('app_or_capture', metavar='appname', nargs='?',
                        help='Application name or network capture file')
    args = parser.parse_args()

    app = args.app_or_capture

    if args.app_or_capture:
        # Check only one app
        runreports(app)
    else:
        # Check all apps tested
        for app in getapps():
            runreports(app)

    eprint(color.bright('Done!'))


if __name__ == "__main__":
    main()
