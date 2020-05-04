#!/usr/bin/python
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


import subprocess
import re
import sys
import os
try:
    import wx
    import dialogs
except ImportError:
    import qt5dialogs as dialogs


def main():
    try:
        # Initialize wx App
        app = wx.App()
        app.MainLoop()
    except NameError:
        # We're using Qt5 dialogs
        pass

    if os.path.isfile('.lastapp'):
        with open('.lastapp', 'r') as lastfile:
            lastapp = lastfile.read()
    else:
        lastapp = ''

    # Call Dialog
    appname = dialogs.Ask(
        message='What application is being tested?', default_value=lastapp)
    testapp(appname, standalone=True)


def testapp(appname, standalone=False):
    outdir = './logs'
    overwrite = False

    appname = re.sub(r'\W+', '', appname).lower()
    with open('.lastapp', 'w+') as lastfile:
        lastfile.write(appname)

    if appname != '':
        outdir = './results/%s' % appname
        flowsfile = '%s/tcpdump.pcap' % outdir
        if os.path.isfile(flowsfile) and standalone:
            overwrite = dialogs.YesNo(
                question='Output file %s already exists. Continue?' % flowsfile)
            if not overwrite:
                sys.exit()

    subprocess.call(['./tcpdump.sh', outdir])

if __name__ == "__main__":
    main()
