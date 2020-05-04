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

    if not os.path.isfile('.killapp'):
        # Call Dialog
        dialogs.Info(
            message='Be sure to terminate the application under test between tests!')
        with open('.killapp', 'w+') as killapp:
            killapp.write('')

    subprocess.call(['xfce4-terminal', '--disable-server', '-T', 'Proxy reset',  '-e', './noproxy.sh'])


if __name__ == "__main__":
    main()
