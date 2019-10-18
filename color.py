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

"""
Utility methods for writing output to a console.
"""
import re
import sys
from colorama import Fore, Style, AnsiToWin32, init as colorama_init


def color_stream():
    """
    Initializes sys.stdout with `colorama's <https://github.com/tartley/colorama>`_ formatting capabilities.

    :return: a colorized output stream
    :rtype: colorama.ansitowin32.StreamWrapper
    """
    colorama_init(wrap=False)
    return AnsiToWin32(sys.stdout).stream


def colorize(color, string):
    """
    Wraps `string` with the `color` ANSI color code.

    :param color: color to style `string` with
    :type color: colorama.ansi.Fore
    :param string: string to colorize
    :type string: str
    :return: colorized string
    :rtype: str
    """
    return "{}{}{}".format(color, string, Style.RESET_ALL)


# Credit goes to Martijn Pieters (http://stackoverflow.com/users/100297/martijn-pieters)
# From post:
# http://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
_ansi_escape = re.compile(r'\x1b[^m]*m')


def decolorize(string):
    """
    Removes any ANSI color codes from `string`.

    :param string: a string with or without ANSI color codes
    :type string: str
    :return: the string without ANSI color codes
    :rtype: str
    """
    return _ansi_escape.sub('', string)


def red(string):
    """
    Colors `string` red.

    :param string: a string
    :type string: str
    :return: colorized string
    :rtype: str
    """
    return colorize(Fore.RED, string)


def yellow(string):
    """
    Colors `string` yellow.

    :param string: a string
    :type string: str
    :return: colorized string
    :rtype: str
    """
    return colorize(Fore.YELLOW, string)


def green(string):
    """
    Colors `string` green.

    :param string: a string
    :type string: str
    :return: colorized string
    :rtype: str
    """
    return colorize(Fore.GREEN, string)


def blue(string):
    """
    Colors `string` blue.

    :param string: a string
    :type string: str
    :return: colorized string
    :rtype: str
    """
    return colorize(Fore.BLUE, string)


def cyan(string):
    """
    Colors `string` cyan.

    :param string: a string
    :type string: str
    :return: colorized string
    :rtype: str
    """
    return colorize(Fore.CYAN, string)


def bright(string):
    """
    Brightens `string`.

    :param string: a string
    :type string: str
    :return: styled string
    :rtype: str
    """
    return colorize(Style.BRIGHT, string)


def dim(string):
    """
    Dims `string`.

    :param string: a string
    :type string: str
    :return: styled string
    :rtype: str
    """
    return colorize(Style.DIM, string)
