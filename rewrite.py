#####################################################
##  Content rewriting script for mitmproxy 4
##  Other versions of mitmproxy may not be compatible
#####################################################
#
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

# See https://github.com/mitmproxy/mitmproxy/tree/master/examples for more
# examples as to what you can do with mitmproxy scripts
# This file can be edited while mitmproxy is running. It will pick up changes
# on file save

from mitmproxy import http

req_before = 'Content to find in intercepted requests'
req_after = 'Content to replace the above with'
resp_before = 'Content to find in intercepted responses'
resp_after = 'Content to replace the above with'

#calcbytes = None
#with open("calc.exe", "rb") as f:
#    calcbytes = f.read()

def response(flow: http.HTTPFlow) -> None:
    try:
        # Older mitmproxy version
        flow.response.replace(resp_before, resp_after)
    except AttributeError:
        # Newer mitmproxy version
        # https://stackoverflow.com/questions/64111152/issue-converting-older-mitmproxy-scripts-to-work-on-5-2-error-on-replace-and-c
        if flow.response.content:
            try:
                # Try binary replacement first
                flow.response.content = flow.response.content.replace(resp_before, resp_after)
            except TypeError:
                # Then fall back to text replacement
                flow.response.text = flow.response.text.replace(resp_before, resp_after)

def request(flow: http.HTTPFlow) -> None:
    try:
        # Older mitmproxy version
        flow.request.replace(req_before, req_after)
    except AttributeError:
        # Newer mitmproxy version
        if flow.request.content:
            try:
                # Try binary replacement first
                flow.request.content = flow.request.content.replace(req_before, req_after)
            except TypeError:
                # Then fall back to text replacement
                flow.request.text = flow.request.text.replace(req_before, req_after)
    #flow.request.headers['User-Agent'] = 'Custom User-Agent'

## Below is an example that will answer any question for a URI that ends in '.exe'
## with the bytes from calc.exe (uncomment the above as well)
#    if flow.request.method == 'GET' and flow.request.url.endswith('.exe'):
#        flow.response = http.HTTPResponse.make(
#            200,  # (optional) status code
#            calcbytes,  # (optional) content
#            {'Content-Type': 'application/octet-stream'}  # (optional) headers
#        )
