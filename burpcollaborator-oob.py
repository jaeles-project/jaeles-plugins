#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
This is proxy parser
run: mitmdump -q -p 8667 -s this_file.py
'''

import os
import sys
import json
import time

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

from mitmproxy import http
import mitmproxy.connections
from pprint import pprint


print('''
[Instructions]

# Route traffic through proxy:
    Burp -> Project Options -> Connections -> Upstream Proxy Server
    Add new proxy rule to this script: * | 127.0.0.1 | 8667
    Run command: mitmdump -q -p 8667 -s burpcollaborator-oob.py

# Get burpcollaborator secret:
    Burp -> Project Options -> Connections -> Mics -> -> Burp Collaborator Server
    Check on Poll over unencrypted HTTP.
    Not open Collaborator Client and click Poll now.
    Not copy as many collab as need to be and store it in a file.

# Note:
    Default log will be store in ./collaborator.json

''')
print('-'*50)

polling_host = 'polling.burpcollaborator.net'
default_log = os.path.join(CURRENT_DIR, 'collaborator.json')


class Analyze:
    def load(self, entry: mitmproxy.addonmanager.Loader):
        self.secret = None
        self.hosts = []

    # def clientconnect(self, layer: mitmproxy.proxy.protocol.Layer):
    #     self.secret = None
    #     self.hosts = []


    def request(self, flow: http.HTTPFlow):
        # Avoid an infinite loop by not replaying already replayed requests
        if flow.request.is_replay:
            return
        flow_dup = flow.copy()
        req_data = flow_dup.request

        pretty_url = req_data.pretty_url
        print('----> {0}'.format(pretty_url))
        if polling_host in pretty_url:
            secret = req_data.query.get('biid', None)
            if secret and secret != 'test':
                self.secret = secret
                print(
                    "[+] Found burpcollaborator polling secret: {0}".format(self.secret))

        elif pretty_url.endswith('.burpcollaborator.net/'):
            self.hosts.append(req_data.pretty_host)
            print(pretty_url)

    def write_log(self, secret, hosts):
        collab_log = self.load_log()

        if collab_log.get('secret', None):
            collab_log[secret].extend(hosts)
        else:
            collab_log[secret] = hosts

        # just clean it up
        for key in collab_log.keys():
            collab_log[key] = list(set(collab_log[key]))

        # store log again
        with open(default_log, 'w+') as f:
            json.dump(collab_log, f)

    def load_log(self):
        if os.path.isfile(default_log):
            with open(default_log, 'r+') as log:
                collab_log = json.loads(log.read())
        else:
            collab_log = {}

        return collab_log

    # save record to db
    def serverdisconnect(self, conn: mitmproxy.connections.ServerConnection):
        if self.secret:
            print('[+] Store log for: {0}'.format(self.secret))
            self.write_log(self.secret, self.hosts)
            print('-'*40)
        # clean up
        self.secret = None
        self.hosts = []


addons = [Analyze()]
