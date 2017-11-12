#!/usr/bin/env python

# Copyright (c) 2009, Giampaolo Rodola'. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file here https://github.com/giampaolo/psutil/blob/master/LICENSE

"""
A clone of 'netstat -antp' on Linux.

Proto Local address      Remote address   Status        PID    Program name
tcp   127.0.0.1:48256    127.0.0.1:45884  ESTABLISHED   13646  chrome
tcp   127.0.0.1:47073    127.0.0.1:45884  ESTABLISHED   13646  chrome
tcp   127.0.0.1:47072    127.0.0.1:45884  ESTABLISHED   13646  chrome
tcp   127.0.0.1:45884    -                LISTEN        13651  GoogleTalkPlugi
tcp   127.0.0.1:60948    -                LISTEN        13651  GoogleTalkPlugi
tcp   172.17.42.1:49102  127.0.0.1:19305  CLOSE_WAIT    13651  GoogleTalkPlugi
tcp   172.17.42.1:55797  127.0.0.1:443    CLOSE_WAIT    13651  GoogleTalkPlugi
...
"""

import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM

import psutil

AD = "-"
AF_INET6 = getattr(socket, 'AF_INET6', object())
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}


class Application:
    def __init__(self):
        self.name = ''
        self.pid = ''
        self.ip = []
        self.pubip = []
        self.proto = []
        self.status = []

    def set(self, ip, pubip, pid, name, proto, status):
        self.name = name
        self.pid = pid
        self.add(ip, pubip, proto, status)

    def add(self, ip, pubip, proto, status):
        self.ip.append(ip)
        self.pubip.append(pubip)
        self.proto.append(proto)
        self.status.append(status)


def get_applications():
    proc_names = {}
    apps = {}  # apps[pid]
    for p in psutil.process_iter(attrs=['pid', 'name']):
        proc_names[p.info['pid']] = p.info['name']
    for c in psutil.net_connections(kind='inet'):
        laddr = "%s:%s" % c.laddr
        raddr = ""
        if c.raddr:
            raddr = "%s:%s" % c.raddr

        pid = c.pid or AD
        if pid in apps.keys():
            apps[pid].add(laddr, raddr or AD, proto_map[(c.family, c.type)], c.status)
        else:
            apps[pid] = Application()
            apps[pid].set(laddr, raddr, pid, proc_names.get(c.pid, '?')[:15], proto_map[(c.family, c.type)], c.status)
    return apps
