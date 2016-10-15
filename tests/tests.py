# coding: utf-8
# Copyright (c) Alexandre Syenchuk, 2016

import re

from bott import models as M
from django.test import TestCase

class TestNetwork(TestCase):
    def setUp(self):
        network = M.Network()
        network.name = "Main network"
        network.sess_start_id = 1
        network.management_start_port = 5000
        network.source_ip_tpl = '192.168.%(uid2)d.%(uid1)d'
        network.device_tpl = 'tun%(uid)d'
        network.log_path = '/var/log/main_network/'
        network.openvpn_cmd_tpl = re.sub(r'\s+', ' ', """
            /usr/sbin/openvpn --daemon --dev %(dev)s
            --management 127.0.0.1 %(management_port)d --management-query-passwords
            --remote %(server_ip)s %(server_port)d
            --config %(config_file)s --log %(network_log_path)s%(provider_log_path)s
            %(extra)s
        """).strip()
        network.full_clean()
        network.save(force_insert=True)

        provider = M.Provider(network=network)
        provider.name = 'HMA'
        provider.ovpn_extra = ''
        provider.log_path_tpl = 'vpn%(id)d.log'
        provider.config_file = '/etc/openvpn/hma/client.conf'
        provider.sess_per_account = 2
        provider.ip_blacklist_delay = 10800
        provider.offline_delay = 30
        provider.intercon_delay = 150
        provider.con_timeout = 20
        provider.sock_timeout = 5
        provider.http_timeout = 10
        provider.sess_timeout = 10
        provider.sess_init_timeout = 2
        provider.full_clean()
        provider.save(force_insert=True)

        account = M.Account(provider=provider)
        account.username = 'alexpirine'
        account.password = 'oZLjb1YldyqgvuNSdwhn'
        account.full_clean()
        account.save(force_insert=True)

        network.update_slots()

        region = M.Region(provider=provider)
        region.name = "Europe"
        region.full_clean()
        region.save(force_insert=True)

        location = M.Location(region=region)
        location.name = "France"
        location.full_clean()
        location.save(force_insert=True)

        server = M.Server(location=location)
        server.ip_address = '62.233.57.2'
        server.port = 443
        server.full_clean()
        server.save(force_insert=True)

        server = M.Server(location=location)
        server.ip_address = '62.233.44.2'
        server.port = 443
        server.full_clean()
        server.save(force_insert=True)

    def test_server_load_balancing(self):
        provider = M.Provider.objects.first()

        session1 = provider.init_session()
        self.assertEqual(session1.status, session1.STATUS_INITIATED)

        session2 = provider.init_session()
        self.assertEqual(session2.status, session2.STATUS_INITIATED)

        self.assertNotEqual(session1.server, session2.server)
        self.assertNotEqual(session1.slot, session2.slot)

    def test_too_many_sessions(self):
        provider = M.Provider.objects.first()

        session1 = provider.init_session()
        self.assertEqual(session1.status, session1.STATUS_INITIATED)

        session2 = provider.init_session()
        self.assertEqual(session2.status, session2.STATUS_INITIATED)

        session3 = provider.init_session()
        self.assertEqual(session3, None)
        self.assertEqual(M.Session.objects.count(), 3)
        self.assertEqual(M.Session.objects.filter(status=M.Session.STATUS_FAILED).count(), 1)
