# coding: utf-8
# Copyright (c) Alexandre Syenchuk, 2016

import re
import subprocess

from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.db import transaction
from django.db.models import Case
from django.db.models import Count
from django.db.models import ExpressionWrapper
from django.db.models import F
from django.db.models import When
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from humanize import naturaltime
from random import random
from time import sleep

from .tools import block

#
# Mixins
#

class EditedTimeMixin(models.Model):
    add_date = models.DateTimeField(_("date added"), auto_now_add=True)
    mod_date = models.DateTimeField(_("date edited"), auto_now=True)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if 'update_fields' in kwargs:
            kwargs['update_fields'] = list(set(kwargs['update_fields'] + ['mod_date']))

        return super(EditedTimeMixin, self).save(*args, **kwargs)

class UsedTimeMixin(models.Model):
    used_date = models.DateTimeField(_("date used"), blank=True, null=True, editable=False)

    class Meta:
        abstract = True

    def get_used_display(self):
        return naturaltime(timezone.now() - self.add_date)
    get_used_display.short_description = _("used")

    def mark_used(self):
        self.used_date = timezone.now()
        self.full_clean()
        self.save(update_fields=['used_date'])

class DisabledMixin(models.Model):
    disabled = models.BooleanField(_("disabled"), default=False, db_index=True)
    disabled_date = models.DateTimeField(_("date disabled"), blank=True, null=True, editable=False)
    enabled_date = models.DateTimeField(_("date enabled"), blank=True, null=True, editable=False)

    class Meta:
        abstract = True

    def get_active_display(self):
        return not self.disabled
    get_active_display.short_description = _("active")
    get_active_display.boolean = True

    def save(self, *args, **kwargs):
        if not self.pk:
            if self.disabled:
                self.disabled_date = timezone.now()
            else:
                self.enabled_date = timezone.now()

        return super(DisabledMixin, self).save(*args, **kwargs)

    def disable(self):
        self.disabled = True
        self.disabled_date = timezone.now()
        self.full_clean()
        self.save(update_fields=['disabled', 'disabled_date'])

    def enable(self):
        self.disabled = False
        self.enabled_date = timezone.now()
        self.full_clean()
        self.save(update_fields=['disabled', 'enabled_date'])

class CompleteMixin(EditedTimeMixin, UsedTimeMixin, DisabledMixin, models.Model):
    class Meta:
        abstract = True

class LockableMixin(models.Model):
    class Meta:
        abstract = True

    @transaction.atomic
    def lock(self):
        self.__class__.objects.select_for_update().filter(pk=self.pk).exists()

#
# Models
#

class Network(LockableMixin, models.Model):
    name = models.CharField(_("name"), max_length=255, unique=True)
    sess_start_id = models.PositiveSmallIntegerField(_("sessions start ID"))
    management_start_port = models.PositiveSmallIntegerField(
        _("management port"), validators=[MinValueValidator(1025)], unique=True,
        help_text=_("Management port start number"),
    )
    source_ip_tpl = models.CharField(
        _("source IP"), max_length=30,
        help_text=_("Example: <code>192.168.%(uid2)d.%(uid1)d</code> or <code>192.168.%(id2)d.%(id1)d</code>"),
    )
    device_tpl = models.CharField(_(
        "device"), max_length=20,
        help_text=_(
            "Example: <code>tun%(id)s</code> or <code>tun%(uid)s</code>, "
            "with <b>uid</b> = <b>id</b> + <b>sess_start_id</b>"
        ),
    )
    log_path = models.CharField(
        _("log path"), max_length=255,
        help_text=_("If is a folder, must be ending in <code>/</code>"),
    )
    openvpn_cmd_tpl = models.CharField(
        _("OpenVPN command template"), max_length=255,
        help_text=_(
            "Available variables:<br/>"
            "- <code>%(management_port)d</code> - management port number, <b>management_port</b> = <b>management_start_port</b> + <b>id</b><br/>"
            "- <code>%(dev)s</code> - tun/tap device name<br/>"
            "- <code>%(server_ip)s</code> - VPN server IP address<br/>"
            "- <code>%(server_port)d</code> - VPN server port number<br/>"
            "- <code>%(config_file)s</code> - OpenVPN configuration file<br/>"
            "- <code>%(network_log_path)s</code> - equals to <b>log_path</b><br/>"
            "- <code>%(provider_log_path)s</code> - equals to compiled <b>Provider.log_path_tpl</b><br/>"
            "- <code>%(extra)s</code> - extra arguments specified by the provider<br/>"
            "All new lines will be replaced by spaces"
        ),
    )

    class Meta:
        verbose_name = _("network")
        verbose_name_plural = _("networks")

    def __str__(self):
        return self.name

    @transaction.atomic
    def get_available_slot(self):
        self.lock()

        return self.slots.filter(session=None).first()

    @transaction.atomic
    def update_slots(self):
        self.lock()

        max_slot_id = sum([
            i.slots_num for i in self.providers.only('pk', 'network').filter(
                disabled=False
            ).annotate(
                slots_num=ExpressionWrapper(Count(
                    Case(
                        When(accounts__disabled=False, then=1),
                    )
                ) * F('sess_per_account'), output_field=models.IntegerField()),
            )
        ])

        self.slots.all().delete()
        for k in range(1, max_slot_id+1):
            slot = SessionSlot(network=self, sid=k)
            slot.update()

class SessionSlot(DisabledMixin, models.Model):
    network = models.ForeignKey(Network, verbose_name=_("network"), on_delete=models.CASCADE, related_name='slots')
    sid = models.PositiveSmallIntegerField(_("slot ID"), validators=[MinValueValidator(1)])
    uid = models.PositiveSmallIntegerField(_("unique slot ID"), validators=[MinValueValidator(1)])
    management_port = models.PositiveSmallIntegerField(_("management port"))
    source_ip = models.GenericIPAddressField(_("IP address"), protocol='IPv4')
    device = models.CharField(_("device"), max_length=20)

    class Meta:
        verbose_name = _("session slot")
        verbose_name_plural = _("session slots")
        unique_together = (
            ('network', 'sid'),
            ('network', 'uid'),
            ('network', 'management_port'),
            ('network', 'source_ip'),
            ('network', 'device'),
        )

    def __str__(self):
        return '%d' % self.id

    def get_session_started_display(self):
        try:
            return self.session.get_started_display()
        except Session.DoesNotExist:
            return None
    get_session_started_display.short_description = _("session started")

    def update(self):
        if not self.sid:
            raise ValidationError(_("Slot id is required for update"))
        self.uid = self.network.sess_start_id + self.sid
        self.management_port = self.network.management_start_port + self.sid
        id1 = self.sid - 1
        uid1 = self.uid - 1
        self.source_ip = self.network.source_ip_tpl % {
            'id1': id1 % 250 + 1,
            'id2': 40 + id1 / 250,
            'uid1': uid1 % 250 + 1,
            'uid2': 40 + uid1 / 250,
        }
        self.device = self.network.device_tpl % {
            'id': self.sid,
            'uid': self.uid,
        }
        self.full_clean()
        self.save()

class Provider(CompleteMixin, LockableMixin, models.Model):
    network = models.ForeignKey(Network, verbose_name=_("network"), on_delete=models.CASCADE, related_name='providers')
    name = models.CharField(_("name"), max_length=255, unique=True)
    ovpn_extra = models.CharField(_("extra OpenVPN arguments"), max_length=255, blank=True)
    log_path_tpl = models.CharField(
        _("OpenVPN log path"), max_length=255,
        help_text=_("OpenVPN log file path template; example: <code>vpn%(id)d.log</code>"),
    )
    config_file = models.CharField(_("OpenVPN configuration file"), max_length=255)
    sess_per_account = models.PositiveSmallIntegerField(_("sessions per account"))
    ip_blacklist_delay = models.PositiveIntegerField(_("IP blacklisting duration"))
    offline_delay = models.PositiveSmallIntegerField(_("minimum offline delay"))
    intercon_delay = models.PositiveSmallIntegerField(_("minimum interconnexion delay"))
    con_timeout = models.PositiveSmallIntegerField(_("connection setup timeout"))
    sock_timeout = models.PositiveSmallIntegerField(_("management socket timeout"))
    http_timeout = models.PositiveSmallIntegerField(_("HTTP timeout"))
    sess_timeout = models.PositiveIntegerField(_("session timeout"))
    sess_init_timeout = models.PositiveIntegerField(_("session initiation timeout"))

    class Meta:
        verbose_name = _("VPN provider")
        verbose_name_plural = _("VPN providers")

    def __str__(self):
        return self.name

    def get_available_account(self):
        if self.disabled:
            return None

        return self.accounts.annotate(
            active_sessions=Count(
                Case(
                    When(
                        sessions__status__in=Session.STATUSES_RUNNING,
                        then=1,
                    )
                )
            )
        ).filter(
            disabled=False,
            active_sessions__lt=self.sess_per_account,
        ).order_by(
            'active_sessions'
        ).first()

    def get_available_server(self):
        if self.disabled:
            return None

        return Server.objects.annotate(
            active_sessions=Count(
                Case(
                    When(
                        sessions__status__in=Session.STATUSES_RUNNING,
                        then=1,
                    )
                )
            )
        ).filter(
            disabled=False,
            location__disabled=False,
            location__region__disabled=False,
            location__region__provider=self,
        ).order_by(
            'active_sessions', 'used_date'
        ).first()

    @transaction.atomic
    def get_resources_for_session(self, session):
        self.lock()
        account = self.get_available_account()
        if not account:
            return False
        server = self.get_available_server()
        if not server:
            return False
        slot = self.network.get_available_slot()
        if not slot:
            return False
        session.init(server=server, account=account, slot=slot)
        return True

    def init_session(self):
        def wait():
            wait.backoff *= 1 + random()
            sleep(wait.backoff)
        wait.backoff = 0.5

        session = Session(provider=self)
        session.full_clean()
        session.save(force_insert=True)

        date_start = timezone.now()
        while (timezone.now() - date_start).total_seconds() < self.sess_init_timeout:
            if self.get_resources_for_session(session):
                return session
            else:
                wait()
        else:
            session.fail()

class Region(CompleteMixin, models.Model):
    provider = models.ForeignKey(Provider, verbose_name=_("provider"), on_delete=models.CASCADE, related_name='regions')
    name = models.CharField(_("name"), max_length=255)

    class Meta:
        verbose_name = _("region")
        verbose_name_plural = _("regions")
        unique_together = ('provider', 'name')

    def __str__(self):
        return self.name

class Location(CompleteMixin, models.Model):
    region = models.ForeignKey(Region, verbose_name=_("region"), on_delete=models.CASCADE, related_name='locations')
    name = models.CharField(_("name"), max_length=255)

    class Meta:
        verbose_name = _("location")
        verbose_name_plural = _("locations")
        unique_together = ('region', 'name')

    def __str__(self):
        return self.name

    @transaction.atomic
    def mark_used(self):
        super(Location, self).mark_used()
        self.region.mark_used()

class Server(CompleteMixin, models.Model):
    location = models.ForeignKey(Location, verbose_name=_("location"), on_delete=models.CASCADE, related_name='servers')
    ip_address = models.GenericIPAddressField(_("IP address"), protocol='IPv4')
    port = models.PositiveSmallIntegerField(
        _("port"),
        help_text=_("Server port, for instance 443")
    )

    class Meta:
        verbose_name = _("server")
        verbose_name_plural = _("servers")
        unique_together = ('location', 'ip_address')

    def __str__(self):
        return self.ip_address

    @transaction.atomic
    def mark_used(self):
        super(Server, self).mark_used()
        self.location.mark_used()

class Account(CompleteMixin, models.Model):
    provider = models.ForeignKey(Provider, verbose_name=_("provider"), on_delete=models.CASCADE, related_name='accounts')
    username = models.CharField(_("username"), max_length=255)
    password = models.CharField(_("password"), max_length=255)

    class Meta:
        verbose_name = _("VPN account")
        verbose_name_plural = _("VPN accounts")
        unique_together = ('provider', 'username')

    def __str__(self):
        return self.username

    @transaction.atomic
    def mark_used(self):
        super(Account, self).mark_used()
        self.provider.mark_used()

class Session(EditedTimeMixin, models.Model):
    STATUS_REQUESTED = 1
    STATUS_INITIATED = 2
    STATUS_ACTIVE = 3
    STATUS_CLOSED = 4
    STATUS_FAILED = 0

    STATUSES_RUNNING = [STATUS_INITIATED, STATUS_ACTIVE]

    STATUS_CHOICES = (
        (STATUS_REQUESTED, _("requested")),
        (STATUS_INITIATED, _("initiated")),
        (STATUS_ACTIVE, _("active")),
        (STATUS_CLOSED, _("closed")),
        (STATUS_FAILED, _("failed")),
    )

    provider = models.ForeignKey(Provider, verbose_name=_("provider"), on_delete=models.CASCADE, related_name='sessions')
    server = models.ForeignKey(Server, verbose_name=_("server"), on_delete=models.CASCADE, related_name='sessions', blank=True, null=True)
    account = models.ForeignKey(Account, verbose_name=_("account"), on_delete=models.CASCADE, related_name='sessions', blank=True, null=True)
    slot = models.OneToOneField(SessionSlot, verbose_name=_("slot"), on_delete=models.SET_NULL, related_name='session', blank=True, null=True)
    status = models.PositiveSmallIntegerField(_("status"), choices=STATUS_CHOICES, default=STATUS_REQUESTED)
    ovpn_cmd = models.TextField(_("OpenVPN compiled command"), blank=True, editable=False)
    ovpn_pid = models.PositiveSmallIntegerField(_("OpenVPN PID"), null=True, editable=False)
    ovpn_ret = models.PositiveSmallIntegerField(_("OpenVPN return code"), null=True, editable=False)
    error = models.CharField(_("error message"), max_length=255, blank=True, editable=False)

    class Meta:
        verbose_name = _("VPN session")
        verbose_name_plural = _("VPN sessions")

    def __str__(self):
        return "%d" % self.pk

    def clean(self):
        self.ovpn_cmd = re.sub(r'\s+', ' ', self.ovpn_cmd)

    def get_started_display(self):
        return naturaltime(timezone.now() - self.add_date)
    get_started_display.short_description = _("started")

    @transaction.atomic
    def fail(self, error=None):
        self.status = self.STATUS_FAILED
        if self.slot:
            self.slot = None
        if error:
            self.error = error
        self.full_clean()
        self.save(update_fields=['status', 'slot', 'error'])

    @transaction.atomic
    def init(self, server, account, slot):
        if self.status != self.STATUS_REQUESTED:
            raise ValidationError(_("Session not in requested state."))

        self.status = self.STATUS_INITIATED
        self.server = server
        self.account = account
        self.slot = slot
        self.full_clean()
        self.save(update_fields=['status', 'server', 'account', 'slot'])
        self.server.mark_used()
        self.account.mark_used()

    @transaction.atomic
    def activate(self):
        if self.status != self.STATUS_INITIATED:
            raise ValidationError(_("Session not in initiated state."))

        self.ovpn_cmd = self.slot.network.openvpn_cmd_tpl % {
            'management_port' : self.slot.management_port,
            'dev' : self.slot.device,
            'server_ip' : self.server.ip_address,
            'server_port' : self.server.port,
            'config_file' : self.provider.config_file,
            'network_log_path' : self.slot.network.log_path,
            'provider_log_path' : self.provider.log_path_tpl % {
                'id': self.slot.sid,
                'uid': self.slot.uid,
            },
            'extra': self.provider.ovpn_extra,
        }
        self.full_clean()
        self.save(update_fields=['ovpn_cmd'])

        p = subprocess.Popen(self.ovpn_cmd, shell=True)
        self.ovpn_pid = p.pid
        self.ovpn_ret = p.returncode
        self.full_clean()
        self.save(update_fields=['ovpn_pid', 'ovpn_ret'])

        if self.ovpn_ret:
            self.fail("Invalid OpenVPN return code: %d" % ret)
            return

        self.status = self.STATUS_ACTIVE
        self.full_clean()
        self.save(update_fields=['status'])

