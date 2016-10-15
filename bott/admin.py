# coding: utf-8
# Copyright (c) Alexandre Syenchuk, 2016

from . import models as M
from django import forms
from django.contrib import admin
from django.db.models import Count
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import ugettext_lazy as _

class NetworkForm(forms.ModelForm):
    class Meta:
        model = M.Network
        fields = '__all__'
        widgets = {
            'openvpn_cmd_tpl': admin.widgets.AdminTextareaWidget()
        }

@admin.register(M.Network)
class Network(admin.ModelAdmin):
    form = NetworkForm

@admin.register(M.SessionSlot)
class SessionSlot(admin.ModelAdmin):
    list_display = ('uid', 'network_link', 'sid', 'management_port', 'source_ip', 'device', 'session_link', 'get_session_started_display')
    list_display_links = ('uid',)

    def network_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_network_change', args=(instance.network.pk,)),
            instance.network,
        )
    network_link.short_description = _("network")

    def session_link(self, instance):
        try:
            return format_html('<a href="{}">{} ({})</a>',
                reverse('admin:bott_session_change', args=(instance.session.pk,)),
                instance.session,
                instance.session.get_status_display(),
            )
        except M.Session.DoesNotExist:
            return None
    session_link.short_description = _("session")

@admin.register(M.Provider)
class Provider(admin.ModelAdmin):
    list_display = ('name', 'network_link', 'regions_num', 'locations_num', 'servers_num')
    list_filter = ('disabled', 'network')

    def network_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_network_change', args=(instance.network.pk,)),
            instance.network,
        )
    network_link.short_description = _("network")

    def regions_num(self, instance):
        num = instance.regions.count()
        if not num:
            return None
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_region_changelist') + '?provider__id__exact=%d' % instance.pk,
            num,
        )
    regions_num.short_description = _("regions")

    def locations_num(self, instance):
        num = instance.regions.aggregate(v=Count('locations'))['v']
        if not num:
            return None
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_location_changelist') + '?region__provider__id__exact=%d' % instance.pk,
            num,
        )
    locations_num.short_description = _("locations")

    def servers_num(self, instance):
        num = instance.regions.aggregate(v=Count('locations__servers'))['v']
        if not num:
            return None
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_server_changelist') + '?location__region__provider__id__exact=%d' % instance.pk,
            num,
        )
    servers_num.short_description = _("servers")

@admin.register(M.Region)
class Region(admin.ModelAdmin):
    list_display = ('name', 'provider_link', 'locations_num', 'servers_num')
    list_filter = ('disabled', 'provider')

    def provider_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_provider_change', args=(instance.provider.pk,)),
            instance.provider,
        )
    provider_link.short_description = _("provider")

    def locations_num(self, instance):
        num = instance.locations.count()
        if not num:
            return None
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_location_changelist') + '?region__id__exact=%d' % instance.pk,
            num,
        )
    locations_num.short_description = _("locations")

    def servers_num(self, instance):
        num = instance.locations.aggregate(v=Count('servers'))['v']
        if not num:
            return None
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_server_changelist') + '?location__region__id__exact=%d' % instance.pk,
            num,
        )
    servers_num.short_description = _("servers")

@admin.register(M.Location)
class Location(admin.ModelAdmin):
    list_display = ('name', 'region_link', 'servers_num')
    list_filter = ('disabled', 'region__provider', 'region')

    def region_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_region_change', args=(instance.region.pk,)),
            instance.region,
        )
    region_link.short_description = _("region")

    def servers_num(self, instance):
        num = instance.servers.count()
        if not num:
            return None
        return format_html('<a href="{}">{}</a>',
            (
                reverse('admin:bott_server_changelist') +
                '?location__id__exact=%d' % instance.pk +
                '&location__region__id__exact=%d' % instance.region.pk +
                '&location__region__provider__id__exact=%d' % instance.region.provider.pk
            ),
            num,
        )
    servers_num.short_description = _("servers")

@admin.register(M.Server)
class Server(admin.ModelAdmin):
    list_display = ('ip_address', 'location_link', 'region_link', 'provider_link', 'get_active_display', 'get_used_display')
    list_filter = ('disabled', 'location__region__provider', 'location__region', 'location')

    def location_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_location_change', args=(instance.location.pk,)),
            instance.location,
        )
    location_link.short_description = _("location")

    def region_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_region_change', args=(instance.location.region.pk,)),
            instance.location.region,
        )
    region_link.short_description = _("region")

    def provider_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_provider_change', args=(instance.location.region.provider.pk,)),
            instance.location.region.provider,
        )
    provider_link.short_description = _("provider")

@admin.register(M.Account)
class Account(admin.ModelAdmin):
    list_display = ('username', 'provider_link', 'running_sessions_num')

    def provider_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_provider_change', args=(instance.provider.pk,)),
            instance.provider,
        )
    provider_link.short_description = _("provider")

    def running_sessions_num(self, instance):
        num = instance.sessions.filter(status__in=M.Session.STATUSES_RUNNING).count()
        if not num:
            return None
        return format_html('<a href="{}">{}</a>',
            (
                reverse('admin:bott_session_changelist') +
                '?account__id__exact=%d' % instance.pk +
                '&account__provider__id__exact=%d' % instance.provider.pk +
                '&status__in=%s' % ','.join(['%d' % s for s in M.Session.STATUSES_RUNNING])
            ),
            num,
        )
    running_sessions_num.short_description = _("running sessions")

@admin.register(M.Session)
class Session(admin.ModelAdmin):
    list_display = ('pk', 'provider_link', 'server_link', 'account_link', 'status', 'slot_link', 'get_started_display')
    list_filter = ('status', 'account__provider', 'account')
    readonly_fields = ('ovpn_cmd', 'ovpn_pid', 'ovpn_ret', 'error')

    def provider_link(self, instance):
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_provider_change', args=(instance.provider.pk,)),
            instance.provider,
        )
    provider_link.short_description = _("provider")

    def server_link(self, instance):
        if not instance.server:
            return None
        return format_html('<a href="{}">{} ({})</a>',
            reverse('admin:bott_server_change', args=(instance.server.pk,)),
            instance.server,
            instance.server.location,
        )
    server_link.short_description = _("server")

    def account_link(self, instance):
        if not instance.account:
            return None
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_account_change', args=(instance.account.pk,)),
            instance.account,
        )
    account_link.short_description = _("account")

    def slot_link(self, instance):
        if not instance.slot:
            return None
        return format_html('<a href="{}">{}</a>',
            reverse('admin:bott_sessionslot_change', args=(instance.slot.pk,)),
            instance.slot,
        )
    slot_link.short_description = _("slot")
