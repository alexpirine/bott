# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-10-15 14:25
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bott', '0002_session_ovpn_cmd'),
    ]

    operations = [
        migrations.AlterField(
            model_name='session',
            name='ovpn_cmd',
            field=models.TextField(blank=True, editable=False, verbose_name='OpenVPN compiled command'),
        ),
    ]