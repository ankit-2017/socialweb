# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-08-06 05:51
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0037_new_message'),
    ]

    operations = [
        migrations.RenameField(
            model_name='notification',
            old_name='comment_notif',
            new_name='notif',
        ),
        migrations.RemoveField(
            model_name='notification',
            name='helpfull',
        ),
        migrations.RemoveField(
            model_name='notification',
            name='profile_notif',
        ),
    ]
