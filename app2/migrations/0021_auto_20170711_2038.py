# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-11 15:08
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0020_remove_blog1_title'),
    ]

    operations = [
        migrations.RenameField(
            model_name='profile',
            old_name='user2',
            new_name='user',
        ),
    ]
