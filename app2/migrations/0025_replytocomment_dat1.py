# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-15 14:56
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0024_replytocomment'),
    ]

    operations = [
        migrations.AddField(
            model_name='replytocomment',
            name='dat1',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
