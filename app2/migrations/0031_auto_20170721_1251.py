# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-21 07:21
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0030_blog1_notification'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blog1',
            name='notification',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
