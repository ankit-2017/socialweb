# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-17 19:49
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0028_auto_20170718_0033'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blog1',
            name='helpful',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='blog1',
            name='not_helpful',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
