# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-11 16:19
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0021_auto_20170711_2038'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='dob',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='profile_pic',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]