# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-06-26 10:54
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0005_auto_20170625_2254'),
    ]

    operations = [
        migrations.AlterField(
            model_name='collage',
            name='event_date',
            field=models.DateTimeField(auto_now=True),
        ),
    ]