# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-09-02 07:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0051_auto_20170902_1303'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blog1',
            name='like',
            field=models.SlugField(max_length=10, null=True),
        ),
    ]
