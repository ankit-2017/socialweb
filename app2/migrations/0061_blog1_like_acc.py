# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-09-04 04:40
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0060_auto_20170903_0505'),
    ]

    operations = [
        migrations.AddField(
            model_name='blog1',
            name='like_acc',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='like_acc', to='app2.forlike'),
        ),
    ]
