# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-06-27 10:13
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0007_auto_20170626_1645'),
    ]

    operations = [
        migrations.CreateModel(
            name='blog1',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100)),
                ('comment', models.TextField()),
            ],
        ),
    ]