# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-05 08:15
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0015_remove_blog1_author'),
    ]

    operations = [
        migrations.AddField(
            model_name='blog1',
            name='image',
            field=models.ImageField(blank=True, upload_to='user_images'),
        ),
    ]