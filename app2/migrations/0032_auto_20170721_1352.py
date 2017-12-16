# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-21 08:22
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('app2', '0031_auto_20170721_1251'),
    ]

    operations = [
        migrations.CreateModel(
            name='notification',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_notif', models.CharField(blank=True, max_length=200, null=True)),
                ('comment_notif', models.CharField(blank=True, max_length=200, null=True)),
                ('helpfull', models.CharField(blank=True, max_length=200, null=True)),
                ('dat2', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='blog1',
            name='notification',
        ),
        migrations.AddField(
            model_name='notification',
            name='notblog',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='app2.blog1'),
        ),
        migrations.AddField(
            model_name='notification',
            name='notiuser',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]