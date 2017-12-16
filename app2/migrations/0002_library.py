# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-06-20 20:09
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app2', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='library',
            fields=[
                ('id_no', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('book_name', models.CharField(max_length=50)),
                ('issue_date', models.DateField()),
                ('submit_date', models.DateField()),
                ('fine', models.IntegerField()),
            ],
        ),
    ]