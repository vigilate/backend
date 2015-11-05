# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Vulns',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('cveid', models.CharField(max_length=20)),
                ('program_name', models.CharField(max_length=100)),
                ('program_version', models.CharField(max_length=100)),
                ('date', models.DateTimeField(verbose_name='Date de parution', auto_now_add=True)),
                ('detail', models.TextField(null=True)),
                ('simple_detail', models.TextField(null=True)),
                ('score', models.IntegerField()),
            ],
        ),
    ]
