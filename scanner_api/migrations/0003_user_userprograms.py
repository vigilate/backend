# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner_api', '0002_auto_20151102_0142'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, unique=True)),
                ('username', models.CharField(max_length=20, unique=True)),
                ('email', models.CharField(max_length=20, unique=True)),
                ('password', models.TextField()),
                ('user_type', models.IntegerField()),
                ('contrat', models.IntegerField()),
                ('id_dealer', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='UserPrograms',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, unique=True)),
                ('program_name', models.CharField(max_length=100)),
                ('program_version', models.CharField(max_length=100)),
                ('minimum_score', models.IntegerField()),
                ('user_id', models.ForeignKey(to='scanner_api.User')),
            ],
        ),
    ]
