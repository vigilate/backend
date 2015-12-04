# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner_api', '0005_auto_20151204_1746'),
    ]

    operations = [
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.AutoField(serialize=False, unique=True, primary_key=True)),
                ('program', models.ForeignKey(to='scanner_api.UserPrograms')),
                ('user', models.ForeignKey(to='scanner_api.User')),
                ('vuln', models.ForeignKey(to='scanner_api.Vuln')),
            ],
        ),
    ]
