# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner_api', '0004_auto_20151102_2346'),
    ]

    operations = [
        migrations.AddField(
            model_name='vuln',
            name='concerned_cpe',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userprograms',
            name='id',
            field=models.AutoField(unique=True, primary_key=True, serialize=False),
        ),
    ]
