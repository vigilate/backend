# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner_api', '0003_user_userprograms'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='id',
            field=models.IntegerField(unique=True, serialize=False, primary_key=True),
        ),
        migrations.AlterField(
            model_name='userprograms',
            name='id',
            field=models.IntegerField(unique=True, serialize=False, primary_key=True),
        ),
    ]
