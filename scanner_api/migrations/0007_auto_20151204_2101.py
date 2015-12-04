# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner_api', '0006_alert'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='alert',
            unique_together=set([('user', 'program', 'vuln')]),
        ),
    ]
