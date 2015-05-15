# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('waffle', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserFeatureFlags',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('is_active', models.BooleanField(default=True)),
                ('flag', models.ForeignKey(to='waffle.Flag')),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='userfeatureflags',
            unique_together=set([('user', 'flag')]),
        ),
        migrations.AddField(
            model_name='flag',
            name='on_or_off_for_users',
            field=models.ManyToManyField(related_name='on_or_off_for_users', through='waffle.UserFeatureFlags', to=settings.AUTH_USER_MODEL),
            preserve_default=True,
        ),
    ]
