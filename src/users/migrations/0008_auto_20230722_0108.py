# Generated by Django 3.2.12 on 2023-07-22 01:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_alter_user_email'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='bvn',
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='is_bvnverified',
            field=models.BooleanField(default=False, null=True),
        ),
    ]
