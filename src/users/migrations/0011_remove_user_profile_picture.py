# Generated by Django 3.2.12 on 2023-07-22 02:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0010_alter_user_profile_picture'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='profile_picture',
        ),
    ]
