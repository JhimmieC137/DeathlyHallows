# Generated by Django 3.2.12 on 2023-07-22 02:02

from django.db import migrations
import easy_thumbnails.fields


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_alter_user_profile_picture'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='profile_picture',
            field=easy_thumbnails.fields.ThumbnailerImageField(blank=True, null=True, upload_to='profile_pictures/', verbose_name='ProfilePicture'),
        ),
    ]