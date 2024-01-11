# Generated by Django 3.2.18 on 2023-06-14 19:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userauths', '0004_profile_groups'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='friends_visibility',
            field=models.CharField(blank=True, choices=[('Only Me', 'Only Me'), ('Everyone', 'Everyone')], default='Everyone', max_length=100, null=True),
        ),
    ]
