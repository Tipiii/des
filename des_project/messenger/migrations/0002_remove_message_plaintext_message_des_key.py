# Generated by Django 5.0.14 on 2025-06-16 06:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('messenger', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='message',
            name='plaintext',
        ),
        migrations.AddField(
            model_name='message',
            name='des_key',
            field=models.CharField(default='', max_length=100),
        ),
    ]
