# Generated by Django 5.1.6 on 2025-03-11 04:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ml_api', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='predictionlog',
            name='city',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
