# Generated by Django 5.1.4 on 2025-01-04 17:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OtpApp', '0026_alter_otptoken_otp_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='83023b', max_length=6),
        ),
    ]
