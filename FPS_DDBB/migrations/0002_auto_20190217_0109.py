# Generated by Django 2.1.7 on 2019-02-17 00:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('FPS_DDBB', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='fps',
            name='ID_FPS',
            field=models.IntegerField(primary_key=True, serialize=False),
        ),
    ]
