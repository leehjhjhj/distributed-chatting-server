# Generated by Django 4.2.7 on 2023-11-20 16:07

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Member',
            fields=[
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('email', models.CharField(max_length=255, unique=True)),
                ('password', models.CharField(max_length=255)),
                ('nickname', models.CharField(max_length=10, unique=True)),
                ('is_blocked', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'members',
            },
        ),
    ]
