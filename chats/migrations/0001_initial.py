# Generated by Django 4.2.7 on 2023-11-20 12:53

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('members', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Chat',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=20)),
                ('description', models.CharField(max_length=64)),
                ('max_capacity', models.IntegerField()),
                ('headcount', models.IntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('made_by', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='members.member')),
            ],
        ),
    ]