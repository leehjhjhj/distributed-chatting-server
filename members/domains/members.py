from django.db import models
from django.contrib.auth.models import AbstractBaseUser

class Member(AbstractBaseUser):
    id = models.BigAutoField(primary_key=True)
    email = models.CharField(unique=True, max_length=255)
    password = models.CharField(max_length=255)
    nickname = models.CharField(unique=True, max_length=10)
    is_blocked = models.BooleanField(default=False)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'members'