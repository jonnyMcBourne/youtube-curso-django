from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager, Group, Permission
from simple_history.models import HistoricalRecords
class CustomUserManager(BaseUserManager):
    def _create_user(self,email,password, first_name,last_name, mobile, **extra_fields):
        if not email:
            raise ValueError("Email must be provided")
        if not password:
            raise ValueError("Password must be provided")
        user = self.model(
            email= self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
            mobile= mobile,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user( email, password, **extra_fields)
    
        
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(db_index=True,unique=True,max_length=254)
    first_name = models.CharField(max_length=255)
    last_name= models.CharField(max_length=255)
    mobile = models.CharField(max_length=15)
    address = models.CharField(max_length=255)
    is_federated= models.BooleanField(default=False)

    is_staff  = models.BooleanField(default=True) # necesita tener esto, sino no vas a poder logearte en django-admin
    is_active = models.BooleanField(default=True) # necesita tener esto, sino no vas a poder logearte en django-admin
    is_superuser = models.BooleanField(default=False) # este campo lo heredamos de PermissionMixin.

    groups= models.ManyToManyField(Group, related_name='custom_user_set')
    user_permissions= models.ManyToManyField(Permission, related_name='custom_user_set')

    objects = CustomUserManager()
    historical= HistoricalRecords()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name','last_name','mobile',]

    class Meta:
        verbose_name='User'
        verbose_name_plural= 'Users'
    
    def __str__(self):
        return f'{self.email} - {self.name} {self.last_name}'
