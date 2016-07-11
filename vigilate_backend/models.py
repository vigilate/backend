import binascii
import random
import string
import PyArgon2
from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator

# Create your models here.

class User(models.Model):
    """User model
    """
    
    id = models.AutoField(primary_key=True, unique=True)
    username = models.CharField(max_length=20, unique=True)
    email = models.CharField(max_length=50, unique=True)
    password = models.TextField(null=False)
    user_type = models.IntegerField(null=False)
    contrat = models.IntegerField(null=False)
    id_dealer = models.IntegerField()

    EMAIL = "EMAIL"
    SMS = "SMS"
    WEB = "WEB"
    NONE = "NONE"

    ALERT_TYPE = (
        (EMAIL, 'Email'),
        (SMS, 'Sms'),
        (WEB, 'Web'),
        (NONE, None)
    )
    default_alert_type = models.CharField(max_length=5,
                                          choices=ALERT_TYPE,
                                          default=EMAIL)

    is_superuser = False

    def is_authenticated(self):
        """Check if the user is authenticated
        """
        return True

    def has_perms(self, perm, obj=None):
        """Check if the user have permission
        """
        return True

    def set_password(self, password):
        """Set the user password
        """
        charset = string.digits + string.ascii_letters

        salt = ''.join([random.choice(charset) for _ in range(10)])
        hsh = PyArgon2.Hash_pwd(password.encode(), salt.encode())
        hsh = (salt.encode()+b"$"+binascii.hexlify(hsh)).decode("utf8")
        self.password = hsh

    def check_password(self, pwd):
        """Check if the given password match the real one
        """
        salt, hsh = self.password.split("$", 1)
        ret = PyArgon2.Check_pwd(pwd.encode(), salt.encode(), binascii.unhexlify(hsh))
        return ret




class UserPrograms(models.Model):
    """User programs model
    """
    
    id = models.AutoField(primary_key=True, unique=True)
    program_name = models.CharField(max_length=100)
    program_version = models.CharField(max_length=100)
    minimum_score = models.IntegerField(null=False)
    user_id = models.ForeignKey('User')
    poste = models.IntegerField()
    cpe = models.ForeignKey('vulnerability_manager.Cpe')
    sms_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(10)], default=0)
    email_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(10)], default=0)
    web_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(10)], default=0)
    alert_type_default = models.BooleanField(default=True)

class Alert(models.Model):
    """Alert model
    """
    
    id = models.AutoField(primary_key=True, unique=True)
    user = models.ForeignKey('User')
    program = models.ForeignKey('UserPrograms')
    cve = models.ManyToManyField('vulnerability_manager.Cve')

    def max_cvss(self):
         return max(self.cve.values_list("cvss_score", flat=True))

    def program_info(self):
        return {k:getattr(self.program, k) for k in ['program_name', 'program_version']}

    def number_cve(self):
        return self.cve.count()
