import binascii
import random
import string
import PyArgon2
from django.db import models

# Create your models here.
class Vuln(models.Model):
    """Vuln model
    """
    cveid = models.CharField(max_length=20, unique=True)
    program_name = models.CharField(max_length=100)
    program_version = models.CharField(max_length=100)
    date = models.DateTimeField(auto_now_add=True, auto_now=False, verbose_name="Date de parution")
    detail = models.TextField(null=True)
    simple_detail = models.TextField(null=True)
    concerned_cpe = models.TextField(null=True)
    score = models.IntegerField()

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
    cpe = models.ManyToManyField('vulnerability_manager.Cpe')

class Alert(models.Model):
    """Alert model
    """
    
    id = models.AutoField(primary_key=True, unique=True)
    user = models.ForeignKey('User')
    program = models.ForeignKey('UserPrograms')
    vuln = models.ForeignKey('Vuln')
    class Meta:
        unique_together = ["user", "program", "vuln"]
