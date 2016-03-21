from django.db import models
from pygments.lexers import get_all_lexers
from pygments.styles import get_all_styles
import PyArgon2
import binascii
import random
import string

# Create your models here.
class Vuln(models.Model):
    cveid = models.CharField(max_length=20, unique=True)
    program_name = models.CharField(max_length=100)
    program_version = models.CharField(max_length=100)
    date = models.DateTimeField(auto_now_add=True, auto_now=False, verbose_name="Date de parution")
    detail = models.TextField(null=True)
    simple_detail = models.TextField(null=True)
    concerned_cpe = models.TextField(null=True)
    score = models.IntegerField()

class User(models.Model):
    id = models.AutoField(primary_key=True, unique=True)
    username = models.CharField(max_length=20, unique=True)
    email = models.CharField(max_length=20, unique=True)
    password = models.TextField(null=False)
    user_type = models.IntegerField(null=False)
    contrat = models.IntegerField(null=False)
    id_dealer= models.IntegerField()

    def is_authenticated(self):
        return True

    def has_perms(self, perm, obj=None):
        return True

    def set_password(self, password):
        charset = string.digits + string.ascii_letters

        salt = ''.join([random.choice(charset) for _ in range(10)])
        h = PyArgon2.Hash_pwd(password.encode(), salt.encode())
        h = (salt.encode()+b"$"+binascii.hexlify(h)).decode("utf8")
        self.password = h

    def check_password(self, pwd):
        salt,hsh = self.password.split("$", 1)
        ret = PyArgon2.Check_pwd(pwd.encode(), salt.encode(), binascii.unhexlify(hsh))
        return ret




class UserPrograms(models.Model):
    id = models.AutoField(primary_key=True, unique=True)
    program_name = models.CharField(max_length=100)
    program_version = models.CharField(max_length=100)
    minimum_score = models.IntegerField(null=False)
    user_id = models.ForeignKey('User')

    def next_id():
        no = UserPrograms.objects.count()
        if no == None:
            return 1
        else:
            return no + 1

class Alert(models.Model):
    id = models.AutoField(primary_key=True, unique=True)
    user = models.ForeignKey('User')
    program = models.ForeignKey('UserPrograms')
    vuln = models.ForeignKey('Vuln')
    class Meta:
        unique_together = ["user", "program", "vuln"]
