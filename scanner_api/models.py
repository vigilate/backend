from django.db import models
from pygments.lexers import get_all_lexers
from pygments.styles import get_all_styles

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
