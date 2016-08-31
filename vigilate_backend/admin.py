from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django import forms
from vigilate_backend.models import User, UserPrograms, Alert, Station, Session, Plans
from vulnerability_manager.models import Cve, Cpe, Cwe, Reference

# Register your models here.

#Custom admin for user to try to fix the issue of lenght of the password
class MyUserAdmin(UserAdmin):
    list_display = ('id', 'email', 'last_login', 'phone', 'user_type', 'contrat', 'id_dealer', 'is_superuser', 'default_alert_type')
    list_search = ('id', 'email', 'last_login', 'phone', 'user_type', 'contrat', 'id_dealer', 'is_superuser', 'default_alert_type')
    filter_horizontal = ()
    ordering = ('id', 'email')
    list_filter = ('id', 'email', 'last_login', 'phone', 'user_type', 'contrat', 'id_dealer', 'is_superuser', 'default_alert_type')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_superuser',)}),
        ('Important dates', {'fields': ('last_login',)}),
        ('Personal info', {'fields': ('phone',)}),
        ('Alert details', {'fields': ('default_alert_type',)}),
        ('Other details', {'fields': ('user_type', 'contrat', 'id_dealer')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2')}
        ),
)

    def get_plan(self, obj):
        return obj.plan.name
    get_plan.short_description = "Current Plan"
    
admin.site.register(User, MyUserAdmin)

class PlansAdmin(admin.ModelAdmin):

    list_display = ('name', 'price', 'max_stations')

admin.site.register(Plans, PlansAdmin)

admin.site.register(UserPrograms)
admin.site.register(Alert)
admin.site.register(Station)
admin.site.register(Session)
admin.site.register(Cve)
admin.site.register(Cpe)
admin.site.register(Cwe)
admin.site.register(Reference)

admin.site.unregister(Group)
