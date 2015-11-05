"""vigilate_backend URL Configuration"""

from django.conf.urls import include, patterns, url
from django.contrib import admin
from rest_framework import routers, serializers, viewsets
from scanner_api import models, views

router = routers.DefaultRouter()
router.register(r'vulnz', views.VulnViewSet)
router.register(r'users', views.UserViewSet)
router.register(r'uprog', views.UserProgramsViewSet)

urlpatterns = [
    url('^api/', include(router.urls)),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', 'scanner_api.views.home'),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
