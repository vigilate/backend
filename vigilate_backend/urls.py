"""vigilate_backend URL Configuration"""

from django.conf.urls import include, url
from django.contrib import admin
from rest_framework import routers
from scanner_api import views

router = routers.DefaultRouter()
router.register(r'vulnz', views.VulnViewSet)
router.register(r'users', views.UserViewSet)
router.register(r'uprog', views.UserProgramsViewSet)
router.register(r'alerts', views.AlertViewSet)

urlpatterns = [
    url('^api/', include(router.urls)),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', views.home),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
