"""vigilate_backend URL Configuration"""

from django.conf.urls import include, url
from django.contrib import admin
from rest_framework import routers
from vigilate_backend import views as views
from vulnerability_manager import views as views_vuln_m

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet, "User")
router.register(r'uprog', views.UserProgramsViewSet, "UserPrograms")
router.register(r'alerts', views.AlertViewSet, "Alert")

urlpatterns = [
    url('^api/v1/', include(router.urls)),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', views.home),
    url('^update_cpe$', views_vuln_m.update_cpe),
    url('^update_recent_cve$', views_vuln_m.update_recent_cve),
    url('^update_all_cve$', views_vuln_m.update_all_cve),
    url('^update_all_cve_using_files$', views_vuln_m.update_all_cve_using_files),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
