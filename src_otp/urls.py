from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from demo import views
from demo.views import login_view


router = DefaultRouter()
router.register('user', views.UserViewSet, basename='user')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', login_view, name='login'),
    path('api-auth/', include('rest_framework.urls')),
]
urlpatterns += router.urls
