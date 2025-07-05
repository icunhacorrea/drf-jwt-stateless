from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.LoginView.as_view()),
    path("refresh/", views.RefreshView.as_view()),
    path("protected/", views.ProtectedView.as_view()),
]
