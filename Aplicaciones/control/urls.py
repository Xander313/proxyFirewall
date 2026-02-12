from django.urls import path

from .views import control_index

urlpatterns = [
    path("", control_index, name="control_index"),
]
