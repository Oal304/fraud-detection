# fraud_prevention/urls.py
# Updated main urls.py
from django.contrib import admin
from django.urls import path, include
from fraud_detection.views import loan_form_home

urlpatterns = [
    path("django-admin/", admin.site.urls),  # Renamed Django admin
    path("", loan_form_home, name="home"),  # Main homepage
    path("", include("fraud_detection.urls")),  # Include all fraud detection URLs
]