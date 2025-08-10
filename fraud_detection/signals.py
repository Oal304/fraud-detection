# fraud_detection/signals.py

from django.db.models.signals import post_save, post_migrate
from django.dispatch import receiver
from .models import LoanApplication
from .utils import detect_fraud
from django.contrib.auth import get_user_model
from django.db import IntegrityError

@receiver(post_save, sender=LoanApplication)
def check_fraud(sender, instance, created, **kwargs):
    if created:
        detect_fraud(instance)



