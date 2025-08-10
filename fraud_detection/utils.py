# fraud_detection/utils.py
import os
import requests
import logging
from datetime import timedelta
from django.utils.timezone import now
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from tenacity import retry, stop_after_attempt, wait_fixed
from .models import LoanApplication, VisitorID, FraudAlert
import json


# Load API credentials
FINGERPRINT_API_KEY = os.getenv("FINGERPRINT_API_KEY")
FINGERPRINT_API_URL = os.getenv("FINGERPRINT_API_URL")

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Extracts client IP address from request headers."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def get_fingerprint_visitor_id(device_info):
    """
    Retrieves the unique visitor ID using the fingerprint API.
    Implements a retry mechanism for robustness.
    """
    try:
        response = requests.post(
            FINGERPRINT_API_URL,
            json={"device_info": device_info},
            headers={"Authorization": f"Bearer {FINGERPRINT_API_KEY}"},
            timeout=5
        )
        response.raise_for_status()
        return response.json().get("visitor_id")
    except requests.exceptions.RequestException as e:
        logger.error(f"Fingerprint API request failed: {e}")
        return None

def detect_fraud(loan_application, extended_metadata=None):
    """
    Enhanced fraud detection using extended metadata from FingerprintJS.
    """
    fraud_reasons = []
    
    if extended_metadata:
        # Check confidence score
        if extended_metadata.get('confidence', 0) < 0.9:
            fraud_reasons.append("Low confidence in visitor identification")
        
        # Check browser consistency
        if loan_application.visitor_id:
            previous_apps = LoanApplication.objects.filter(visitor_id=loan_application.visitor_id)
            for app in previous_apps:
                if app.metadata:
                    prev_browser = json.loads(app.metadata).get('browserInfo', {})
                    curr_browser = extended_metadata.get('browserInfo', {})
                    
                    if prev_browser.get('browserName') != curr_browser.get('browserName'):
                        fraud_reasons.append("Browser type mismatch")
                    if prev_browser.get('os') != curr_browser.get('os'):
                        fraud_reasons.append("Operating system mismatch")
    
    # Check for rapid submissions
    if loan_application.visitor_id:
        recent_apps = LoanApplication.objects.filter(
            visitor_id=loan_application.visitor_id,
            application_date__gte=timezone.now() - timedelta(minutes=30)
        ).exclude(id=loan_application.id)
        
        if recent_apps.count() > 2:
            fraud_reasons.append("Multiple applications in short timeframe")
    
    if fraud_reasons:
        FraudAlert.objects.create(
            loan_application=loan_application,
            visitor_id=loan_application.visitor_id,
            reason=" | ".join(fraud_reasons),
        )
        return True
    
    return False


def store_visitor_data(request):
    """
    Stores visitor data and retrieves fingerprint.
    """
    try:
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "Unknown")
        
        # Verify API credentials
        if not FINGERPRINT_API_KEY or not FINGERPRINT_API_URL:
            logger.error("Fingerprint API credentials not configured")
            raise ValueError("Fingerprint API not configured")
        
        # Get visitor ID from Fingerprint API
        visitor_id = get_fingerprint_visitor_id({
            "ip": client_ip,
            "user_agent": user_agent
        })
        
        # Store visitor data
        visitor, created = VisitorID.objects.get_or_create(
            ip_address=client_ip,
            defaults={
                "visitor_id": visitor_id,
                "device_fingerprint": request.headers.get("Device-Fingerprint", None)
            }
        )
        
        if not visitor.visitor_id and visitor_id:
            visitor.visitor_id = visitor_id
            visitor.save()
            
        return visitor.visitor_id
    except Exception as e:
        logger.error(f"Failed to store visitor data: {str(e)}")
        raise


def flag_suspicious_application(loan_app):
    """
    Checks if a loan application is suspicious based on fraud patterns.
    """
    fraud_detected = detect_fraudulent_application(loan_app)
    if fraud_detected:
        # Send email notification
        send_mail(
            "Suspicious Loan Application Detected",
            f"Loan application {loan_app.id} has been flagged for fraud review.",
            settings.DEFAULT_FROM_EMAIL,
            [settings.ADMIN_EMAIL],
            fail_silently=True,
        )
    return fraud_detected