# fraud_detection/views.py
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.conf import settings
from .models import VisitorID, LoanApplication, FraudAlert
from django.db.models import F  # New import
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.utils.decorators import method_decorator
from .forms import LoanApplicationForm
from .utils import get_fingerprint_visitor_id, store_visitor_data, flag_suspicious_application, get_client_ip
import json
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Q, Count, Avg
from datetime import timedelta
from .services import (
    EnhancedFraudDetectionService, 
    EnhancedRiskScoringService, 
    get_enhanced_decision_with_explanation,
    RiskScoringService, 
    FraudDetectionService
)
from .ml_services import MLFraudEnhancer
from django.utils import timezone
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .forms import LoginForm  # Renamed from AdminLoginForm
from django.contrib.auth.models import User
from .forms import LoginForm  # Renamed from AdminLoginForm
from fraud_detection.services import RiskScoringService, FraudDetectionService
from django.db import transaction
import logging
import requests 

# Configure the logger
logger = logging.getLogger(__name__)

# Helper function to check if user is an admin
def is_admin(user):
    return user.is_authenticated and user.is_staff

# UPDATED: Admin dashboard with proper auth
@login_required(login_url='fraud_detection:login')
@user_passes_test(is_admin, login_url='fraud_detection:login')
def admin_dashboard(request):
    """
    Enhanced admin dashboard view
    """
    context = {
        'user': request.user,
        'page_title': 'VeriLoan Admin Dashboard'
    }
    return render(request, 'fraud_detection/admin_dashboard.html', context)

# FIXED: Separate admin dashboard from Django admin
@login_required(login_url='fraud_detection:login')
@user_passes_test(is_admin, login_url='fraud_detection:login')
def dashboard(request):
    """
    Custom admin dashboard (separate from Django admin)
    """
    context = {
        'user': request.user,
        'page_title': 'Admin Dashboard'
    }
    return render(request, 'fraud_detection/dashboard.html', context)

def login_view(request):
    """
    Custom admin login view that redirects to proper dashboard
    """
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('fraud_detection:dashboard')
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            
            if user.is_staff:
                login(request, user)
                messages.success(request, f'Welcome back, {user.first_name or user.username}!')
                return redirect('fraud_detection:dashboard')
            else:
                messages.error(request, "Insufficient permissions.")
        else:
            messages.error(request, "Please fill out the form correctly.")
    else:
        form = AuthenticationForm()

    return render(request, 'fraud_detection/login.html', {'form': form})

# FIXED: Proper logout view
@login_required
def logout_view(request):
    """
    Custom logout view with proper redirect
    """
    username = request.user.username
    logout(request)
    messages.info(request, f'You have been successfully logged out.')
    return redirect('fraud_detection:loan_form_home')

def loan_form_home(request):
    """
    Renders the loan application form as the homepage.
    """
    form = LoanApplicationForm()  # Create an empty form for display
    context = {
        "form": form,
        "fingerprintjs_public_key": settings.FINGERPRINTJS_PUBLIC_KEY,  # Pass the public key
    }
    return render(request, "fraud_detection/loan_form.html", context)

@staff_member_required
def dashboard_data(request):
    """
    API endpoint to provide dashboard data - UPDATED for dual status
    """
    try:
        from datetime import timedelta
        from django.utils import timezone
        from .models import LoanApplication, FraudAlert
        from django.db.models import Count
        import json
        
        # Get recent applications (last 30 days)
        recent_date = timezone.now() - timedelta(days=30)
        recent_applications = LoanApplication.objects.filter(
            application_date__gte=recent_date
        ).order_by('-application_date')
        
        # Calculate statistics with dual status
        total_applications = recent_applications.count()
        
        # Fraud detection statistics (backend)
        fraud_pending = recent_applications.filter(status='pending').count()
        fraud_approved = recent_applications.filter(status='approve').count()
        fraud_rejected = recent_applications.filter(status='rejected').count()
        fraud_flagged = recent_applications.filter(status='flagged').count()
        
        # Final approval statistics (staff)
        final_pending = recent_applications.filter(final_status='pending_review').count()
        final_approved = recent_applications.filter(final_status='approved').count()
        final_rejected = recent_applications.filter(final_status='rejected').count()
        
        # Risk-based statistics
        high_risk_applications = recent_applications.filter(risk_score__gt=70).count()
        
        # Applications that can be decided by staff
        can_staff_decide = recent_applications.filter(status__in=['approve', 'flagged']).count()
        
        # Count anomalies from metadata
        anomalies_count = 0
        applications_data = []
        
        for app in recent_applications[:50]:  # Limit to 50 for performance
            # Parse metadata to check for ML anomalies
            ml_anomaly = False
            behavioral_risk = 'unknown'
            
            try:
                if app.metadata:
                    metadata = json.loads(app.metadata) if isinstance(app.metadata, str) else app.metadata
                    ml_analysis = metadata.get('ml_analysis', {})
                    ml_anomaly = ml_analysis.get('anomaly_detected', False)
                    behavioral_risk = ml_analysis.get('behavioral_risk', 'unknown')
                    
                    if ml_anomaly:
                        anomalies_count += 1
            except (json.JSONDecodeError, TypeError):
                pass
            
            applications_data.append({
                'id': str(app.id),
                'full_name': app.full_name,
                'email': app.email,
                'amount_requested': float(app.amount_requested),
                'risk_score': float(app.risk_score),
                'fraud_status': app.status,  # Backend fraud detection status
                'final_status': app.final_status,  # Staff decision status
                'display_status': app.display_status,  # Combined status for display
                'can_staff_decide': app.can_staff_decide,  # Whether staff can make decisions
                'application_date': app.application_date.isoformat(),
                'staff_decision_date': app.staff_decision_date.isoformat() if app.staff_decision_date else None,
                'decided_by': app.staff_decision_by.username if app.staff_decision_by else None,
                'ml_anomaly': ml_anomaly,
                'behavioral_risk': behavioral_risk,
                'visitor_id': app.visitor_id.visitor_id if app.visitor_id else None
            })
        
        stats = {
            'total': total_applications,
            'high_risk': high_risk_applications,
            'anomalies': anomalies_count,
            'fraud_stats': {
                'pending': fraud_pending,
                'approved': fraud_approved,
                'rejected': fraud_rejected,
                'flagged': fraud_flagged
            },
            'final_stats': {
                'pending_review': final_pending,
                'approved': final_approved,
                'rejected': final_rejected
            },
            'can_staff_decide': can_staff_decide
        }
        
        return JsonResponse({
            'stats': stats,
            'applications': applications_data
        })
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {str(e)}")
        return JsonResponse({'error': 'Failed to load dashboard data'}, status=500)

# UPDATED: Dashboard data API with proper auth
@login_required(login_url='fraud_detection:login')
@user_passes_test(is_admin, login_url='fraud_detection:login')
def dashboard_data(request):
    """
    API endpoint to provide dashboard data - properly protected
    """
    try:
        from datetime import timedelta
        from django.utils import timezone
        from .models import LoanApplication, FraudAlert
        from django.db.models import Count
        import json
        
        # Get recent applications (last 30 days)
        recent_date = timezone.now() - timedelta(days=30)
        recent_applications = LoanApplication.objects.filter(
            application_date__gte=recent_date
        ).order_by('-application_date')
        
        # Calculate statistics
        total_applications = recent_applications.count()
        high_risk_applications = recent_applications.filter(risk_score__gt=70).count()
        approved_applications = recent_applications.filter(status='approve').count()
        
        # Count anomalies from metadata
        anomalies_count = 0
        applications_data = []
        
        for app in recent_applications[:50]:
            ml_anomaly = False
            behavioral_risk = 'unknown'
            
            try:
                if app.metadata:
                    metadata = json.loads(app.metadata) if isinstance(app.metadata, str) else app.metadata
                    ml_analysis = metadata.get('ml_analysis', {})
                    ml_anomaly = ml_analysis.get('anomaly_detected', False)
                    behavioral_risk = ml_analysis.get('behavioral_risk', 'unknown')
                    
                    if ml_anomaly:
                        anomalies_count += 1
            except (json.JSONDecodeError, TypeError):
                pass
            
            applications_data.append({
                'id': str(app.id),
                'full_name': app.full_name,
                'email': app.email,
                'amount_requested': float(app.amount_requested),
                'risk_score': float(app.risk_score),
                'status': app.status,
                'application_date': app.application_date.isoformat(),
                'ml_anomaly': ml_anomaly,
                'behavioral_risk': behavioral_risk,
                'visitor_id': app.visitor_id.visitor_id if app.visitor_id else None
            })
        
        stats = {
            'total': total_applications,
            'high_risk': high_risk_applications,
            'anomalies': anomalies_count,
            'approved': approved_applications
        }
        
        return JsonResponse({
            'stats': stats,
            'applications': applications_data
        })
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {str(e)}")
        return JsonResponse({'error': 'Failed to load dashboard data'}, status=500)

@staff_member_required  
def application_details(request, application_id):
    """
    Get detailed information about a specific application - UPDATED for dual status
    """
    try:
        from .models import LoanApplication, FraudAlert
        import json
        
        application = LoanApplication.objects.get(id=application_id)
        
        # Get fraud alerts for this application
        fraud_alerts = FraudAlert.objects.filter(loan_application=application)
        
        # Parse metadata
        metadata = {}
        ml_analysis = {}
        try:
            if application.metadata:
                metadata = json.loads(application.metadata) if isinstance(application.metadata, str) else application.metadata
                ml_analysis = metadata.get('ml_analysis', {})
        except (json.JSONDecodeError, TypeError):
            pass
        
        # Get visitor information
        visitor_info = None
        if application.visitor_id:
            visitor = application.visitor_id
            visitor_info = {
                'visitor_id': visitor.visitor_id,
                'ip_address': visitor.ip_address,
                'public_ip': visitor.public_ip,
                'confidence_score': visitor.confidence_score,
                'browser_name': visitor.browser_name,
                'os': visitor.os,
                'device': visitor.device,
                'application_count': visitor.application_count,
                'last_application_date': visitor.last_application_date.isoformat() if visitor.last_application_date else None
            }
        
        # Get smart signals
        smart_signals = {
            'bot_detected': application.bot_detected,
            'vpn_detected': application.vpn_detected,
            'proxy_detected': application.proxy_detected,
            'tor_detected': application.tor_detected,
            'tampering_detected': application.tampering_detected,
            'incognito': application.incognito,
            'ip_blocklisted': application.ip_blocklisted
        }
        
        response_data = {
            'application': {
                'id': str(application.id),
                'full_name': application.full_name,
                'email': application.email,
                'phone': application.phone,
                'address': application.address,
                'employment_status': application.employment_status,
                'occupation': application.occupation,
                'amount_requested': float(application.amount_requested),
                'repayment_duration': application.repayment_duration,
                'purpose': application.purpose,
                'fraud_status': application.status,  # Backend fraud status
                'final_status': application.final_status,  # Staff decision status
                'display_status': application.display_status,  # Combined display status
                'can_staff_decide': application.can_staff_decide,  # Whether staff can decide
                'risk_score': float(application.risk_score),
                'application_date': application.application_date.isoformat(),
                'last_modified': application.last_modified.isoformat(),
                'staff_decision_date': application.staff_decision_date.isoformat() if application.staff_decision_date else None,
                'staff_decision_by': application.staff_decision_by.username if application.staff_decision_by else None,
                'staff_comments': application.staff_comments or ''
            },
            'visitor_info': visitor_info,
            'smart_signals': smart_signals,
            'ml_analysis': ml_analysis,
            'fraud_alerts': [
                {
                    'id': alert.id,
                    'reason': alert.reason,
                    'status': alert.status,
                    'risk_score': float(alert.risk_score),
                    'created_at': alert.created_at.isoformat(),
                    'resolved': alert.resolved
                }
                for alert in fraud_alerts
            ],
            'metadata': metadata
        }
        
        return JsonResponse(response_data)
        
    except LoanApplication.DoesNotExist:
        return JsonResponse({'error': 'Application not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting application details: {str(e)}")
        return JsonResponse({'error': 'Failed to get application details'}, status=500)

# UPDATED: Other protected views
@login_required(login_url='fraud_detection:login')
@user_passes_test(is_admin, login_url='fraud_detection:login')
def application_details(request, application_id):
    """
    Get detailed information about a specific application - properly protected
    """
    try:
        from .models import LoanApplication, FraudAlert
        import json
        
        application = LoanApplication.objects.get(id=application_id)
        
        # Get fraud alerts for this application
        fraud_alerts = FraudAlert.objects.filter(loan_application=application)
        
        # Parse metadata
        metadata = {}
        ml_analysis = {}
        try:
            if application.metadata:
                metadata = json.loads(application.metadata) if isinstance(application.metadata, str) else application.metadata
                ml_analysis = metadata.get('ml_analysis', {})
        except (json.JSONDecodeError, TypeError):
            pass
        
        # Get visitor information
        visitor_info = None
        if application.visitor_id:
            visitor = application.visitor_id
            visitor_info = {
                'visitor_id': visitor.visitor_id,
                'ip_address': visitor.ip_address,
                'public_ip': visitor.public_ip,
                'confidence_score': visitor.confidence_score,
                'browser_name': visitor.browser_name,
                'os': visitor.os,
                'device': visitor.device,
                'application_count': visitor.application_count,
                'last_application_date': visitor.last_application_date.isoformat() if visitor.last_application_date else None
            }
        
        # Get smart signals
        smart_signals = {
            'bot_detected': application.bot_detected,
            'vpn_detected': application.vpn_detected,
            'proxy_detected': application.proxy_detected,
            'tor_detected': application.tor_detected,
            'tampering_detected': application.tampering_detected,
            'incognito': application.incognito,
            'ip_blocklisted': application.ip_blocklisted
        }
        
        response_data = {
            'application': {
                'id': str(application.id),
                'full_name': application.full_name,
                'email': application.email,
                'phone': application.phone,
                'address': application.address,
                'employment_status': application.employment_status,
                'occupation': application.occupation,
                'amount_requested': float(application.amount_requested),
                'repayment_duration': application.repayment_duration,
                'purpose': application.purpose,
                'status': application.status,
                'risk_score': float(application.risk_score),
                'application_date': application.application_date.isoformat(),
                'last_modified': application.last_modified.isoformat()
            },
            'visitor_info': visitor_info,
            'smart_signals': smart_signals,
            'ml_analysis': ml_analysis,
            'fraud_alerts': [
                {
                    'id': alert.id,
                    'reason': alert.reason,
                    'status': alert.status,
                    'risk_score': float(alert.risk_score),
                    'created_at': alert.created_at.isoformat(),
                    'resolved': alert.resolved
                }
                for alert in fraud_alerts
            ],
            'metadata': metadata
        }
        
        return JsonResponse(response_data)
        
    except LoanApplication.DoesNotExist:
        return JsonResponse({'error': 'Application not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting application details: {str(e)}")
        return JsonResponse({'error': 'Failed to get application details'}, status=500)


@csrf_protect
def get_smart_signals(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # Debugging: Print the secret key
        print("FingerprintJS Secret Key:", settings.FINGERPRINTJS_SECRET_KEY)  # Debugging
        
        print("Request Headers:", request.headers)  # Debugging
        print("Request Body:", request.body)  # Debugging

        data = json.loads(request.body)
        request_id = data.get("requestId")

        if not request_id:
            return JsonResponse({"error": "Missing request ID"}, status=400)

        url = f"https://api.fpjs.io/events/{request_id}"
        headers = {
            "Auth-API-Key": f"{settings.FINGERPRINTJS_SECRET_KEY}",  # Corrected header key
            "Accept": "application/json"
        }

        response = requests.get(url, headers=headers)
        print("FingerprintJS Response:", response.status_code, response.text)  # Debugging

        if response.status_code != 200:
            return JsonResponse({"error": "Failed to fetch smart signals"}, status=response.status_code)

        return JsonResponse(response.json())

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except Exception as e:
        print("Internal Server Error:", str(e))  # Debugging
        return JsonResponse({"error": str(e)}, status=500)


def track_visitor(request):
    """
    Extracts client IP & User-Agent, retrieves Visitor ID from Fingerprint API, and stores it in the database.
    """
    client_ip = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "Unknown")

    visitor_id = get_visitor_id(client_ip, user_agent)

    if visitor_id:
        visitor, created = VisitorID.objects.get_or_create(
            visitor_id=visitor_id,
            defaults={"ip_address": client_ip, "device_info": user_agent}
        )
        return JsonResponse({"message": "Visitor tracked successfully", "visitor_id": visitor.visitor_id})

    return JsonResponse({"error": "Could not retrieve visitor ID"}, status=400)


@csrf_exempt
def get_fingerprint_visitor_id(request):
    """
    API Endpoint: Fetches and stores Visitor ID for fraud detection.
    """
    if request.method == "POST":
        try:
            visitor_id = store_visitor_data(request)
            if visitor_id:
                return JsonResponse({"visitor_id": visitor_id}, status=200)
            return JsonResponse({"error": "Unable to retrieve visitor ID"}, status=400)
        except Exception as e:
            logger.error(f"Error processing visitor ID request: {str(e)}")
            return JsonResponse({"error": "Internal server error"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

def application_success(request):
    """
    Success page after loan application submission
    """
    # You can pass application reference or other context
    context = {
        'reference_number': request.session.get('application_reference', 'PROCESSING')
    }
    return render(request, 'fraud_detection/success.html', context)

@csrf_exempt
def apply_for_loan(request):
    try:
        if request.method != "POST":
            return JsonResponse({"error": "Invalid request method"}, status=405)
        form = LoanApplicationForm(request.POST)
        if not form.is_valid():
            return JsonResponse({
                "error": "Invalid form data",
                "details": dict(form.errors)
            }, status=400)
        extended_metadata_str = request.POST.get('extended_metadata', '')
        if not extended_metadata_str:
            return JsonResponse({
                "error": "Invalid metadata format",
                "details": "Extended metadata is empty"
            }, status=400)
        try:
            extended_metadata = json.loads(extended_metadata_str)
        except json.JSONDecodeError:
            return JsonResponse({
                "error": "Invalid JSON format",
                "details": "Extended metadata must be valid JSON"
            }, status=400)
        
        # Initialize services
        fraud_detection_service = FraudDetectionService()
        risk_scoring_service = RiskScoringService()
        
        # Process loan application within transaction
        try:
            with transaction.atomic():
                loan_app = form.save(commit=False)
                loan_app.metadata = extended_metadata_str
                
                # Get or create visitor ID
                visitor_data = {
                    'ip_address': get_client_ip(request),
                    'public_ip': extended_metadata.get('publicIpAddress'),
                    'confidence_score': extended_metadata.get('confidence', 0),
                    'browser_name': extended_metadata.get('browserDetails', {}).get('browser'),
                    'browser_version': extended_metadata.get('browserDetails', {}).get('version'),
                    'os': extended_metadata.get('osDetails', {}).get('os'),
                    'os_version': extended_metadata.get('osDetails', {}).get('version'),
                    'device': extended_metadata.get('device'),
                    'first_seen_at': extended_metadata.get('firstSeenAt'),
                    'last_seen_at': extended_metadata.get('lastSeenAt'),
                }
                
                # Create visitor first without applications count
                visitor, created = VisitorID.objects.get_or_create(
                    visitor_id=extended_metadata['visitorId'],
                    defaults=visitor_data
                )
                
                # Update visitor data if it exists
                if not created:
                    for key, value in visitor_data.items():
                        setattr(visitor, key, value)
                
                # Save loan application with visitor ID
                loan_app.visitor_id = visitor
                loan_app.ip_address = visitor_data['ip_address']
                loan_app.public_ip = visitor_data['public_ip']
                loan_app.confidence_score = visitor_data['confidence_score']
                
                # Set smart signals and incognito
                smart_signals = extended_metadata.get('smartSignals', {})
                loan_app.bot_detected = smart_signals.get('botDetection', False)
                loan_app.ip_blocklisted = smart_signals.get('ipBlocklist', False)
                loan_app.tor_detected = smart_signals.get('tor', False)
                loan_app.vpn_detected = smart_signals.get('vpn', False)
                loan_app.proxy_detected = smart_signals.get('proxy', False)
                loan_app.tampering_detected = smart_signals.get('tampering', False)
                loan_app.incognito = extended_metadata.get('incognito', None)
                
                # Save initial application data
                loan_app.save()
                
                # Detect fraud and calculate risk score
                fraud_detected, risk_score = fraud_detection_service.detect_fraud(loan_app)
                
                # Update loan application with final status
                decision = risk_scoring_service.get_decision(risk_score)
                loan_app.risk_score = risk_score
                loan_app.status = decision
                loan_app.save()
                
                # Update visitor with correct count
                if created:
                    # For new visitors, increment count immediately
                    VisitorID.objects.filter(pk=visitor.pk).update(
                        application_count=F('application_count') + 1,
                        last_application_date=timezone.now()
                    )
                else:
                    # For existing visitors, update count and date
                    visitor.application_count = visitor.loanapplication_set.count()
                    visitor.last_application_date = timezone.now()
                    visitor.save()
                
                return JsonResponse({
                    "message": "Application submitted successfully",
                    "risk_score": risk_score,
                    "decision": decision,
                    "fraud_detected": fraud_detected,
                    "status": loan_app.status
                }, status=201)
            
        except Exception as e:
            logger.error(f"Error processing loan application: {str(e)}")
            return JsonResponse({"error": "Unexpected server error"}, status=500)
        
    except Exception as e:
        logger.error(f"Error in apply_for_loan view: {str(e)}")
        return JsonResponse({"error": "Unexpected server error"}, status=500)


@csrf_exempt
def apply_for_loan_enhanced(request):
    """
    Enhanced loan application processing with ML fraud detection.
    Updated to redirect after successful submission.
    """
    try:
        if request.method != "POST":
            return JsonResponse({"error": "Invalid request method"}, status=405)
            
        form = LoanApplicationForm(request.POST)
        if not form.is_valid():
            return JsonResponse({
                "error": "Invalid form data",
                "details": dict(form.errors)
            }, status=400)
            
        extended_metadata_str = request.POST.get('extended_metadata', '')
        if not extended_metadata_str:
            return JsonResponse({
                "error": "Invalid metadata format",
                "details": "Extended metadata is empty"
            }, status=400)
            
        try:
            extended_metadata = json.loads(extended_metadata_str)
        except json.JSONDecodeError:
            return JsonResponse({
                "error": "Invalid JSON format",
                "details": "Extended metadata must be valid JSON"
            }, status=400)
        
        # Initialize enhanced services
        enhanced_fraud_service = EnhancedFraudDetectionService()
        enhanced_risk_service = EnhancedRiskScoringService()
        
        try:
            with transaction.atomic():
                loan_app = form.save(commit=False)
                loan_app.metadata = extended_metadata_str
                
                # Visitor details
                visitor_data = {
                    'ip_address': get_client_ip(request),
                    'public_ip': extended_metadata.get('publicIpAddress'),
                    'confidence_score': extended_metadata.get('confidence', 0),
                    'browser_name': extended_metadata.get('browserDetails', {}).get('browser'),
                    'browser_version': extended_metadata.get('browserDetails', {}).get('version'),
                    'os': extended_metadata.get('osDetails', {}).get('os'),
                    'os_version': extended_metadata.get('osDetails', {}).get('version'),
                    'device': extended_metadata.get('device'),
                    'first_seen_at': extended_metadata.get('firstSeenAt'),
                    'last_seen_at': extended_metadata.get('lastSeenAt'),
                }
                
                visitor, created = VisitorID.objects.get_or_create(
                    visitor_id=extended_metadata['visitorId'],
                    defaults=visitor_data
                )
                
                if not created:
                    for key, value in visitor_data.items():
                        setattr(visitor, key, value)
                
                # Link visitor to application
                loan_app.visitor_id = visitor
                loan_app.ip_address = visitor_data['ip_address']
                loan_app.public_ip = visitor_data['public_ip']
                loan_app.confidence_score = visitor_data['confidence_score']
                
                # Smart signals
                smart_signals = extended_metadata.get('smartSignals', {})
                loan_app.bot_detected = smart_signals.get('botDetection', False)
                loan_app.ip_blocklisted = smart_signals.get('ipBlocklist', False)
                loan_app.tor_detected = smart_signals.get('tor', False)
                loan_app.vpn_detected = smart_signals.get('vpn', False)
                loan_app.proxy_detected = smart_signals.get('proxy', False)
                loan_app.tampering_detected = smart_signals.get('tampering', False)
                loan_app.incognito = extended_metadata.get('incognito', None)
                
                loan_app.save()
                
                # ML fraud detection
                fraud_detected, enhanced_risk_score, ml_results = enhanced_fraud_service.detect_fraud_with_ml(loan_app)
                
                decision_info = get_enhanced_decision_with_explanation(
                    loan_app, enhanced_risk_score, ml_results
                )
                
                loan_app.risk_score = enhanced_risk_score
                loan_app.status = decision_info['decision']
                loan_app.save()
                
                # Update visitor stats
                if created:
                    VisitorID.objects.filter(pk=visitor.pk).update(
                        application_count=F('application_count') + 1,
                        last_application_date=timezone.now()
                    )
                else:
                    visitor.application_count = visitor.loanapplication_set.count()
                    visitor.last_application_date = timezone.now()
                    visitor.save()
                
                # Save minimal info in session for the success page
                request.session['application_reference'] = str(loan_app.id)[:8].upper()
                request.session['application_status'] = decision_info['decision']
                
                # Send JSON response with redirect URL (works for AJAX)
                return JsonResponse({
                    "success": True,
                    "message": "Application submitted successfully",
                    "redirect_url": "/success/"
                }, status=201)
            
        except Exception as e:
            logger.error(f"Error processing enhanced loan application: {str(e)}")
            return JsonResponse({"error": "Server error in ML processing"}, status=500)
        
    except Exception as e:
        logger.error(f"Error in enhanced apply_for_loan view: {str(e)}")
        return JsonResponse({"error": "Unexpected server error"}, status=500)


@csrf_exempt 
def get_ml_insights(request):
    """
    API endpoint to get ML insights for existing applications.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
    try:
        application_id = request.GET.get('application_id')
        if not application_id:
            return JsonResponse({"error": "Application ID required"}, status=400)
        
        try:
            loan_app = LoanApplication.objects.get(id=application_id)
        except LoanApplication.DoesNotExist:
            return JsonResponse({"error": "Application not found"}, status=404)
        
        # Initialize ML services
        ml_enhancer = MLFraudEnhancer()
        behavioral_analyzer = ml_enhancer.behavioral_analyzer
        
        # Get fresh ML analysis
        behavioral_analysis = behavioral_analyzer.analyze_current_application(loan_app)
        ml_results = ml_enhancer.enhance_fraud_detection(loan_app, float(loan_app.risk_score))
        
        # Get decision explanation
        decision_info = get_enhanced_decision_with_explanation(
            loan_app, ml_results['enhanced_risk_score'], ml_results
        )
        
        return JsonResponse({
            "application_id": str(loan_app.id),
            "current_status": loan_app.status,
            "original_risk_score": float(loan_app.risk_score),
            "enhanced_risk_score": ml_results['enhanced_risk_score'],
            "ml_risk_adjustment": ml_results['ml_risk_adjustment'],
            "decision_info": decision_info,
            "behavioral_analysis": behavioral_analysis,
            "recommendations": _generate_recommendations(behavioral_analysis, loan_app)
        })
        
    except Exception as e:
        logger.error(f"Error getting ML insights: {str(e)}")
        return JsonResponse({"error": "Failed to generate ML insights"}, status=500)

def _generate_recommendations(behavioral_analysis, loan_app):
    """Generate actionable recommendations based on ML analysis."""
    recommendations = []
    
    # Anomaly-based recommendations
    if behavioral_analysis.get('anomaly_detected'):
        recommendations.append({
            "type": "review_required",
            "priority": "high",
            "message": "Manual review recommended due to anomalous behavioral pattern",
            "action": "Schedule detailed verification call with applicant"
        })
    
    # Smart signals recommendations
    if loan_app.bot_detected:
        recommendations.append({
            "type": "security_check",
            "priority": "high", 
            "message": "Bot activity detected - potential automated fraud",
            "action": "Verify human interaction through additional authentication"
        })
    
    if loan_app.vpn_detected or loan_app.proxy_detected:
        recommendations.append({
            "type": "identity_verification",
            "priority": "medium",
            "message": "Network anonymization detected",
            "action": "Request additional identity verification documents"
        })
    
    # Behavioral pattern recommendations
    behavioral_risk = behavioral_analysis.get('behavioral_risk')
    if behavioral_risk == 'high':
        recommendations.append({
            "type": "risk_mitigation",
            "priority": "high",
            "message": "High behavioral risk detected",
            "action": "Consider lower loan amount or additional collateral"
        })
    
    # Application frequency recommendations
    if loan_app.visitor_id and loan_app.visitor_id.application_count > 3:
        recommendations.append({
            "type": "frequency_check",
            "priority": "medium",
            "message": f"Multiple applications ({loan_app.visitor_id.application_count}) from same device",
            "action": "Verify legitimate need and prevent application farming"
        })
    
    return recommendations

# Additional utility endpoint for batch ML analysis
@csrf_exempt
def batch_ml_analysis(request):
    """
    Run ML analysis on multiple applications (admin feature).
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
    try:
        data = json.loads(request.body)
        application_ids = data.get('application_ids', [])
        
        if not application_ids:
            return JsonResponse({"error": "No application IDs provided"}, status=400)
        
        # Limit batch size to prevent performance issues
        if len(application_ids) > 50:
            return JsonResponse({"error": "Batch size limited to 50 applications"}, status=400)
        
        results = []
        ml_enhancer = MLFraudEnhancer()
        
        for app_id in application_ids:
            try:
                loan_app = LoanApplication.objects.get(id=app_id)
                
                # Run ML analysis
                behavioral_analysis = ml_enhancer.behavioral_analyzer.analyze_current_application(loan_app)
                ml_results = ml_enhancer.enhance_fraud_detection(loan_app, float(loan_app.risk_score))
                
                results.append({
                    "application_id": str(loan_app.id),
                    "applicant_name": loan_app.full_name,
                    "original_risk": float(loan_app.risk_score),
                    "enhanced_risk": ml_results['enhanced_risk_score'],
                    "ml_adjustment": ml_results['ml_risk_adjustment'],
                    "behavioral_risk": behavioral_analysis.get('behavioral_risk'),
                    "anomaly_detected": behavioral_analysis.get('anomaly_detected'),
                    "recommendation": "review" if behavioral_analysis.get('anomaly_detected') else "approve"
                })
                
            except LoanApplication.DoesNotExist:
                results.append({
                    "application_id": app_id,
                    "error": "Application not found"
                })
            except Exception as e:
                results.append({
                    "application_id": app_id,
                    "error": str(e)
                })
        
        # Generate summary statistics
        successful_analyses = [r for r in results if 'error' not in r]
        summary = {
            "total_analyzed": len(successful_analyses),
            "high_risk_count": len([r for r in successful_analyses if r.get('enhanced_risk', 0) > 70]),
            "anomalies_detected": len([r for r in successful_analyses if r.get('anomaly_detected')]),
            "avg_risk_adjustment": sum(r.get('ml_adjustment', 0) for r in successful_analyses) / len(successful_analyses) if successful_analyses else 0
        }
        
        return JsonResponse({
            "summary": summary,
            "results": results
        })
        
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except Exception as e:
        logger.error(f"Error in batch ML analysis: {str(e)}")
        return JsonResponse({"error": "Batch analysis failed"}, status=500)

@staff_member_required
def fraud_analytics(request):
    """
    Get fraud analytics data for dashboard charts.
    """
    try:
        # Get data for last 30 days
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=30)
        
        # Daily application counts
        daily_stats = []
        current_date = start_date
        
        while current_date <= end_date:
            day_applications = LoanApplication.objects.filter(
                application_date__date=current_date
            )
            
            daily_stats.append({
                'date': current_date.isoformat(),
                'total_applications': day_applications.count(),
                'high_risk': day_applications.filter(risk_score__gt=70).count(),
                'fraud_alerts': FraudAlert.objects.filter(
                    created_at__date=current_date
                ).count()
            })
            
            current_date += timedelta(days=1)
        
        # Risk score distribution
        risk_distribution = {
            'low': LoanApplication.objects.filter(risk_score__lte=40).count(),
            'medium': LoanApplication.objects.filter(risk_score__gt=40, risk_score__lte=70).count(),
            'high': LoanApplication.objects.filter(risk_score__gt=70).count()
        }
        
        # Status distribution
        status_distribution = dict(
            LoanApplication.objects.values('status').annotate(count=Count('status'))
            .values_list('status', 'count')
        )
        
        # ML insights
        recent_applications = LoanApplication.objects.filter(
            application_date__gte=timezone.now() - timedelta(days=7)
        )
        
        ml_insights = {
            'total_analyzed': recent_applications.count(),
            'anomalies_detected': 0,
            'behavioral_risks': {'low': 0, 'medium': 0, 'high': 0}
        }
        
        # Parse ML data from metadata
        for app in recent_applications:
            try:
                if app.metadata:
                    metadata = json.loads(app.metadata) if isinstance(app.metadata, str) else app.metadata
                    ml_analysis = metadata.get('ml_analysis', {})
                    
                    if ml_analysis.get('anomaly_detected'):
                        ml_insights['anomalies_detected'] += 1
                    
                    behavioral_risk = ml_analysis.get('behavioral_risk', 'medium')
                    if behavioral_risk in ml_insights['behavioral_risks']:
                        ml_insights['behavioral_risks'][behavioral_risk] += 1
            except (json.JSONDecodeError, TypeError):
                continue
        
        return JsonResponse({
            'daily_stats': daily_stats,
            'risk_distribution': risk_distribution,
            'status_distribution': status_distribution,
            'ml_insights': ml_insights
        })
        
    except Exception as e:
        logger.error(f"Error getting fraud analytics: {str(e)}")
        return JsonResponse({'error': 'Failed to get analytics data'}, status=500)



@staff_member_required
def export_applications(request):
    """
    Export applications data as CSV.
    """
    try:
        from django.http import HttpResponse
        import csv
        
        # Get filters from request
        status_filter = request.GET.get('status')
        risk_filter = request.GET.get('risk')
        days = int(request.GET.get('days', 30))
        
        # Build query
        start_date = timezone.now() - timedelta(days=days)
        applications = LoanApplication.objects.filter(application_date__gte=start_date)
        
        if status_filter:
            applications = applications.filter(status=status_filter)
            
        if risk_filter == 'low':
            applications = applications.filter(risk_score__lte=40)
        elif risk_filter == 'medium':
            applications = applications.filter(risk_score__gt=40, risk_score__lte=70)
        elif risk_filter == 'high':
            applications = applications.filter(risk_score__gt=70)
        
        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="veriloan_applications_{timezone.now().date()}.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Application ID', 'Full Name', 'Email', 'Phone', 'Amount Requested',
            'Risk Score', 'Status', 'Application Date', 'ML Anomaly',
            'Behavioral Risk', 'Bot Detected', 'VPN Detected', 'Visitor ID'
        ])
        
        for app in applications:
            # Parse ML data
            ml_anomaly = 'No'
            behavioral_risk = 'Unknown'
            
            try:
                if app.metadata:
                    metadata = json.loads(app.metadata) if isinstance(app.metadata, str) else app.metadata
                    ml_analysis = metadata.get('ml_analysis', {})
                    ml_anomaly = 'Yes' if ml_analysis.get('anomaly_detected') else 'No'
                    behavioral_risk = ml_analysis.get('behavioral_risk', 'Unknown').title()
            except (json.JSONDecodeError, TypeError):
                pass
            
            writer.writerow([
                str(app.id)[:8],  # Shortened ID
                app.full_name,
                app.email,
                app.phone,
                float(app.amount_requested),
                float(app.risk_score),
                app.status,
                app.application_date.strftime('%Y-%m-%d %H:%M'),
                ml_anomaly,
                behavioral_risk,
                'Yes' if app.bot_detected else 'No',
                'Yes' if app.vpn_detected else 'No',
                app.visitor_id.visitor_id if app.visitor_id else 'None'
            ])
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting applications: {str(e)}")
        return JsonResponse({'error': 'Failed to export data'}, status=500)



@staff_member_required
def bulk_update_status(request):
    """
    Bulk update application statuses (admin action).
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        data = json.loads(request.body)
        application_ids = data.get('application_ids', [])
        new_status = data.get('status')
        reason = data.get('reason', '')
        
        if not application_ids:
            return JsonResponse({'error': 'No application IDs provided'}, status=400)
        
        if new_status not in ['PENDING', 'APPROVE', 'REJECT', 'FLAGGED', 'UNDER_REVIEW']:
            return JsonResponse({'error': 'Invalid status'}, status=400)
        
        # Limit bulk operations to prevent performance issues
        if len(application_ids) > 100:
            return JsonResponse({'error': 'Bulk update limited to 100 applications'}, status=400)
        
        updated_count = 0
        failed_updates = []
        
        with transaction.atomic():
            for app_id in application_ids:
                try:
                    application = LoanApplication.objects.get(id=app_id)
                    old_status = application.status
                    application.status = new_status
                    application.save()
                    
                    # Log the change
                    logger.info(f"Bulk update: Application {app_id} status changed from {old_status} to {new_status}. Reason: {reason}")
                    
                    # Update related fraud alerts if approved
                    if new_status == 'APPROVE':
                        FraudAlert.objects.filter(loan_application=application).update(resolved=True)
                    
                    updated_count += 1
                    
                except LoanApplication.DoesNotExist:
                    failed_updates.append(f"Application {app_id} not found")
                except Exception as e:
                    failed_updates.append(f"Failed to update {app_id}: {str(e)}")
        
        response_data = {
            'message': f'Successfully updated {updated_count} applications',
            'updated_count': updated_count,
            'total_requested': len(application_ids)
        }
        
        if failed_updates:
            response_data['failed_updates'] = failed_updates
        
        return JsonResponse(response_data)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error in bulk status update: {str(e)}")
        return JsonResponse({'error': 'Bulk update failed'}, status=500)

@staff_member_required
def bulk_update_final_status(request):
    """
    Bulk update final application statuses (staff decisions only) - UPDATED FUNCTION
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        data = json.loads(request.body)
        application_ids = data.get('application_ids', [])
        new_final_status = data.get('final_status')
        staff_comments = data.get('staff_comments', '')
        
        if not application_ids:
            return JsonResponse({'error': 'No application IDs provided'}, status=400)
        
        # Validate final status
        valid_final_statuses = [choice[0] for choice in LoanApplication.FINAL_STATUS_CHOICES]
        if new_final_status not in valid_final_statuses:
            return JsonResponse({'error': 'Invalid final status'}, status=400)
        
        # Limit bulk operations
        if len(application_ids) > 100:
            return JsonResponse({'error': 'Bulk update limited to 100 applications'}, status=400)
        
        updated_count = 0
        failed_updates = []
        
        with transaction.atomic():
            for app_id in application_ids:
                try:
                    application = LoanApplication.objects.get(id=app_id)
                    
                    # Check if staff can make decisions on this application
                    if not application.can_staff_decide:
                        failed_updates.append(
                            f"Application {app_id}: Cannot update - {application.status} by fraud detection"
                        )
                        continue
                    
                    old_final_status = application.final_status
                    application.final_status = new_final_status
                    application.staff_comments = staff_comments
                    application.staff_decision_by = request.user
                    application.staff_decision_date = timezone.now()
                    application.save()
                    
                    # Log the change
                    logger.info(
                        f"Bulk update: Application {app_id} final status changed from {old_final_status} "
                        f"to {new_final_status} by {request.user.username}. Comments: {staff_comments}"
                    )
                    
                    updated_count += 1
                    
                except LoanApplication.DoesNotExist:
                    failed_updates.append(f"Application {app_id} not found")
                except Exception as e:
                    failed_updates.append(f"Failed to update {app_id}: {str(e)}")
        
        response_data = {
            'message': f'Successfully updated {updated_count} applications',
            'updated_count': updated_count,
            'total_requested': len(application_ids)
        }
        
        if failed_updates:
            response_data['failed_updates'] = failed_updates
        
        return JsonResponse(response_data)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error in bulk final status update: {str(e)}")
        return JsonResponse({'error': 'Bulk update failed'}, status=500)

@staff_member_required
def add_application_comment(request):
    """
    Add comment to an application (admin action).
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        data = json.loads(request.body)
        application_id = data.get('application_id')
        comment = data.get('comment', '').strip()
        
        if not application_id or not comment:
            return JsonResponse({'error': 'Application ID and comment are required'}, status=400)
        
        application = LoanApplication.objects.get(id=application_id)
        
        # For now, we'll store comments in the metadata
        # In a production system, you'd want a separate Comments model
        try:
            metadata = json.loads(application.metadata) if isinstance(application.metadata, str) else application.metadata
        except (json.JSONDecodeError, TypeError):
            metadata = {}
        
        if 'admin_comments' not in metadata:
            metadata['admin_comments'] = []
        
        metadata['admin_comments'].append({
            'comment': comment,
            'timestamp': timezone.now().isoformat(),
            'admin_user': request.user.username if hasattr(request.user, 'username') else 'system'
        })
        
        application.metadata = json.dumps(metadata)
        application.save()
        
        # Log the comment
        logger.info(f"Comment added to application {application_id} by {request.user.username if hasattr(request.user, 'username') else 'system'}")
        
        return JsonResponse({
            'message': 'Comment added successfully',
            'comment_count': len(metadata['admin_comments'])
        })
        
    except LoanApplication.DoesNotExist:
        return JsonResponse({'error': 'Application not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error adding comment: {str(e)}")
        return JsonResponse({'error': 'Failed to add comment'}, status=500)

@staff_member_required
def get_application_comments(request):
    """
    Get comments for an application.
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        application_id = request.GET.get('application_id')
        if not application_id:
            return JsonResponse({'error': 'Application ID required'}, status=400)
        
        application = LoanApplication.objects.get(id=application_id)
        
        try:
            metadata = json.loads(application.metadata) if isinstance(application.metadata, str) else application.metadata
            comments = metadata.get('admin_comments', [])
        except (json.JSONDecodeError, TypeError):
            comments = []
        
        return JsonResponse({
            'comments': comments,
            'total_comments': len(comments)
        })
        
    except LoanApplication.DoesNotExist:
        return JsonResponse({'error': 'Application not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting comments: {str(e)}")
        return JsonResponse({'error': 'Failed to get comments'}, status=500)

@staff_member_required
def dashboard_stats_summary(request):
    """
    Get comprehensive dashboard statistics.
    """
    try:
        # Time periods
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        # Basic counts
        total_applications = LoanApplication.objects.count()
        applications_today = LoanApplication.objects.filter(application_date__date=today).count()
        applications_this_week = LoanApplication.objects.filter(application_date__date__gte=week_ago).count()
        applications_this_month = LoanApplication.objects.filter(application_date__date__gte=month_ago).count()
        
        # Status breakdown
        status_counts = dict(
            LoanApplication.objects.values('status')
            .annotate(count=Count('status'))
            .values_list('status', 'count')
        )
        
        # Risk analysis
        high_risk_count = LoanApplication.objects.filter(risk_score__gt=70).count()
        medium_risk_count = LoanApplication.objects.filter(risk_score__gt=40, risk_score__lte=70).count()
        low_risk_count = LoanApplication.objects.filter(risk_score__lte=40).count()
        
        # Fraud indicators
        bot_detected_count = LoanApplication.objects.filter(bot_detected=True).count()
        vpn_detected_count = LoanApplication.objects.filter(vpn_detected=True).count()
        proxy_detected_count = LoanApplication.objects.filter(proxy_detected=True).count()
        
        # Recent activity
        recent_flagged = LoanApplication.objects.filter(
            status='FLAGGED', 
            application_date__gte=timezone.now() - timedelta(days=1)
        ).count()
        
        # ML anomalies (from metadata analysis)
        ml_anomalies = 0
        recent_apps = LoanApplication.objects.filter(application_date__gte=week_ago)
        for app in recent_apps:
            try:
                if app.metadata:
                    metadata = json.loads(app.metadata) if isinstance(app.metadata, str) else app.metadata
                    ml_analysis = metadata.get('ml_analysis', {})
                    if ml_analysis.get('anomaly_detected'):
                        ml_anomalies += 1
            except (json.JSONDecodeError, TypeError):
                continue
        
        return JsonResponse({
            'overview': {
                'total_applications': total_applications,
                'applications_today': applications_today,
                'applications_this_week': applications_this_week,
                'applications_this_month': applications_this_month
            },
            'status_breakdown': status_counts,
            'risk_analysis': {
                'high_risk': high_risk_count,
                'medium_risk': medium_risk_count,
                'low_risk': low_risk_count
            },
            'security_alerts': {
                'bot_detected': bot_detected_count,
                'vpn_detected': vpn_detected_count,
                'proxy_detected': proxy_detected_count,
                'recent_flagged': recent_flagged
            },
            'ml_insights': {
                'anomalies_detected': ml_anomalies,
                'total_analyzed': recent_apps.count()
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        return JsonResponse({'error': 'Failed to get statistics'}, status=500)

# Update your existing update_application_status view to handle notifications
@staff_member_required
def update_application_status(request, application_id):
    """
    Update application status with notification support (admin action).
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        data = json.loads(request.body)
        new_status = data.get('status')
        reason = data.get('reason', '')
        send_notification = data.get('send_notification', False)
        
        if new_status not in ['PENDING', 'APPROVE', 'REJECT', 'FLAGGED', 'UNDER_REVIEW']:
            return JsonResponse({'error': 'Invalid status'}, status=400)
        
        application = LoanApplication.objects.get(id=application_id)
        old_status = application.status
        application.status = new_status
        application.save()
        
        # Log the change with reason
        logger.info(f"Application {application_id} status changed from {old_status} to {new_status} by {request.user.username if hasattr(request.user, 'username') else 'admin'}. Reason: {reason}")
        
        # Update related fraud alerts if needed
        if new_status == 'APPROVE':
            FraudAlert.objects.filter(loan_application=application).update(resolved=True)
        
        # In a real implementation, you would send actual email here
        # For now, we'll just indicate if notification was requested
        notification_sent = False
        if send_notification:
            # TODO: Implement actual email notification
            # send_status_update_email(application, new_status, reason)
            notification_sent = True
        
        return JsonResponse({
            'message': 'Status updated successfully',
            'new_status': new_status,
            'notification_sent': notification_sent,
            'applicant_email': application.email if send_notification else None
        })
        
    except LoanApplication.DoesNotExist:
        return JsonResponse({'error': 'Application not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error updating application status: {str(e)}")
        return JsonResponse({'error': 'Failed to update status'}, status=500)
    

@staff_member_required
def update_application_final_status(request, application_id):
    """
    Update FINAL application status (staff decision only) - NEW FUNCTION
    Staff can only update final_status, not the fraud detection status
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        data = json.loads(request.body)
        new_final_status = data.get('final_status')
        staff_comments = data.get('staff_comments', '')
        send_notification = data.get('send_notification', False)
        
        # Validate final status
        valid_final_statuses = [choice[0] for choice in LoanApplication.FINAL_STATUS_CHOICES]
        if new_final_status not in valid_final_statuses:
            return JsonResponse({'error': 'Invalid final status'}, status=400)
        
        application = LoanApplication.objects.get(id=application_id)
        
        # Check if staff can make decisions on this application
        if not application.can_staff_decide:
            return JsonResponse({
                'error': f'Cannot update final status. Application is {application.status} by fraud detection system.'
            }, status=400)
        
        # Store previous status for logging
        old_final_status = application.final_status
        
        # Update the application
        application.final_status = new_final_status
        application.staff_comments = staff_comments
        application.staff_decision_by = request.user
        application.staff_decision_date = timezone.now()
        application.save()
        
        # Log the change
        logger.info(
            f"Application {application_id} final status changed from {old_final_status} to {new_final_status} "
            f"by {request.user.username}. Comments: {staff_comments}"
        )
        
        # In a real implementation, send email notification here
        notification_sent = False
        if send_notification:
            # TODO: Implement actual email notification
            # send_final_status_notification(application, new_final_status, staff_comments)
            notification_sent = True
        
        return JsonResponse({
            'message': 'Final status updated successfully',
            'new_final_status': new_final_status,
            'display_status': application.display_status,
            'fraud_status': application.status,  # Show fraud status for context
            'can_staff_decide': application.can_staff_decide,
            'decision_date': application.staff_decision_date.isoformat() if application.staff_decision_date else None,
            'decided_by': request.user.username,
            'notification_sent': notification_sent
        })
        
    except LoanApplication.DoesNotExist:
        return JsonResponse({'error': 'Application not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error updating application final status: {str(e)}")
        return JsonResponse({'error': 'Failed to update final status'}, status=500)