# fraud_detection/urls.py - Complete URL configuration
from django.urls import path
from . import views

app_name = 'fraud_detection'

urlpatterns = [
    # PUBLIC PAGES (No authentication required)
    path('', views.loan_form_home, name='loan_form_home'),  # Main loan form
    path('success/', views.application_success, name='application_success'),  # Success page
    
    # API ENDPOINTS (For form processing)
    path('api/get-smart-signals/', views.get_smart_signals, name='get_smart_signals'),
    path('api/apply-enhanced/', views.apply_for_loan_enhanced, name='apply_for_loan_enhanced'),
    path('api/visitor-id/', views.get_fingerprint_visitor_id, name='get_visitor_id'),
    
    # ADMIN AUTHENTICATION
    path('admin/login/', views.login_view, name='login'),
    path('admin/logout/', views.logout_view, name='logout'),
    
    # ADMIN DASHBOARD (Protected - staff only)
    path('admin/dashboard/', views.dashboard, name='dashboard'),
    path('admin/dashboard-data/', views.dashboard_data, name='dashboard_data'),
    path('admin/fraud-analytics/', views.fraud_analytics, name='fraud_analytics'),
    path('admin/application/<uuid:application_id>/', views.application_details, name='application_details'),
    path('admin/application/<uuid:application_id>/update-status/', views.update_application_status, name='update_application_status'),
    path('admin/export-applications/', views.export_applications, name='export_applications'),
    
    # ADMIN ML FEATURES (Protected)
    path('admin/ml-insights/', views.get_ml_insights, name='get_ml_insights'),
    path('admin/batch-analysis/', views.batch_ml_analysis, name='batch_ml_analysis'),

    # ADMIN BULK OPERATIONS (Add these new ones)
    path('admin/bulk-update-status/', views.bulk_update_status, name='bulk_update_status'),
    path('admin/add-comment/', views.add_application_comment, name='add_comment'),
    path('admin/get-comments/', views.get_application_comments, name='get_comments'),
    path('admin/stats-summary/', views.dashboard_stats_summary, name='stats_summary'),
]