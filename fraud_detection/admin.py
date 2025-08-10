# fraud_detection/admin.py

from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from .models import LoanApplication, VisitorID, FraudAlert

class FraudAlertInline(admin.TabularInline):
    model = FraudAlert
    extra = 0
    readonly_fields = ("reason", "created_at", "resolved", "status", "risk_score", "metadata")

@admin.register(FraudAlert)
class FraudAlertAdmin(admin.ModelAdmin):
    list_display = (
        "fraud_alert_id", "linked_loan_application", "linked_visitor_id", "status", 
        "risk_score", "decision", "reason", "metadata", "created_at", "resolved"
    )
    list_filter = ("resolved", "status")
    search_fields = ("loan_application__id", "visitor_id__visitor_id", "risk_score")
    ordering = ("-created_at",)
    actions = ["mark_as_resolved"]

    def mark_as_resolved(self, request, queryset):
        queryset.update(resolved=True)
    mark_as_resolved.short_description = "Mark selected alerts as resolved"

    def linked_loan_application(self, obj):
        url = reverse("admin:fraud_detection_loanapplication_change", args=[obj.loan_application.id])
        return format_html('<a href="{}">{}</a>', url, obj.loan_application.id)
    linked_loan_application.short_description = "Loan Application ID"

    def linked_visitor_id(self, obj):
        url = reverse("admin:fraud_detection_visitorid_change", args=[obj.visitor_id.id])
        return format_html('<a href="{}">{}</a>', url, obj.visitor_id.visitor_id)
    linked_visitor_id.short_description = "Visitor ID"

    def fraud_alert_id(self, obj):
        return obj.id  
    fraud_alert_id.short_description = "FraudAlert ID"

    def decision(self, obj):
        if obj.risk_score <= 40:
            return 'Low Risk - No action needed'
        elif obj.risk_score <= 70:
            return 'Medium Risk - Flag for manual review'
        else:
            return 'High Risk - Auto-reject loan'
    decision.short_description = "Decision"

@admin.register(LoanApplication)
class LoanApplicationAdmin(admin.ModelAdmin):
    def status_label(self, obj):
        return obj.get_status_display()
    status_label.short_description = "Status"
    status_label.admin_order_field = 'status'  

    list_display = (
        "full_name", "email", "amount_requested", "purpose", 
        "status_label", "risk_score", "risk_level", "application_date", 
        "linked_visitor_id", "linked_fraud_alerts", "linked_applications"
    )
    search_fields = ("full_name", "email", "visitor_id__visitor_id", "risk_score")
    list_filter = ("status", "application_date", "risk_score")  
    ordering = ("-application_date",)
    inlines = [FraudAlertInline]
    actions = ["approve_selected", "reject_selected"]

    def linked_applications(self, obj):
        return LoanApplication.objects.filter(visitor_id=obj.visitor_id).count()
    linked_applications.short_description = "Linked Applications"

    def linked_fraud_alerts(self, obj):
        return FraudAlert.objects.filter(loan_application=obj).count()
    linked_fraud_alerts.short_description = "Fraud Alerts Linked"

    def approve_selected(self, request, queryset):
        queryset.update(status="approve")
    approve_selected.short_description = "Approve selected applications"

    def reject_selected(self, request, queryset):
        queryset.update(status="rejected")
    reject_selected.short_description = "Reject selected applications"

    def linked_visitor_id(self, obj):
        url = reverse("admin:fraud_detection_visitorid_change", args=[obj.visitor_id.id])
        return format_html('<a href="{}">{}</a>', url, obj.visitor_id.visitor_id)
    linked_visitor_id.short_description = "Visitor ID"

    def risk_level(self, obj):
        if obj.risk_score <= 40:
            return 'Low Risk'
        elif obj.risk_score <= 70:
            return 'Medium Risk'
        else:
            return 'High Risk'
    risk_level.short_description = "Risk Level"

@admin.register(VisitorID)
class VisitorIDAdmin(admin.ModelAdmin):
    list_display = (
        "visitor_id", "ip_address", "public_ip", "device",  
        "application_count", "linked_fraud_alerts", "first_seen_at"
    )
    search_fields = ("visitor_id", "ip_address", "public_ip", "device")
    ordering = ("-application_count",)

    def linked_fraud_alerts(self, obj):
        return FraudAlert.objects.filter(visitor_id=obj).count()
    linked_fraud_alerts.short_description = "Fraud Alerts Linked"


# Change admin site titles
admin.site.site_header = "VeriLoan"
admin.site.site_title = "VeriLoan Admin"
admin.site.index_title = "VeriLoan Administration"