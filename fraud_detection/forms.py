# fraud_detection/forms.py

from django import forms
from .models import LoanApplication
from django.contrib.auth.forms import AuthenticationForm

class LoginForm(AuthenticationForm):  # Renamed from AdminLoginForm
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))


class LoanApplicationForm(forms.ModelForm):
    extended_metadata = forms.JSONField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = LoanApplication
        fields = [
            'full_name', 'email', 'phone', 'address', 'employment_status', 'occupation',
            'amount_requested', 'repayment_duration', 'purpose', 'extended_metadata'
        ]
        widgets = {
            'purpose': forms.Textarea(attrs={'rows': 3}),
            'repayment_duration': forms.Select(attrs={'class': 'form-control'})
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['amount_requested'].widget.attrs.update({'min': 0, 'step': '0.01'})
        self.fields['employment_status'].widget.attrs.update({'class': 'form-control'})
    
    def clean_amount_requested(self):
        
        amount = self.cleaned_data['amount_requested']
        if amount <= 0:
            raise forms.ValidationError("Amount must be greater than zero")
        return amount
    
    def clean_phone(self):
        phone = self.cleaned_data['phone']
        if not phone.replace(' ', '').replace('+', '').isdigit():
            raise forms.ValidationError("Please enter a valid phone number")
        return phone
    
