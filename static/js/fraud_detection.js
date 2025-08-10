// Enhanced fraud_detection.js with dual status system support

document.addEventListener("DOMContentLoaded", async function () {
    const form = document.getElementById("loanForm");
    const publicKey = window.fingerprintjsPublicKey;

    // Get CSRF token from cookie
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Enhanced form submission with dual status handling
    form.addEventListener("submit", async function (event) {
        event.preventDefault();

        // Show loading state
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing Application...';
        submitBtn.disabled = true;

        try {
            const csrftoken = getCookie('csrftoken');

            // Load FingerprintJS
            const FingerprintJS = await import(`https://fpjscdn.net/v3/${publicKey}`);
            const fp = await FingerprintJS.load();
            const result = await fp.get({ extendedResult: true });

            // Send requestId to Django backend with CSRF token
            const smartSignalsResponse = await fetch("/api/get-smart-signals/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrftoken
                },
                body: JSON.stringify({ requestId: result.requestId })
            });

            if (!smartSignalsResponse.ok) {
                throw new Error(`Failed to fetch smart signals: ${smartSignalsResponse.statusText}`);
            }

            const smartSignalsData = await smartSignalsResponse.json();

            // Collect enhanced metadata including smart signals
            const extendedData = {
                requestId: result.requestId,
                visitorId: result.visitorId,
                firstSeenAt: result.firstSeenAt.global,
                lastSeenAt: result.lastSeenAt.global,
                browserDetails: {
                    browser: result.browserName,
                    version: result.browserVersion
                },
                osDetails: {
                    os: result.os,
                    version: result.osVersion,
                },
                device: result.device,
                publicIpAddress: result.ip,
                incognito: result.incognito,
                confidence: result.confidence?.score || 0,
                smartSignals: {
                    botDetection: smartSignalsData.products?.botd?.data?.bot?.result === 'detected',
                    ipBlocklist: smartSignalsData.products?.ipBlocklist?.data?.result || false,
                    tor: smartSignalsData.products?.tor?.data?.result || false,
                    vpn: smartSignalsData.products?.vpn?.data?.result || false,
                    proxy: smartSignalsData.products?.proxy?.data?.result || false,
                    tampering: smartSignalsData.products?.tampering?.data?.result || false,
                    velocity: smartSignalsData.products?.velocity?.data || {},
                    ipInfo: smartSignalsData.products?.ipInfo?.data?.v4 || {}
                }
            };

            // Append metadata to form
            document.getElementById("extended_metadata").value = JSON.stringify(extendedData);

            // Submit form using enhanced endpoint
            const formData = new FormData(form);
            const response = await fetch('/api/apply-enhanced/', {
                method: "POST",
                body: formData,
                headers: {
                    "X-CSRFToken": csrftoken
                }
            });

            const data = await response.json();

            // Handle enhanced response with dual status awareness
            if (response.ok) {
                // Check if redirect URL is provided (for success page)
                if (data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else {
                    // Fallback to displaying results (shouldn't happen with updated backend)
                    displayUserFriendlyResults(data);
                }
            } else {
                displayError(data.error || "Something went wrong. Please try again later.");
            }

        } catch (error) {
            console.error("Error processing application:", error);
            displayError("An unexpected error occurred. Please try again.");
        } finally {
            // Restore button state
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    });

    // Updated user-friendly results display (with dual status awareness)
    function displayUserFriendlyResults(result) {
        // Map backend decisions to user-friendly messages
        // Note: With dual status, users see simplified messaging
        const statusMessages = {
            // Backend fraud detection statuses
            'approve': {
                title: 'Application Submitted Successfully! 📋',
                message: 'Thank you for your application! Our team will review it and contact you within 2-3 business days with the final decision.',
                bgColor: '#d1ecf1',
                textColor: '#0c5460',
                icon: 'check-circle',
                nextSteps: [
                    'Your application has passed initial fraud checks',
                    'Our loan officers will now review your application', 
                    'You may be contacted for additional documentation',
                    'Final decision will be communicated within 2-3 business days'
                ]
            },
            'flagged': {
                title: 'Application Under Review 📋',
                message: 'Thank you for your application! We need to conduct additional verification. We\'ll get back to you within 3-5 business days.',
                bgColor: '#fff3cd',
                textColor: '#856404',
                icon: 'clock',
                nextSteps: [
                    'Additional verification is required',
                    'Our security team will review your application',
                    'You may be contacted for document verification',
                    'Please ensure your phone is accessible'
                ]
            },
            'rejected': {
                title: 'Application Update ℹ️',
                message: 'Thank you for your interest in VeriLoan. Unfortunately, we cannot process your application at this time. You may reapply after 30 days.',
                bgColor: '#f8d7da',
                textColor: '#721c24',
                icon: 'info-circle',
                nextSteps: [
                    'Your application did not meet our current criteria',
                    'You can reapply after 30 days',
                    'Consider improving your credit profile',
                    'Contact support if you have questions'
                ]
            },
            'pending': {
                title: 'Application Processing 🔄',
                message: 'Your application is being processed. We\'ll notify you once the initial review is complete.',
                bgColor: '#e2e3e5',
                textColor: '#383d41',
                icon: 'hourglass-half',
                nextSteps: [
                    'Application is in the processing queue',
                    'Initial fraud detection checks are running',
                    'You will receive an update shortly',
                    'Please monitor your email and phone'
                ]
            }
        };

        const status = statusMessages[result.status] || statusMessages['pending'];
        
        form.innerHTML = `
            <div class="result-container">
                <div class="alert text-center" style="background-color: ${status.bgColor}; color: ${status.textColor}; border: none; border-radius: 15px; padding: 3rem 2rem;">
                    <div class="mb-4">
                        <i class="fas fa-${status.icon} fa-4x mb-3"></i>
                        <h2 class="mb-3">${status.title}</h2>
                        <p class="lead mb-0">${status.message}</p>
                    </div>
                    
                    <!-- Application Reference -->
                    ${result.reference ? `
                    <div class="mt-4 p-3 rounded" style="background-color: rgba(255, 255, 255, 0.3);">
                        <h6><i class="fas fa-receipt me-2"></i>Application Reference</h6>
                        <h4 class="text-monospace">${result.reference}</h4>
                        <small>Please keep this reference number for your records</small>
                    </div>
                    ` : ''}
                    
                    <!-- Next Steps -->
                    <div class="mt-4 p-3 rounded" style="background-color: rgba(255, 255, 255, 0.2);">
                        <h6><i class="fas fa-list-check me-2"></i>What Happens Next?</h6>
                        <ul class="list-unstyled mb-0 text-start">
                            ${status.nextSteps.map(step => `<li class="mb-2"><i class="fas fa-arrow-right me-2"></i>${step}</li>`).join('')}
                        </ul>
                    </div>
                    
                    <!-- Expected Timeline -->
                    <div class="mt-4 p-3 rounded" style="background-color: rgba(255, 255, 255, 0.2);">
                        <h6><i class="fas fa-calendar-alt me-2"></i>Expected Timeline</h6>
                        <div class="row text-start">
                            <div class="col-md-6">
                                <strong>Initial Review:</strong><br>
                                <small>${result.status === 'approve' ? '✅ Completed' : result.status === 'rejected' ? '❌ Declined' : '⏳ In Progress'}</small>
                            </div>
                            <div class="col-md-6">
                                <strong>Final Decision:</strong><br>
                                <small>${result.status === 'rejected' ? '❌ Declined' : '⏳ 2-3 Business Days'}</small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <button type="button" class="btn btn-primary btn-lg me-3" onclick="submitNewApplication()">
                            <i class="fas fa-plus me-2"></i>New Application
                        </button>
                        <button type="button" class="btn btn-outline-primary" onclick="contactSupport()">
                            <i class="fas fa-headset me-2"></i>Contact Support
                        </button>
                    </div>
                </div>
                
                <!-- Trust Indicators -->
                <div class="row mt-4 text-center">
                    <div class="col-md-3">
                        <i class="fas fa-shield-alt fa-2x text-success mb-2"></i>
                        <h6>AI-Powered Security</h6>
                        <small class="text-muted">Advanced fraud detection protects all parties</small>
                    </div>
                    <div class="col-md-3">
                        <i class="fas fa-user-shield fa-2x text-info mb-2"></i>
                        <h6>Data Protection</h6>
                        <small class="text-muted">Your information is encrypted and secure</small>
                    </div>
                    <div class="col-md-3">
                        <i class="fas fa-clock fa-2x text-warning mb-2"></i>
                        <h6>Quick Processing</h6>
                        <small class="text-muted">Dual-layer review for optimal speed</small>
                    </div>
                    <div class="col-md-3">
                        <i class="fas fa-handshake fa-2x text-primary mb-2"></i>
                        <h6>Human Review</h6>
                        <small class="text-muted">Expert staff make final decisions</small>
                    </div>
                </div>
                
                <!-- Security Notice (for transparency about dual system) -->
                <div class="mt-4">
                    <div class="alert alert-info" style="border-radius: 10px;">
                        <h6><i class="fas fa-info-circle me-2"></i>Our Review Process</h6>
                        <p class="mb-0 small">
                            VeriLoan uses a dual-layer review system: 
                            <strong>AI fraud detection</strong> for security, followed by 
                            <strong>human expert review</strong> for final decisions. 
                            This ensures both security and personalized service.
                        </p>
                    </div>
                </div>
            </div>
        `;
    }

    function displayError(errorMessage) {
        // Enhanced error display with dual status context
        form.innerHTML = `
            <div class="alert alert-danger text-center" style="border-radius: 15px; padding: 3rem 2rem;">
                <i class="fas fa-exclamation-triangle fa-3x mb-3"></i>
                <h4>Application Submission Failed</h4>
                <p class="mb-4">${errorMessage}</p>
                
                <!-- Common error solutions -->
                <div class="text-start mt-4 p-3" style="background-color: rgba(255, 255, 255, 0.1); border-radius: 10px;">
                    <h6><i class="fas fa-lightbulb me-2"></i>Quick Solutions:</h6>
                    <ul class="mb-0">
                        <li>Check your internet connection</li>
                        <li>Ensure all required fields are completed</li>
                        <li>Try refreshing the page and submitting again</li>
                        <li>Contact support if the problem persists</li>
                    </ul>
                </div>
                
                <div class="mt-4">
                    <button type="button" class="btn btn-danger btn-lg me-3" onclick="location.reload()">
                        <i class="fas fa-redo me-2"></i>Try Again
                    </button>
                    <button type="button" class="btn btn-outline-danger" onclick="contactSupport()">
                        <i class="fas fa-headset me-2"></i>Get Help
                    </button>
                </div>
            </div>
        `;
    }

    // Global functions for button actions
    window.submitNewApplication = function() {
        if (confirm('Start a new loan application? This will clear the current form.')) {
            location.reload();
        }
    };

    window.contactSupport = function() {
        const supportModal = `
            <div class="modal fade" id="supportModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                            <h5 class="modal-title"><i class="fas fa-headset me-2"></i>VeriLoan Support Center</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="text-center mb-4">
                                <i class="fas fa-phone-alt fa-3x text-primary mb-3"></i>
                                <h6>We're here to help with your loan application!</h6>
                                <p class="text-muted">Our support team understands both our AI system and manual review process</p>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <h6><i class="fas fa-phone text-success me-2"></i>Phone Support</h6>
                                    <p><a href="tel:+2348000000000" class="btn btn-outline-success btn-sm">+234 800 000 0000</a></p>
                                    
                                    <h6><i class="fas fa-envelope text-warning me-2"></i>Email Support</h6>
                                    <p><a href="mailto:support@veriloan.com" class="btn btn-outline-warning btn-sm">support@veriloan.com</a></p>
                                    
                                    <h6><i class="fab fa-whatsapp text-success me-2"></i>WhatsApp</h6>
                                    <p><a href="https://wa.me/2348000000000" target="_blank" class="btn btn-outline-success btn-sm">Chat with us</a></p>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-clock text-info me-2"></i>Business Hours</h6>
                                    <ul class="list-unstyled">
                                        <li>Monday - Friday: 9AM - 6PM WAT</li>
                                        <li>Saturday: 10AM - 2PM WAT</li>
                                        <li>Sunday: Emergency support only</li>
                                    </ul>
                                    
                                    <h6><i class="fas fa-question-circle text-primary me-2"></i>Common Questions</h6>
                                    <ul class="list-unstyled small">
                                        <li>• Application status inquiries</li>
                                        <li>• Document verification help</li>
                                        <li>• Technical issues</li>
                                        <li>• Loan terms clarification</li>
                                    </ul>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <!-- FAQ Section -->
                            <div class="accordion" id="faqAccordion">
                                <div class="accordion-item">
                                    <h2 class="accordion-header" id="faq1">
                                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse1">
                                            How does your dual review system work?
                                        </button>
                                    </h2>
                                    <div id="collapse1" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                                        <div class="accordion-body small">
                                            Our AI system first checks for fraud and calculates risk scores. 
                                            Then our human experts review approved applications for final decisions. 
                                            This ensures both security and personalized service.
                                        </div>
                                    </div>
                                </div>
                                <div class="accordion-item">
                                    <h2 class="accordion-header" id="faq2">
                                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse2">
                                            How long does the review process take?
                                        </button>
                                    </h2>
                                    <div id="collapse2" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                                        <div class="accordion-body small">
                                            AI fraud detection is instant. Staff review typically takes 2-3 business days. 
                                            Applications flagged for additional verification may take 3-5 business days.
                                        </div>
                                    </div>
                                </div>
                                <div class="accordion-item">
                                    <h2 class="accordion-header" id="faq3">
                                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse3">
                                            What if my application is rejected?
                                        </button>
                                    </h2>
                                    <div id="collapse3" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                                        <div class="accordion-body small">
                                            You can reapply after 30 days. Consider improving your credit profile, 
                                            providing additional documentation, or applying for a smaller amount. 
                                            Contact support for personalized guidance.
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="alert alert-info mt-3">
                                <small><i class="fas fa-shield-alt me-1"></i>
                                <strong>Privacy Note:</strong> All support communications are encrypted and confidential. 
                                Please have your application reference number ready when contacting us.</small>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" onclick="window.open('https://wa.me/2348000000000', '_blank')">
                                <i class="fab fa-whatsapp me-1"></i> Chat Now
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal if any
        const existingModal = document.getElementById('supportModal');
        if (existingModal) existingModal.remove();
        
        document.body.insertAdjacentHTML('beforeend', supportModal);
        const modal = new bootstrap.Modal(document.getElementById('supportModal'));
        modal.show();
        
        // Remove modal from DOM after it's hidden
        document.getElementById('supportModal').addEventListener('hidden.bs.modal', function() {
            this.remove();
        });
    };

    // Add real-time form validation with dual status awareness
    addEnhancedFormValidation();
});

// Enhanced form validation with better UX
function addEnhancedFormValidation() {
    const form = document.getElementById("loanForm");
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, select, textarea');
    
    inputs.forEach(input => {
        input.addEventListener('blur', function() {
            validateField(this);
        });
        
        // Real-time validation for specific fields
        if (input.type === 'email') {
            input.addEventListener('input', debounce(function() {
                validateEmail(this);
            }, 500));
        }
        
        if (input.type === 'tel') {
            input.addEventListener('input', debounce(function() {
                validatePhone(this);
            }, 500));
        }
        
        if (input.name === 'amount_requested') {
            input.addEventListener('input', debounce(function() {
                validateAmount(this);
            }, 300));
        }
        
        // Add focus effects
        input.addEventListener('focus', function() {
            this.classList.remove('is-invalid');
        });
    });
    
    // Form submission validation
    form.addEventListener('submit', function(event) {
        let hasErrors = false;
        
        inputs.forEach(input => {
            if (!validateField(input) && input.required) {
                hasErrors = true;
            }
        });
        
        if (hasErrors) {
            event.preventDefault();
            showFormError('Please correct the errors above before submitting.');
        }
    });
}

function validateField(field) {
    const value = field.value.trim();
    let isValid = true;
    let message = '';
    
    // Clear previous validation
    clearValidation(field);
    
    if (!value && field.required) {
        isValid = false;
        message = `${getFieldLabel(field)} is required`;
    } else if (value) {
        switch(field.name) {
            case 'full_name':
                if (value.length < 3) {
                    isValid = false;
                    message = 'Full name must be at least 3 characters';
                } else if (!/^[a-zA-Z\s.'-]+$/.test(value)) {
                    isValid = false;
                    message = 'Name should only contain letters, spaces, and common punctuation';
                } else if (value.split(' ').length < 2) {
                    isValid = false;
                    message = 'Please enter your first and last name';
                }
                break;
                
            case 'address':
                if (value.length < 15) {
                    isValid = false;
                    message = 'Please provide a complete address with street, area, and city';
                }
                break;
                
            case 'purpose':
                if (value.length < 20) {
                    isValid = false;
                    message = 'Please provide more detailed information about the loan purpose';
                }
                break;
                
            case 'occupation':
                if (value.length < 3) {
                    isValid = false;
                    message = 'Please specify your occupation';
                }
                break;
        }
    }
    
    if (!isValid) {
        showFieldError(field, message);
        return false;
    } else if (value) {
        field.classList.add('is-valid');
        showFieldSuccess(field);
    }
    
    return true;
}

function validateEmail(emailField) {
    const email = emailField.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    clearValidation(emailField);
    
    if (!email) {
        if (emailField.required) {
            showFieldError(emailField, 'Email address is required');
            return false;
        }
        return true;
    }
    
    if (!emailRegex.test(email)) {
        showFieldError(emailField, 'Please enter a valid email address (e.g., name@example.com)');
        return false;
    }
    
    // Additional email validations
    const commonDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    const domain = email.split('@')[1];
    
    if (domain && !commonDomains.includes(domain) && !domain.includes('.')) {
        showFieldError(emailField, 'Please check your email domain');
        return false;
    }
    
    emailField.classList.add('is-valid');
    showFieldSuccess(emailField);
    return true;
}

function validatePhone(phoneField) {
    const phone = phoneField.value.trim().replace(/[\s-()]/g, '');
    const phoneRegex = /^(\+234|234|0)[789][01]\d{8}$/;
    
    clearValidation(phoneField);
    
    if (!phone) {
        if (phoneField.required) {
            showFieldError(phoneField, 'Phone number is required');
            return false;
        }
        return true;
    }
    
    if (!phoneRegex.test(phone)) {
        showFieldError(phoneField, 'Please enter a valid Nigerian phone number (e.g., 08012345678)');
        return false;
    }
    
    phoneField.classList.add('is-valid');
    showFieldSuccess(phoneField);
    return true;
}

function validateAmount(amountField) {
    const amount = parseFloat(amountField.value.replace(/,/g, ''));
    
    clearValidation(amountField);
    
    if (isNaN(amount)) {
        if (amountField.required) {
            showFieldError(amountField, 'Please enter a loan amount');
            return false;
        }
        return true;
    }
    
    if (amount < 10000) {
        showFieldError(amountField, 'Minimum loan amount is ₦10,000');
        return false;
    } else if (amount > 5000000) {
        showFieldError(amountField, 'Maximum loan amount is ₦5,000,000');
        return false;
    }
    
    // Format the amount with commas
    amountField.value = amount.toLocaleString();
    amountField.classList.add('is-valid');
    showFieldSuccess(amountField);
    return true;
}

// Helper functions
function getFieldLabel(field) {
    const label = field.closest('.form-group')?.querySelector('label');
    return label ? label.textContent.replace('*', '').trim() : field.name;
}

function clearValidation(field) {
    const feedback = field.parentNode.querySelector('.validation-feedback');
    if (feedback) feedback.remove();
    field.classList.remove('is-valid', 'is-invalid');
}

function showFieldError(field, message) {
    field.classList.add('is-invalid');
    const feedback = document.createElement('div');
    feedback.className = 'validation-feedback invalid-feedback d-block';
    feedback.innerHTML = `<i class="fas fa-exclamation-circle me-1"></i>${message}`;
    field.parentNode.appendChild(feedback);
}

function showFieldSuccess(field) {
    const feedback = document.createElement('div');
    feedback.className = 'validation-feedback valid-feedback d-block';
    feedback.innerHTML = `<i class="fas fa-check-circle me-1"></i>Looks good!`;
    field.parentNode.appendChild(feedback);
}

function showFormError(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-danger alert-dismissible fade show';
    alertDiv.innerHTML = `
        <i class="fas fa-exclamation-triangle me-2"></i>${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const form = document.getElementById('loanForm');
    form.insertBefore(alertDiv, form.firstChild);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        if (alertDiv && alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Utility function for debouncing
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func.apply(this, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Initialize enhanced features
document.addEventListener('DOMContentLoaded', function() {
    // Add loading states to form
    const form = document.getElementById('loanForm');
    if (form) {
        // Add progress indicator
        const progressDiv = document.createElement('div');
        progressDiv.className = 'progress mb-3';
        progressDiv.style.display = 'none';
        progressDiv.innerHTML = `
            <div class="progress-bar progress-bar-striped progress-bar-animated" 
                 role="progressbar" style="width: 0%"></div>
        `;
        form.insertBefore(progressDiv, form.firstChild);
        
        // Show progress during form submission
        form.addEventListener('submit', function() {
            progressDiv.style.display = 'block';
            let width = 0;
            const interval = setInterval(() => {
                width += Math.random() * 10;
                if (width >= 90) {
                    clearInterval(interval);
                    width = 90;
                }
                progressDiv.querySelector('.progress-bar').style.width = width + '%';
            }, 200);
        });
    }