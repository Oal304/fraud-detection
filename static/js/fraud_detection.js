// Enhanced fraud_detection.js with user-friendly results

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

    // Enhanced form submission with user-friendly results
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
                    botDetection: smartSignalsData.products.botd?.data?.bot?.result === 'detected',
                    ipBlocklist: smartSignalsData.products.ipBlocklist?.data?.result,
                    tor: smartSignalsData.products.tor?.data?.result,
                    vpn: smartSignalsData.products.vpn?.data?.result,
                    proxy: smartSignalsData.products.proxy?.data?.result,
                    tampering: smartSignalsData.products.tampering?.data?.result,
                    velocity: smartSignalsData.products.velocity?.data,
                    ipInfo: smartSignalsData.products.ipInfo?.data?.v4
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

            // Handle enhanced response with user-friendly messaging
            if (response.ok) {
                displayUserFriendlyResults(data);
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

    function displayUserFriendlyResults(result) {
        // User-friendly messaging without exposing risk scores or technical details
        const statusMessages = {
            'APPROVE': {
                title: 'Application Approved! 🎉',
                message: 'Congratulations! Your loan application has been approved. We\'ll contact you within 24 hours with next steps.',
                bgColor: '#d4edda',
                textColor: '#155724',
                icon: 'check-circle'
            },
            'REVIEW': {
                title: 'Application Under Review 📋',
                message: 'Thank you for your application! We\'re currently reviewing it and will get back to you within 2-3 business days.',
                bgColor: '#fff3cd',
                textColor: '#856404',
                icon: 'clock'
            },
            'REJECT': {
                title: 'Application Status ℹ️',
                message: 'Thank you for your interest. Unfortunately, we cannot approve your application at this time. You may reapply after 30 days.',
                bgColor: '#f8d7da',
                textColor: '#721c24',
                icon: 'info-circle'
            }
        };

        const status = statusMessages[result.decision] || statusMessages['REVIEW'];
        
        form.innerHTML = `
            <div class="result-container">
                <div class="alert text-center" style="background-color: ${status.bgColor}; color: ${status.textColor}; border: none; border-radius: 15px; padding: 3rem 2rem;">
                    <div class="mb-4">
                        <i class="fas fa-${status.icon} fa-4x mb-3"></i>
                        <h2 class="mb-3">${status.title}</h2>
                        <p class="lead mb-0">${status.message}</p>
                    </div>
                    
                    ${result.decision === 'APPROVE' ? `
                    <div class="mt-4 p-3 rounded" style="background-color: rgba(255, 255, 255, 0.3);">
                        <h6><i class="fas fa-info-circle me-2"></i>What Happens Next?</h6>
                        <ul class="list-unstyled mb-0 text-start">
                            <li><i class="fas fa-phone me-2"></i>Our loan officer will contact you</li>
                            <li><i class="fas fa-file-contract me-2"></i>Document verification process</li>
                            <li><i class="fas fa-money-bill-wave me-2"></i>Loan disbursement</li>
                        </ul>
                    </div>
                    ` : ''}
                    
                    ${result.decision === 'REVIEW' ? `
                    <div class="mt-4 p-3 rounded" style="background-color: rgba(255, 255, 255, 0.3);">
                        <h6><i class="fas fa-lightbulb me-2"></i>While You Wait</h6>
                        <p class="mb-0 text-start">Please ensure your phone is accessible and check your email regularly for any additional document requests.</p>
                    </div>
                    ` : ''}
                    
                    <div class="mt-4">
                        <button type="button" class="btn btn-primary btn-lg me-3" onclick="submitNewApplication()">
                            <i class="fas fa-plus me-2"></i>Submit New Application
                        </button>
                        <button type="button" class="btn btn-outline-primary" onclick="contactSupport()">
                            <i class="fas fa-headset me-2"></i>Contact Support
                        </button>
                    </div>
                </div>
                
                <div class="row mt-4 text-center">
                    <div class="col-md-4">
                        <i class="fas fa-shield-alt fa-2x text-success mb-2"></i>
                        <h6>Secure Process</h6>
                        <small class="text-muted">Your data is protected with enterprise-grade security</small>
                    </div>
                    <div class="col-md-4">
                        <i class="fas fa-clock fa-2x text-info mb-2"></i>
                        <h6>Quick Response</h6>
                        <small class="text-muted">Fast processing with AI-powered assessment</small>
                    </div>
                    <div class="col-md-4">
                        <i class="fas fa-handshake fa-2x text-warning mb-2"></i>
                        <h6>Personal Service</h6>
                        <small class="text-muted">Dedicated support throughout the process</small>
                    </div>
                </div>
            </div>
        `;
    }

    function displayError(errorMessage) {
        form.innerHTML = `
            <div class="alert alert-danger text-center" style="border-radius: 15px; padding: 3rem 2rem;">
                <i class="fas fa-exclamation-triangle fa-3x mb-3"></i>
                <h4>Oops! Something went wrong</h4>
                <p class="mb-4">${errorMessage}</p>
                <button type="button" class="btn btn-danger btn-lg" onclick="location.reload()">
                    <i class="fas fa-redo me-2"></i>Try Again
                </button>
            </div>
        `;
    }

    // Global functions for button actions
    window.submitNewApplication = function() {
        location.reload();
    };

    window.contactSupport = function() {
        const supportModal = `
            <div class="modal fade" id="supportModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header" style="background-color: var(--royal-purple); color: white;">
                            <h5 class="modal-title"><i class="fas fa-headset me-2"></i>Contact Support</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="text-center mb-4">
                                <i class="fas fa-phone-alt fa-3x text-success mb-3"></i>
                                <h6>We're here to help!</h6>
                            </div>
                            
                            <div class="contact-info">
                                <div class="d-flex align-items-center mb-3">
                                    <i class="fas fa-phone text-success me-3"></i>
                                    <div>
                                        <strong>Phone</strong><br>
                                        <a href="tel:+2348000000000" class="text-decoration-none">+234 800 000 0000</a>
                                    </div>
                                </div>
                                
                                <div class="d-flex align-items-center mb-3">
                                    <i class="fas fa-envelope text-warning me-3"></i>
                                    <div>
                                        <strong>Email</strong><br>
                                        <a href="mailto:support@veriloan.com" class="text-decoration-none">support@veriloan.com</a>
                                    </div>
                                </div>
                                
                                <div class="d-flex align-items-center mb-3">
                                    <i class="fas fa-clock text-info me-3"></i>
                                    <div>
                                        <strong>Business Hours</strong><br>
                                        Monday - Friday: 9AM - 6PM WAT<br>
                                        Saturday: 10AM - 2PM WAT
                                    </div>
                                </div>
                                
                                <div class="d-flex align-items-center">
                                    <i class="fab fa-whatsapp text-success me-3"></i>
                                    <div>
                                        <strong>WhatsApp</strong><br>
                                        <a href="https://wa.me/2348000000000" target="_blank" class="text-decoration-none">+234 800 000 0000</a>
                                    </div>
                                </div>
                            </div>
                            
                            <hr>
                            <div class="alert alert-info">
                                <small><i class="fas fa-info-circle me-1"></i>
                                Please have your application reference number ready when contacting us.</small>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', supportModal);
        const modal = new bootstrap.Modal(document.getElementById('supportModal'));
        modal.show();
        
        // Remove modal from DOM after it's hidden
        document.getElementById('supportModal').addEventListener('hidden.bs.modal', function() {
            this.remove();
        });
    };

    // Add real-time form validation
    addFormValidation();
});

// Enhanced form validation
function addFormValidation() {
    const form = document.getElementById("loanForm");
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, select, textarea');
    
    inputs.forEach(input => {
        input.addEventListener('blur', function() {
            validateField(this);
        });
        
        // Real-time validation for email and phone
        if (input.type === 'email') {
            input.addEventListener('input', function() {
                validateEmail(this);
            });
        }
        
        if (input.type === 'tel') {
            input.addEventListener('input', function() {
                validatePhone(this);
            });
        }
        
        // Amount validation
        if (input.name === 'amount_requested') {
            input.addEventListener('input', function() {
                validateAmount(this);
            });
        }
    });
}

function validateField(field) {
    const value = field.value.trim();
    let isValid = true;
    let message = '';
    
    // Remove existing validation feedback
    const existingFeedback = field.parentNode.querySelector('.validation-feedback');
    if (existingFeedback) {
        existingFeedback.remove();
    }
    field.classList.remove('is-valid', 'is-invalid');
    
    switch(field.name) {
        case 'full_name':
            if (value.length < 3) {
                isValid = false;
                message = 'Full name must be at least 3 characters';
            } else if (!/^[a-zA-Z\s.'-]+$/.test(value)) {
                isValid = false;
                message = 'Name should only contain letters, spaces, and common punctuation';
            }
            break;
            
        case 'address':
            if (value.length < 10) {
                isValid = false;
                message = 'Please provide a complete address';
            }
            break;
            
        case 'purpose':
            if (value.length < 10) {
                isValid = false;
                message = 'Please provide more details about the loan purpose';
            }
            break;
    }
    
    if (!isValid && value !== '') {
        field.classList.add('is-invalid');
        const feedback = document.createElement('div');
        feedback.className = 'validation-feedback invalid-feedback d-block';
        feedback.textContent = message;
        field.parentNode.appendChild(feedback);
    } else if (value !== '') {
        field.classList.add('is-valid');
    }
}

function validateEmail(emailField) {
    const email = emailField.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    clearValidation(emailField);
    
    if (email === '') return;
    
    if (!emailRegex.test(email)) {
        showFieldError(emailField, 'Please enter a valid email address');
    } else {
        emailField.classList.add('is-valid');
    }
}

function validatePhone(phoneField) {
    const phone = phoneField.value.trim().replace(/[\s-]/g, '');
    const phoneRegex = /^(\+234|234|0)[789][01]\d{8}$/;
    
    clearValidation(phoneField);
    
    if (phone === '') return;
    
    if (!phoneRegex.test(phone)) {
        showFieldError(phoneField, 'Please enter a valid Nigerian phone number');
    } else {
        phoneField.classList.add('is-valid');
    }
}

function validateAmount(amountField) {
    const amount = parseFloat(amountField.value);
    
    clearValidation(amountField);
    
    if (isNaN(amount)) return;
    
    if (amount < 10000) {
        showFieldError(amountField, 'Minimum loan amount is ₦10,000');
    } else if (amount > 5000000) {
        showFieldError(amountField, 'Maximum loan amount is ₦5,000,000');
    } else {
        amountField.classList.add('is-valid');
    }
}

function clearValidation(field) {
    const existingFeedback = field.parentNode.querySelector('.validation-feedback');
    if (existingFeedback) {
        existingFeedback.remove();
    }
    field.classList.remove('is-valid', 'is-invalid');
}

function showFieldError(field, message) {
    field.classList.add('is-invalid');
    const feedback = document.createElement('div');
    feedback.className = 'validation-feedback invalid-feedback d-block';
    feedback.textContent = message;
    field.parentNode.appendChild(feedback);
}