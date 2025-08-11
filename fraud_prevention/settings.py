# fraud_prevention/settings.py

import os
from pathlib import Path
from dotenv import load_dotenv
import pymysql


# Load environment variables
load_dotenv()

pymysql.install_as_MySQLdb()

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key secret!
SECRET_KEY = os.getenv("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DEBUG") == "False"

ALLOWED_HOSTS = ["*"]  # Change this in production

# URL CONFIGURATION
ROOT_URLCONF = "fraud_prevention.urls"

FINGERPRINTJS_PUBLIC_KEY = os.getenv('FINGERPRINTJS_PUBLIC_KEY')
FINGERPRINTJS_SECRET_KEY = os.getenv('FINGERPRINTJS_SECRET_KEY')

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST"),
        "PORT": os.getenv("DB_PORT"),
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'"
        }
    }
}


# Installed Apps
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "fraud_detection",
    "crispy_forms",
    "crispy_bootstrap5",
]

# MIDDLEWARE
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # Directories where templates are stored
        'APP_DIRS': True,  # Look for templates in app directories
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

CSRF_TRUSTED_ORIGINS = [
    f"https://{os.getenv('RAILWAY_PUBLIC_DOMAIN', '')}",
    "http://127.0.0.1:8000",
]

ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '.railway.app',
    os.getenv('RAILWAY_PUBLIC_DOMAIN', ''),  
]


LOGIN_REDIRECT_URL = '/dashboard/'
LOGIN_URL = '/login/'

# STATIC & MEDIA FILES
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"  
CRISPY_TEMPLATE_PACK = "bootstrap5"

# ML INSIGHTS
ML_ANALYSIS_ENABLED = os.getenv('ENABLE_ML_ANALYSIS', 'false').lower() == 'true'
ML_BATCH_SIZE_LIMIT = int(os.getenv('ML_BATCH_SIZE_LIMIT', 50))

# EMAIL CONFIGURATION (for fraud alerts)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")

# WSGI APPLICATION
WSGI_APPLICATION = "fraud_prevention.wsgi.application"

# LANGUAGE & TIMEZONE
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True

# DEFAULT AUTO FIELD
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


