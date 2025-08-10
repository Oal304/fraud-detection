# fraud_prevention/wsgi.py

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fraud_prevention.settings")

application = get_wsgi_application()
