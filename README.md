# VeriLoan: Intelligent Loan Fraud Detection System

## Overview

VeriLoan is an advanced fraud detection and prevention system designed for banks and financial institutions to identify and mitigate loan application fraud in real-time. Inspired by the limitations of traditional security measures, VeriLoan integrates Fingerprint's device intelligence platform with custom risk scoring algorithms and unsupervised machine learning to analyze loan applications using multiple risk factors and Smart Signals.

The system flags suspicious applications, calculates risk scores, and provides an admin dashboard for staff review. All applications require manual staff approval, with automated recommendations based on rule-based and ML-enhanced analysis. It uses a microservices architecture built on Django, with Redis for caching and performance optimization.

## Deployed Website: https://fraud-detection-production-11c8.up.railway.app/

Admin Credentials:
username: admin
password: admin123!

Key capabilities:
- Real-time device fingerprinting and Smart Signals integration with FingerprintJS.
- Rule-based and ML-based fraud detection (using Isolation Forest and DBSCAN for anomaly detection).
- Comprehensive risk scoring across identity, device, IP, and historical factors.
- Behavioral pattern analysis without requiring labeled training data.
- Admin dashboard for monitoring, reviewing, and updating applications.
- API endpoints for enhanced insights, batch processing, and analytics.

## Features

- **Fraud Detection**: Combines rule-based checks (e.g., multiple applications from the same device, fake data patterns) with ML anomaly detection.
- **Risk Scoring**: Weighted scoring system with adjustable thresholds for identity, device, IP, history, and ML behavioral risks.
- **Smart Signals**: Detects bots, VPNs, proxies, TOR, tampering, incognito mode, and IP blocklisting.
- **Admin Dashboard**: Secure login for staff, real-time stats, application details, ML insights, status updates, comments, and exports.
- **ML Enhancements**: Unsupervised learning for behavioral anomalies, cluster analysis, and risk adjustments.
- **Workflow**: All applications start as PENDING or FLAGGED; staff can approve, reject, or flag with reasons and notifications.
- **Analytics**: Daily stats, risk distributions, ML insights, and export to CSV.
- **Security**: CSRF protection, staff authentication, atomic transactions for data integrity.

## Technologies Used

- **Backend**: Django (Python web framework)
- **Database**: Django ORM (supports PostgreSQL, SQLite, etc.)
- **Machine Learning**: scikit-learn (Isolation Forest, DBSCAN, PCA, StandardScaler), NumPy, Pandas
- **Device Intelligence**: FingerprintJS API for visitor ID and Smart Signals
- **Caching**: Redis
- **Other Libraries**: tenacity (for retries), logging, requests, json
- **Frontend**: HTML templates (assumed; extendable with JavaScript frameworks like React)
- **Environment**: Python 3.x

## Installation

### Prerequisites

- Python 3.8+
- Virtual environment tool (e.g., venv or virtualenv)
- Redis server (for caching)
- FingerprintJS account (for API keys: public and secret)

### Steps

1. **Clone the Repository**:
   ```
   git clone https://github.com/Oal304/fraud-detection
   cd veriloan
   ```

2. **Set Up Virtual Environment**:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   Then run:
   ```
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:
   Create a `.env` file in the project root:
   ```
   DEBUG=True
   SECRET_KEY=your_django_secret_key
   FINGERPRINTJS_PUBLIC_KEY=your_fpjs_public_key
   FINGERPRINTJS_SECRET_KEY=your_fpjs_secret_key
   IDENTITY_WEIGHT=0.3
   DEVICE_WEIGHT=0.2
   IP_WEIGHT=0.2
   HISTORY_WEIGHT=0.3
   ML_WEIGHT=0.15
   CONFIDENCE_THRESHOLD=0.9
   VPN_DETECTION_THRESHOLD=0.8
   TAMPERING_THRESHOLD=0.7
   DATABASE_URL=sqlite:///db.sqlite3  # Or your DB connection string
   ```

5. **Database Setup**:
   ```
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create Superuser for Admin**:
   ```
   python manage.py createsuperuser
   ```

7. **Run the Server**:
   ```
   python manage.py runserver
   ```
   Access at `http://127.0.0.1:8000/`.

## Usage

### Loan Application Flow

1. Visit the homepage (`/`) to submit a loan application form.
2. The system collects device fingerprint and Smart Signals via FingerprintJS.
3. On submission, the application is processed:
   - Visitor data stored.
   - Fraud detection (rule-based + ML) runs.
   - Risk score calculated.
   - Status set to PENDING (clean) or FLAGGED (suspicious).
4. Redirect to success page with reference number.

### Admin Dashboard

1. Login at `/login/` with staff credentials.
2. Access dashboard at `/dashboard/`:
   - View recent applications, stats, and ML insights.
   - Drill into application details (visitor info, smart signals, fraud alerts).
   - Update status (approve/reject/flag) with reasons.
   - Add comments, export data, run batch ML analysis.
   - View analytics charts via API endpoints.

### Key API Endpoints

- **Submit Loan**: `POST /apply_for_loan_enhanced/` (enhanced with ML)
- **Get Smart Signals**: `POST /get_smart_signals/` (from FingerprintJS)
- **Dashboard Data**: `GET /dashboard_data/`
- **Application Details**: `GET /application_details/<id>/`
- **Update Status**: `POST /update_application_status/<id>/`
- **ML Insights**: `GET /get_ml_insights/?application_id=<id>`
- **Batch ML Analysis**: `POST /batch_ml_analysis/`
- **Fraud Analytics**: `GET /fraud_analytics/`
- **Export Applications**: `GET /export_applications/`
- **Bulk Update**: `POST /bulk_update_status/`
- **Add Comment**: `POST /add_application_comment/`
- **Get Comments**: `GET /get_application_comments/?application_id=<id>`
- **Dashboard Stats**: `GET /dashboard_stats_summary/`

### Example Configuration

Adjust weights and thresholds in `.env` for custom risk scoring.

## Architecture Overview

- **Models**: `LoanApplication`, `VisitorID`, `FraudAlert` – Store application data, visitor fingerprints, and alerts.
- **Services** (`services.py`): RiskScoringService (weighted risks), FraudDetectionService (rules + patterns), Enhanced versions with ML.
- **ML Services** (`ml_services.py`): BehavioralPatternAnalyzer (extracts features, runs Isolation Forest/DBSCAN), MLFraudEnhancer (integrates ML into detection).
- **Views** (`views.py`): Handle form submission, API calls, admin functions with authentication.
- **Utils**: Helper functions for IP extraction, visitor tracking.
- **Forms**: `LoanApplicationForm` for validation.

The system uses atomic transactions for reliability and logging for auditing.

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/new-feature`.
3. Commit changes: `git commit -am 'Add new feature'`.
4. Push to branch: `git push origin feature/new-feature`.
5. Submit a pull request.

Please follow PEP 8 for Python code.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contact

For questions or support, open an issue on GitHub.

*Last updated: August 11, 2025*