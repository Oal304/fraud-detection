# fraud_detection/ml_services.py
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from django.db.models import Q
from datetime import timedelta
from django.utils import timezone
import json
import logging
from .models import LoanApplication, VisitorID

logger = logging.getLogger(__name__)

class BehavioralPatternAnalyzer:
    """
    Analyzes behavioral patterns using unsupervised ML algorithms
    to detect anomalous loan applications without training data.
    """
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        
    def extract_behavioral_features(self, loan_application):
        """Extract behavioral features from loan application and visitor data."""
        features = {}
        
        # Time-based features
        app_time = loan_application.application_date
        features['hour_of_day'] = app_time.hour
        features['day_of_week'] = app_time.weekday()
        features['is_weekend'] = 1 if app_time.weekday() >= 5 else 0
        
        # Application characteristics
        features['amount_requested'] = float(loan_application.amount_requested)
        features['confidence_score'] = loan_application.confidence_score or 0.5
        
        # Smart signals (convert booleans to integers)
        features['bot_detected'] = int(loan_application.bot_detected or False)
        features['vpn_detected'] = int(loan_application.vpn_detected or False)
        features['proxy_detected'] = int(loan_application.proxy_detected or False)
        features['tor_detected'] = int(loan_application.tor_detected or False)
        features['tampering_detected'] = int(loan_application.tampering_detected or False)
        features['incognito'] = int(loan_application.incognito or False)
        features['ip_blocklisted'] = int(loan_application.ip_blocklisted or False)
        
        # Visitor behavior features
        if loan_application.visitor_id:
            visitor = loan_application.visitor_id
            features['visitor_app_count'] = visitor.application_count or 0
            
            # Time since last application
            if visitor.last_application_date:
                time_diff = (timezone.now() - visitor.last_application_date).total_seconds() / 3600  # hours
                features['hours_since_last_app'] = min(time_diff, 168)  # Cap at 1 week
            else:
                features['hours_since_last_app'] = 168  # Default to 1 week
        else:
            features['visitor_app_count'] = 0
            features['hours_since_last_app'] = 168
            
        # Device consistency features
        if loan_application.metadata:
            try:
                metadata = json.loads(loan_application.metadata) if isinstance(loan_application.metadata, str) else loan_application.metadata
                browser_details = metadata.get('browserDetails', {})
                features['browser_stability'] = 1 if browser_details.get('browser') else 0
                features['os_stability'] = 1 if metadata.get('osDetails', {}).get('os') else 0
            except (json.JSONDecodeError, TypeError):
                features['browser_stability'] = 0
                features['os_stability'] = 0
        else:
            features['browser_stability'] = 0
            features['os_stability'] = 0
            
        # Text-based features (length and patterns)
        features['name_length'] = len(loan_application.full_name or '')
        features['email_length'] = len(loan_application.email or '')
        features['purpose_length'] = len(loan_application.purpose or '')
        
        # Email domain features
        if loan_application.email and '@' in loan_application.email:
            domain = loan_application.email.split('@')[-1].lower()
            common_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
            features['common_email_domain'] = 1 if domain in common_domains else 0
        else:
            features['common_email_domain'] = 0
            
        return features
    
    def analyze_current_application(self, loan_application):
        """
        Analyze current application against recent patterns to detect anomalies.
        """
        try:
            # Get recent applications for comparison (last 30 days)
            recent_date = timezone.now() - timedelta(days=30)
            recent_applications = LoanApplication.objects.filter(
                application_date__gte=recent_date
            ).exclude(id=loan_application.id)
            
            if recent_applications.count() < 10:  # Need minimum data for analysis
                return {
                    'anomaly_score': 0.5,  # Neutral score
                    'anomaly_detected': False,
                    'cluster_label': -1,
                    'behavioral_risk': 'medium',
                    'analysis_details': 'Insufficient historical data for ML analysis'
                }
            
            # Extract features for all applications
            all_features = []
            feature_names = []
            
            # Process recent applications
            for app in recent_applications:
                features = self.extract_behavioral_features(app)
                all_features.append(list(features.values()))
                if not feature_names:  # Get feature names from first application
                    feature_names = list(features.keys())
            
            # Process current application
            current_features = self.extract_behavioral_features(loan_application)
            current_feature_vector = [current_features[name] for name in feature_names]
            
            # Convert to numpy array
            X = np.array(all_features)
            X_current = np.array([current_feature_vector])
            
            # Handle any NaN values
            X = np.nan_to_num(X, nan=0.0)
            X_current = np.nan_to_num(X_current, nan=0.0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            X_current_scaled = self.scaler.transform(X_current)
            
            # Isolation Forest for anomaly detection
            self.isolation_forest.fit(X_scaled)
            anomaly_score = self.isolation_forest.decision_function(X_current_scaled)[0]
            is_anomaly = self.isolation_forest.predict(X_current_scaled)[0] == -1
            
            # DBSCAN for clustering
            cluster_labels = self.dbscan.fit_predict(X_scaled)
            
            # Find which cluster the current application belongs to
            # Add current application to the dataset and re-cluster
            X_with_current = np.vstack([X_scaled, X_current_scaled])
            all_cluster_labels = self.dbscan.fit_predict(X_with_current)
            current_cluster = all_cluster_labels[-1]  # Last item is current application
            
            # Calculate behavioral risk
            behavioral_risk = self._calculate_behavioral_risk(
                anomaly_score, is_anomaly, current_cluster, current_features
            )
            
            # Generate analysis details
            analysis_details = self._generate_analysis_details(
                current_features, anomaly_score, current_cluster, recent_applications.count()
            )
            
            return {
                'anomaly_score': float(anomaly_score),
                'anomaly_detected': bool(is_anomaly),
                'cluster_label': int(current_cluster),
                'behavioral_risk': behavioral_risk,
                'analysis_details': analysis_details,
                'feature_importance': self._get_feature_importance(current_features, feature_names)
            }
            
        except Exception as e:
            logger.error(f"Error in behavioral pattern analysis: {str(e)}")
            return {
                'anomaly_score': 0.5,
                'anomaly_detected': False,
                'cluster_label': -1,
                'behavioral_risk': 'medium',
                'analysis_details': f'Analysis failed: {str(e)}'
            }
    
    def _calculate_behavioral_risk(self, anomaly_score, is_anomaly, cluster_label, features):
        """Calculate behavioral risk level based on ML analysis."""
        risk_score = 0
        
        # Anomaly detection contribution
        if is_anomaly:
            risk_score += 40
        
        # Anomaly score contribution (normalize to 0-30 range)
        normalized_anomaly = max(0, min(30, (1 - anomaly_score) * 30))
        risk_score += normalized_anomaly
        
        # Cluster analysis contribution
        if cluster_label == -1:  # Noise/outlier cluster
            risk_score += 20
            
        # Smart signals contribution
        smart_signal_count = sum([
            features['bot_detected'], features['vpn_detected'],
            features['proxy_detected'], features['tor_detected'],
            features['tampering_detected']
        ])
        risk_score += smart_signal_count * 5
        
        # Determine risk level
        if risk_score >= 70:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _generate_analysis_details(self, features, anomaly_score, cluster_label, sample_size):
        """Generate human-readable analysis details."""
        details = []
        
        details.append(f"Analyzed against {sample_size} recent applications")
        details.append(f"Anomaly score: {anomaly_score:.3f} (lower = more anomalous)")
        
        if cluster_label == -1:
            details.append("Application behavior is outlier (doesn't fit common patterns)")
        else:
            details.append(f"Application belongs to behavioral cluster #{cluster_label}")
            
        # Highlight unusual features
        if features['bot_detected']:
            details.append("⚠️ Bot activity detected")
        if features['vpn_detected'] or features['proxy_detected']:
            details.append("⚠️ Network anonymization detected")
        if features['visitor_app_count'] > 3:
            details.append(f"⚠️ High application frequency ({features['visitor_app_count']} applications)")
        if features['hours_since_last_app'] < 1:
            details.append("⚠️ Very recent previous application")
            
        return " | ".join(details)
    
    def _get_feature_importance(self, features, feature_names):
        """Get feature importance for transparency."""
        # Simple heuristic-based importance
        importance = {}
        
        high_importance = ['bot_detected', 'vpn_detected', 'tampering_detected', 'visitor_app_count']
        medium_importance = ['confidence_score', 'proxy_detected', 'tor_detected', 'hours_since_last_app']
        
        for name in feature_names:
            if name in high_importance:
                importance[name] = 'high'
            elif name in medium_importance:
                importance[name] = 'medium'
            else:
                importance[name] = 'low'
                
        return importance

class MLFraudEnhancer:
    """
    Enhances existing fraud detection with ML-based behavioral analysis.
    """
    
    def __init__(self):
        self.behavioral_analyzer = BehavioralPatternAnalyzer()
    
    def enhance_fraud_detection(self, loan_application, existing_risk_score):
        """
        Enhance existing fraud detection with ML analysis.
        """
        try:
            # Get behavioral analysis
            behavioral_analysis = self.behavioral_analyzer.analyze_current_application(loan_application)
            
            # Calculate ML risk adjustment
            ml_risk_adjustment = self._calculate_ml_risk_adjustment(behavioral_analysis)
            
            # Combine with existing risk score
            enhanced_risk_score = min(100, existing_risk_score + ml_risk_adjustment)
            
            # Update loan application metadata with ML analysis
            if loan_application.metadata:
                try:
                    metadata = json.loads(loan_application.metadata) if isinstance(loan_application.metadata, str) else loan_application.metadata
                except json.JSONDecodeError:
                    metadata = {}
            else:
                metadata = {}
                
            metadata['ml_analysis'] = behavioral_analysis
            metadata['ml_risk_adjustment'] = ml_risk_adjustment
            metadata['enhanced_risk_score'] = enhanced_risk_score
            
            loan_application.metadata = json.dumps(metadata)
            
            return {
                'enhanced_risk_score': enhanced_risk_score,
                'ml_risk_adjustment': ml_risk_adjustment,
                'behavioral_analysis': behavioral_analysis
            }
            
        except Exception as e:
            logger.error(f"Error in ML fraud enhancement: {str(e)}")
            return {
                'enhanced_risk_score': existing_risk_score,
                'ml_risk_adjustment': 0,
                'behavioral_analysis': {'analysis_details': f'ML enhancement failed: {str(e)}'}
            }
    
    def _calculate_ml_risk_adjustment(self, behavioral_analysis):
        """Calculate risk score adjustment based on ML analysis."""
        adjustment = 0
        
        # Anomaly detection adjustment
        if behavioral_analysis.get('anomaly_detected'):
            adjustment += 15
            
        # Anomaly score adjustment
        anomaly_score = behavioral_analysis.get('anomaly_score', 0)
        if anomaly_score < -0.2:  # Highly anomalous
            adjustment += 20
        elif anomaly_score < 0:  # Moderately anomalous
            adjustment += 10
            
        # Cluster analysis adjustment
        if behavioral_analysis.get('cluster_label') == -1:  # Outlier
            adjustment += 10
            
        # Behavioral risk adjustment
        behavioral_risk = behavioral_analysis.get('behavioral_risk', 'medium')
        if behavioral_risk == 'high':
            adjustment += 15
        elif behavioral_risk == 'medium':
            adjustment += 5
            
        return min(30, adjustment)  # Cap at 30 points adjustment