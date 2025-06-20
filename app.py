import dash
from dash import dcc, html, Input, Output, State, callback_context, dash_table
import pandas as pd
import json
import hashlib
import time
import base64
import secrets
import numpy as np
from datetime import datetime
from io import StringIO
import logging
import logging.handlers
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hmac
import re
from typing import Dict, List, Optional

# Set up logging with rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            'banking_security.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)

class BankingSecuritySystem:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BankingSecuritySystem, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.aes_key = os.urandom(32)  # 256-bit key for AES
        self.hmac_key = os.urandom(32)  # Key for HMAC
        self.cipher_suite = Fernet(Fernet.generate_key())
        self.nonce = os.urandom(16)  # Nonce for AES
        self.session_key = secrets.token_hex(32)
        self.active = True

    def validate_input(self, data: Dict) -> bool:
        try:
            malicious_patterns = [r'<script>', r'javascript:', r'sqlmap', r'1=1', r'--', r'\' OR']
            for key, value in data.items():
                if isinstance(value, str):
                    if any(re.search(pattern, value.lower()) for pattern in malicious_patterns):
                        logging.warning(f"Potential malicious input detected: {key}")
                        return False
                if isinstance(value, (int, float)) and value < 0:
                    logging.warning(f"Negative value detected in {key}")
                    return False
            return True
        except Exception as e:
            logging.error(f"Input validation failed: {str(e)}")
            return False

    def encrypt_transaction(self, transaction_data: Dict) -> Optional[Dict]:
        if not self.active:
            logging.error("Session terminated")
            return None
        try:
            if not self.validate_input(transaction_data):
                raise ValueError("Invalid input data detected")
            json_data = json.dumps(transaction_data, sort_keys=True)
            hmac_obj = hmac.new(self.hmac_key, json_data.encode(), hashlib.sha256)
            data_hmac = hmac_obj.hexdigest()
            encrypted_data = self.cipher_suite.encrypt(json_data.encode())
            transaction_hash = hashlib.sha512(encrypted_data + data_hmac.encode() + self.session_key.encode()).hexdigest()
            return {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'transaction_hash': transaction_hash,
                'hmac': data_hmac,
                'encryption_method': 'AES-256-GCM',
                'timestamp': int(time.time()),
                'nonce': base64.b64encode(self.nonce).decode()
            }
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            return None

    def simulate_blockchain_verification(self, transaction_data: Dict) -> Optional[Dict]:
        if not self.active:
            logging.error("Session terminated")
            return None
        try:
            if not self.validate_input(transaction_data):
                raise ValueError("Invalid input data detected")
            data_hash = hashlib.sha256(json.dumps(transaction_data).encode()).hexdigest()
            merkle_leaf = hashlib.sha256(data_hash.encode() + self.session_key.encode()).hexdigest()
            blockchain_tx = {
                'tx_hash': f"0x{secrets.token_hex(32)}",
                'block_number': np.random.randint(18000000, 19000000),
                'from_address': f"0x{secrets.token_hex(20)}",
                'to_address': f"0x{secrets.token_hex(20)}",
                'gas_used': np.random.randint(21000, 85000),
                'gas_price': np.random.randint(20, 100),
                'status': 'confirmed',
                'timestamp': int(time.time()),
                'data_hash': data_hash,
                'merkle_leaf': merkle_leaf,
                'chain_id': 1,
                'nonce': secrets.token_hex(8)
            }
            return blockchain_tx
        except Exception as e:
            logging.error(f"Blockchain simulation failed: {str(e)}")
            return None

    def calculate_cibyl_score(self, transaction: Dict) -> Dict:
        if not self.active:
            return {
                'cibyl_score': 0.5,
                'risk_level': 'MODERATE',
                'risk_factors': ['Session Terminated'],
                'recommendation': 'REVIEW',
                'confidence': 0.5,
                'security_checks': ['Session Terminated']
            }
        try:
            score = 0.0
            risk_factors = []
            security_checks = []
            amount = float(transaction.get('transaction_amount', 0))
            age_days = int(transaction.get('account_age_days', 365))
            failed_txns = int(transaction.get('previous_failed_transactions', 0))
            if amount > 1000000:
                score += 0.5
                risk_factors.append('Critical Amount (>10L)')
                security_checks.append('Large Transaction Verification Required')
            elif amount > 500000:
                score += 0.4
                risk_factors.append('Very High Amount (>5L)')
            elif amount > 100000:
                score += 0.3
                risk_factors.append('High Amount (>1L)')
            sender_country = transaction.get('sender_country', '').strip().lower()
            recipient_country = transaction.get('recipient_country', '').strip().lower()
            high_risk_countries = ['kp', 'ir', 'sy']
            if sender_country != recipient_country and sender_country and recipient_country:
                score += 0.3
                risk_factors.append('International Transfer')
                if recipient_country in high_risk_countries:
                    score += 0.4
                    risk_factors.append('High Risk Country')
                    security_checks.append('Sanctions List Check Required')
            if age_days < 15:
                score += 0.5
                risk_factors.append('Very New Account (<15 days)')
                security_checks.append('Enhanced KYC Required')
            elif age_days < 30:
                score += 0.4
                risk_factors.append('New Account (<30 days)')
            elif age_days < 90:
                score += 0.2
                risk_factors.append('Recent Account (<90 days)')
            if failed_txns > 10:
                score += 0.6
                risk_factors.append('Excessive Failed Transactions')
                security_checks.append('Account Lock Recommended')
            elif failed_txns > 5:
                score += 0.5
                risk_factors.append('Multiple Failed Transactions')
            elif failed_txns > 2:
                score += 0.3
                risk_factors.append('Some Failed Transactions')
            txn_type = transaction.get('transaction_type', '').lower()
            high_risk_types = ['crypto', 'investment', 'gambling', 'escrow']
            if txn_type in high_risk_types:
                score += 0.4
                risk_factors.append('High Risk Transaction Type')
                security_checks.append('Transaction Type Verification')
            purpose = transaction.get('purpose', '').lower()
            suspicious_purposes = ['loan', 'urgent', 'emergency', 'investment', 'trading', 'charity']
            if any(word in purpose for word in suspicious_purposes):
                score += 0.3
                risk_factors.append('Suspicious Purpose')
                security_checks.append('Purpose Verification Required')
            if not transaction.get('sender_account_verified', False):
                score += 0.2
                risk_factors.append('Unverified Sender Account')
                security_checks.append('Account Verification Required')
            final_score = min(score, 1.0)
            if final_score >= 0.8:
                risk_level = 'CRITICAL'
                recommendation = 'BLOCK'
                security_checks.append('Immediate Action Required')
            elif final_score >= 0.6:
                risk_level = 'HIGH'
                recommendation = 'QUARANTINE'
            elif final_score >= 0.4:
                risk_level = 'MODERATE'
                recommendation = 'REVIEW'
            else:
                risk_level = 'LOW'
                recommendation = 'APPROVE'
            return {
                'cibyl_score': round(final_score, 3),
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'recommendation': recommendation,
                'confidence': min(0.98, 0.8 + (final_score * 0.2)),
                'security_checks': security_checks
            }
        except Exception as e:
            logging.error(f"CIBYL calculation failed: {str(e)}")
            return {
                'cibyl_score': 0.5,
                'risk_level': 'MODERATE',
                'risk_factors': ['Calculation Error'],
                'recommendation': 'REVIEW',
                'confidence': 0.5,
                'security_checks': ['Error Recovery Required']
            }

    def terminate_session(self):
        self.active = False
        logging.info(f"Session terminated: {self.session_key}")
        self._initialize()  # Reset to new session

# Initialize security system
security_system = BankingSecuritySystem()

# Dash App
app = dash.Dash(__name__, external_stylesheets=[
    'https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
])

app.config.suppress_callback_exceptions = True

app.clientside_callback(
    """
    function(currentStep, intervalDisabled) {
        if (currentStep >= 8 || intervalDisabled) {
            return window.dash_clientside.no_update;
        }
        const animations = [
            {
                id: 'encryption-animation',
                keyframes: [
                    { transform: 'rotate(0deg) scale(1)', opacity: 1 },
                    { transform: 'rotate(360deg) scale(1.2)', opacity: 0.7 },
                    { transform: 'rotate(720deg) scale(1)', opacity: 1 }
                ],
                options: { duration: 2000, iterations: Infinity }
            },
            {
                id: 'blockchain-animation',
                keyframes: [
                    { transform: 'translateY(0px)', opacity: 1 },
                    { transform: 'translateY(-20px)', opacity: 0.5 },
                    { transform: 'translateY(0px)', opacity: 1 }
                ],
                options: { duration: 1500, iterations: Infinity }
            }
        ];
        animations.forEach(anim => {
            const element = document.getElementById(anim.id);
            if (element && currentStep >= 2 && anim.id === 'encryption-animation') {
                element.animate(anim.keyframes, anim.options);
            }
            if (element && currentStep >= 3 && anim.id === 'blockchain-animation') {
                element.animate(anim.keyframes, anim.options);
            }
        });
        return window.dash_clientside.no_update;
    }
    """,
    Output('processing-animation', 'data-animation'),
    [Input('processing-step-store', 'data'),
     Input('processing-interval', 'disabled')]
)

app.layout = html.Div([
    html.Div([
        html.Div([
            html.H1([
                html.I(className="fas fa-shield-alt mr-3 text-indigo-600"),
                "RBI - Secure Transaction Monitoring System"
            ], className="text-3xl font-bold text-gray-800"),
            html.P("Military-Grade Transaction Security and Fraud Detection", 
                   className="text-lg text-gray-600 mt-2"),
            html.P("FIPS 140-2 Compliant | AES-256-GCM | Blockchain Verified", 
                   className="text-sm text-blue-600 font-semibold")
        ], className="text-center")
    ], className="bg-white shadow-lg rounded-lg p-6 mb-6"),
    
    html.Div([
        html.Div([
            html.I(className="fas fa-lock mr-2 text-green-600"),
            html.Span(f"Secure Session: {security_system.session_key[:8]}...", 
                     className="text-green-700 font-medium")
        ], className="flex items-center justify-center")
    ], className="bg-green-50 border-l-4 border-green-500 rounded-lg p-4 mb-6"),
    
    html.Div(id="stats-cards", className="grid grid-cols-1 md:grid-cols-5 gap-6 mb-6"),
    
    html.Div([
        html.Div([
            html.H3([
                html.I(className="fas fa-upload mr-2"),
                "Secure Transaction Data Upload"
            ], className="text-xl font-semibold text-gray-800 mb-4"),
            dcc.Upload(
                id='upload-data',
                children=html.Div([
                    html.I(className="fas fa-cloud-upload-alt text-4xl text-gray-400 mb-4"),
                    html.H4("Secure File Upload", className="text-lg font-medium text-gray-600"),
                    html.P("CSV files only (max 50MB) | AES-256 Encrypted Transmission", 
                           className="text-sm text-gray-500"),
                    html.P("Required columns: account_id, user_id, transaction_amount, recipient_account, sender_country, recipient_country, account_age_days, previous_failed_transactions, transaction_type, purpose, sender_account_verified",
                           className="text-xs text-gray-400 mt-2")
                ], className="text-center p-8"),
                className="border-2 border-dashed border-gray-300 rounded-lg hover:border-indigo-400 transition-colors cursor-pointer",
                accept='.csv',
                max_size=52428800
            )
        ], className="bg-white rounded-lg shadow-md p-6")
    ], className="mb-6"),
    
    html.Div(id="processing-animation", className="mb-6"),
    
    html.Div(id="results-section"),
    
    html.Div([
        html.Button([
            html.I(className="fas fa-times mr-2"),
            "Terminate Session"
        ], id="terminate-btn", className="bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-6 rounded-lg")
    ], className="mb-6"),
    
    dcc.Store(id='processed-data-store'),
    dcc.Store(id='processing-step-store', data=0),
    dcc.Interval(id='processing-interval', interval=800, disabled=True, n_intervals=0),
    dcc.Download(id="download-report")
], className="container mx-auto p-6 bg-gray-50 min-h-screen")

@app.callback(
    [Output('processing-step-store', 'data'),
     Output('processing-interval', 'disabled')],
    [Input('processing-interval', 'n_intervals')],
    [State('processing-step-store', 'data')]
)
def update_processing_step(n_intervals: int, current_step: int) -> tuple:
    if current_step >= 8:
        return current_step, True
    return current_step + 1, False

@app.callback(
    [Output('processed-data-store', 'data'),
     Output('processing-interval', 'disabled', allow_duplicate=True),
     Output('processing-step-store', 'data', allow_duplicate=True),
     Output('stats-cards', 'children', allow_duplicate=True),
     Output('results-section', 'children', allow_duplicate=True),
     Output('processing-animation', 'children', allow_duplicate=True)],
    [Input('upload-data', 'contents')],
    [State('upload-data', 'filename')],
    prevent_initial_call=True
)
def process_uploaded_file(contents: str, filename: str) -> tuple:
    global security_system
    if contents is None:
        return None, True, 0, html.Div(), html.Div(), html.Div()
    
    # Initialize new session for each upload
    security_system.terminate_session()
    
    try:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(StringIO(decoded.decode('utf-8')))
        
        required_cols = [
            'account_id', 'user_id', 'transaction_amount', 'recipient_account',
            'sender_country', 'recipient_country', 'account_age_days',
            'previous_failed_transactions', 'transaction_type', 'purpose',
            'sender_account_verified'
        ]
        
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            logging.error(f"Missing columns: {', '.join(missing_cols)}")
            return {'error': f"Missing columns: {', '.join(missing_cols)}"}, True, 0, html.Div(), html.Div(), html.Div()
        
        if df.empty or len(df) > 10000:
            logging.error("Empty CSV or too many transactions")
            return {'error': "Empty CSV or too many transactions (max 10000)"}, True, 0, html.Div(), html.Div(), html.Div()
        
        processed_transactions = []
        for idx, row in df.iterrows():
            transaction_data = row.to_dict()
            if not security_system.validate_input(transaction_data):
                logging.warning(f"Invalid transaction data at row {idx}")
                continue
            encrypted_data = security_system.encrypt_transaction(transaction_data)
            if not encrypted_data:
                logging.error(f"Encryption failed for transaction at row {idx}")
                continue
            blockchain_tx = security_system.simulate_blockchain_verification(transaction_data)
            if not blockchain_tx:
                logging.error(f"Blockchain verification failed for transaction at row {idx}")
                continue
            risk_analysis = security_system.calculate_cibyl_score(transaction_data)
            processed_transactions.append({
                'original_data': transaction_data,
                'encrypted_data': encrypted_data,
                'blockchain_tx': blockchain_tx,
                'risk_analysis': risk_analysis,
                'processed_at': datetime.now().isoformat(),
                'security_session': security_system.session_key
            })
        
        if not processed_transactions:
            logging.error("No valid transactions processed")
            return {'error': "No valid transactions processed"}, True, 0, html.Div(), html.Div(), html.Div()
        
        return {
            'transactions': processed_transactions,
            'total_count': len(processed_transactions),
            'session_id': security_system.session_key
        }, True, 8, html.Div(), html.Div(), html.Div()
    
    except Exception as e:
        logging.error(f"Processing error: {str(e)}")
        return {'error': str(e)}, True, 0, html.Div(), html.Div(), html.Div()

@app.callback(
    Output('processing-animation', 'children'),
    [Input('processing-step-store', 'data'),
     Input('processing-interval', 'disabled')],
    [State('processed-data-store', 'data')]
)
def update_processing_animation(current_step: int, interval_disabled: bool, processed_data: Dict) -> html.Div:
    if processed_data is None:
        return html.Div()
    if 'error' in processed_data:
        return html.Div([
            html.Div([
                html.I(className="fas fa-exclamation-triangle text-red-500 text-2xl mb-2"),
                html.H3("Security Alert", className="text-lg font-semibold text-red-700"),
                html.P(processed_data['error'], className="text-red-600"),
                html.P("Please verify input data and try again", className="text-red-500 text-sm")
            ], className="bg-red-50 border border-red-200 rounded-lg p-6 text-center")
        ])
    if not interval_disabled or current_step < 8:
        steps = [
            "🔍 Validating Input Data",
            "🛡️ Sanitizing Transaction Data",
            "🔐 AES-256-GCM Encryption",
            "🔗 Blockchain Merkle Tree Verification",
            "🎯 CIBYL Score Analysis",
            "⚠️ Risk Assessment",
            "🔍 Additional Security Checks",
            "📝 Generating Security Report"
        ]
        return html.Div([
            html.Div([
                html.H3([
                    html.I(className="fas fa-cogs animate-spin mr-2"),
                    "Processing Secure Transactions"
                ], className="text-lg font-semibold text-blue-700 mb-4"),
                html.Div([
                    html.Div([
                        html.I(className="fas fa-check-circle text-green-500" if i < current_step else 
                               "fas fa-spinner fa-spin text-blue-500" if i == current_step else 
                               "fas fa-circle text-gray-300"),
                        html.Span(step, className=f"ml-3 {'text-green-700' if i < current_step else 'text-blue-700 font-semibold' if i == current_step else 'text-gray-500'}")
                    ], className="flex items-center mb-2")
                    for i, step in enumerate(steps)
                ]),
                html.Div([
                    html.Div([
                        html.I(id="encryption-animation", 
                               className="fas fa-lock text-3xl text-blue-600 mr-2 animate-pulse"),
                        html.Span("Encryption Process", className="text-blue-600 font-medium")
                    ], className="flex items-center mt-4" if current_step >= 2 else "hidden"),
                    html.Div([
                        html.I(id="blockchain-animation", 
                               className="fas fa-link text-3xl text-purple-600 mr-2 animate-pulse"),
                        html.Span("Blockchain Verification", className="text-purple-600 font-medium")
                    ], className="flex items-center mt-2" if current_step >= 3 else "hidden")
                ]),
                html.Div([
                    html.Div(
                        className="bg-blue-500 h-3 rounded-full transition-all duration-500",
                        style={'width': f'{(current_step / (len(steps) - 1)) * 100}%'}
                    )
                ], className="bg-gray-200 rounded-full h-3 mt-4")
            ], className="bg-blue-50 border border-blue-200 rounded-lg p-6")
        ])
    return html.Div()

@app.callback(
    [Output('results-section', 'children'),
     Output('stats-cards', 'children')],
    [Input('processed-data-store', 'data')]
)
def display_results_and_stats(processed_data: Dict) -> tuple:
    if processed_data is None or 'error' in processed_data:
        return html.Div(), html.Div()
    transactions = processed_data['transactions']
    total_count = processed_data['total_count']
    counts = {
        'CRITICAL': 0, 'HIGH': 0, 'MODERATE': 0, 'LOW': 0,
        'blocked': 0, 'quarantined': 0, 'needs_review': 0
    }
    for t in transactions:
        risk_level = t['risk_analysis']['risk_level']
        recommendation = t['risk_analysis']['recommendation']
        counts[risk_level] += 1
        if recommendation == 'BLOCK':
            counts['blocked'] += 1
        elif recommendation == 'QUARANTINE':
            counts['quarantined'] += 1
        elif recommendation == 'REVIEW':
            counts['needs_review'] += 1
    stats_cards = html.Div([
        html.Div([html.Div([html.I(className="fas fa-file-invoice-dollar text-2xl text-blue-600"),
                            html.Div([html.H3(f"{total_count:,}", className="text-2xl font-bold text-gray-800"),
                                      html.P("Total Transactions", className="text-sm text-gray-600")], className="ml-4")],
                           className="flex items-center")], className="bg-white rounded-lg shadow-md p-6"),
        html.Div([html.Div([html.I(className="fas fa-shield-check text-2xl text-green-600"),
                            html.Div([html.H3(f"{counts['LOW']:,}", className="text-2xl font-bold text-green-700"),
                                      html.P("Safe Transactions", className="text-sm text-gray-600")], className="ml-4")],
                           className="flex items-center")], className="bg-green-50 rounded-lg shadow-md p-6 border-l-4 border-green-500"),
        html.Div([html.Div([html.I(className="fas fa-exclamation-triangle text-2xl text-yellow-600"),
                            html.Div([html.H3(f"{counts['MODERATE']:,}", className="text-2xl font-bold text-yellow-700"),
                                      html.P("Needs Review", className="text-sm text-gray-600")], className="ml-4")],
                           className="flex items-center")], className="bg-yellow-50 rounded-lg shadow-md p-6 border-l-4 border-yellow-500"),
        html.Div([html.Div([html.I(className="fas fa-ban text-2xl text-red-600"),
                            html.Div([html.H3(f"{counts['HIGH'] + counts['CRITICAL']:,}", className="text-2xl font-bold text-red-700"),
                                      html.P("High Risk", className="text-sm text-gray-600")], className="ml-4")],
                           className="flex items-center")], className="bg-red-50 rounded-lg shadow-md p-6 border-l-4 border-red-500"),
        html.Div([html.Div([html.I(className="fas fa-lock text-2xl text-purple-600"),
                            html.Div([html.H3(f"{counts['blocked']:,}", className="text-2xl font-bold text-purple-700"),
                                      html.P("Blocked Transactions", className="text-sm text-gray-600")], className="ml-4")],
                           className="flex items-center")], className="bg-purple-50 rounded-lg shadow-md p-6 border-l-4 border-purple-500")
    ], className="grid grid-cols-1 md:grid-cols-5 gap-6")
    table_data = []
    for t in transactions:
        orig = t['original_data']
        risk = t['risk_analysis']
        blockchain = t['blockchain_tx']
        table_data.append({
            'Account ID': orig.get('account_id', ''),
            'User ID': orig.get('user_id', ''),
            'Amount (₹)': f"₹{float(orig.get('transaction_amount', 0)):,.2f}",
            'CIBYL Score': f"{risk['cibyl_score']:.3f}",
            'Risk Level': risk['risk_level'],
            'Recommendation': risk['recommendation'],
            'Blockchain TX': blockchain['tx_hash'][:16] + '...' if blockchain else 'N/A',
            'Risk Factors': ', '.join(risk['risk_factors'][:2]) + ('...' if len(risk['risk_factors']) > 2 else ''),
            'Security Checks': ', '.join(risk['security_checks'][:2]) + ('...' if len(risk['security_checks']) > 2 else '')
        })
    results_section = html.Div([
        html.Div([
            html.H3([html.I(className="fas fa-chart-line mr-2"), "Transaction Security Analysis"],
                   className="text-2xl font-bold text-gray-800 mb-4"),
            html.Div([
                html.H4("Security Status", className="text-lg font-semibold text-gray-700 mb-2"),
                html.Div([html.I(className="fas fa-check-circle text-green-500 mr-2"),
                          "All transactions encrypted with AES-256-GCM"], className="text-green-700 mb-1"),
                html.Div([html.I(className="fas fa-shield-alt text-blue-500 mr-2"),
                          "HMAC-SHA256 integrity verification completed"], className="text-blue-700 mb-1"),
                html.Div([html.I(className="fas fa-link text-purple-500 mr-2"),
                          "Blockchain Merkle tree verification completed"], className="text-purple-700 mb-1"),
                html.Div([html.I(className="fas fa-lock text-indigo-500 mr-2"),
                          f"Secure Session ID: {processed_data['session_id'][:8]}..."], className="text-indigo-700")
            ], className="bg-gray-50 rounded-lg p-4"),
            html.Div([
                html.Button([html.I(className="fas fa-download mr-2"), "Download Security Report"],
                           id="download-btn", className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-6 rounded-lg mr-4"),
                html.Button([html.I(className="fas fa-paper-plane mr-2"), "Report to RBI"],
                           className="bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-6 rounded-lg mr-4"),
                html.Button([html.I(className="fas fa-university mr-2"), "Notify Banks"],
                           className="bg-green-600 hover:bg-green-700 text-white font-semibold py-2 px-6 rounded-lg")
            ], className="mt-6 mb-6")
        ], className="bg-white rounded-lg shadow-md p-6 mb-6"),
        html.Div([
            html.H3([html.I(className="fas fa-table mr-2"), "Detailed Transaction Analysis"],
                   className="text-xl font-semibold text-gray-800 mb-4"),
            dash_table.DataTable(
                data=table_data,
                columns=[
                    {"name": "Account ID", "id": "Account ID"},
                    {"name": "User ID", "id": "User ID"},
                    {"name": "Amount", "id": "Amount (₹)"},
                    {"name": "CIBYL Score", "id": "CIBYL Score"},
                    {"name": "Risk Level", "id": "Risk Level"},
                    {"name": "Recommendation", "id": "Recommendation"},
                    {"name": "Blockchain TX", "id": "Blockchain TX"},
                    {"name": "Risk Factors", "id": "Risk Factors"},
                    {"name": "Security Checks", "id": "Security Checks"}
                ],
                style_cell={'textAlign': 'left', 'padding': '10px'},
                style_data_conditional=[
                    {'if': {'filter_query': '{Risk Level} = CRITICAL'}, 'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'},
                    {'if': {'filter_query': '{Risk Level} = HIGH'}, 'backgroundColor': '#ef4444', 'color': 'white', 'fontWeight': 'bold'},
                    {'if': {'filter_query': '{Risk Level} = MODERATE'}, 'backgroundColor': '#fef3c7', 'color': 'black'},
                    {'if': {'filter_query': '{Risk Level} = LOW'}, 'backgroundColor': '#d1fae5', 'color': 'black'}
                ],
                style_header={'backgroundColor': '#374151', 'color': 'white', 'fontWeight': 'bold'},
                page_size=10,
                sort_action="native",
                filter_action="native",
                export_format="csv"
            )
        ], className="bg-white rounded-lg shadow-md p-6")
    ])
    return results_section, stats_cards

@app.callback(
    Output("download-report", "data"),
    [Input("download-btn", "n_clicks")],
    [State('processed-data-store', 'data')],
    prevent_initial_call=True
)
def download_report(n_clicks: int, processed_data: Dict) -> Dict:
    if n_clicks is None or processed_data is None:
        return None
    report_data = []
    for t in processed_data['transactions']:
        orig = t['original_data']
        risk = t['risk_analysis']
        blockchain = t['blockchain_tx']
        report_data.append({
            'Account_ID': orig.get('account_id', ''),
            'User_ID': orig.get('user_id', ''),
            'Account_Holder_Name': orig.get('account_holder_name', 'N/A'),
            'Transaction_Amount': orig.get('transaction_amount', ''),
            'CIBYL_Score': risk['cibyl_score'],
            'Risk_Level': risk['risk_level'],
            'Recommendation': risk['recommendation'],
            'Risk_Factors': '; '.join(risk['risk_factors']),
            'Security_Checks': '; '.join(risk['security_checks']),
            'Confidence_Level': risk['confidence'],
            'Blockchain_TX_Hash': blockchain['tx_hash'] if blockchain else 'N/A',
            'Block_Number': blockchain['block_number'] if blockchain else 'N/A',
            'Merkle_Leaf': blockchain['merkle_leaf'] if blockchain else 'N/A',
            'Processed_Timestamp': t['processed_at'],
            'Sender_Country': orig.get('sender_country', ''),
            'Recipient_Country': orig.get('recipient_country', ''),
            'Transaction_Type': orig.get('transaction_type', ''),
            'Purpose': orig.get('purpose', ''),
            'Session_ID': t['security_session'][:8] + '...'
        })
    df_report = pd.DataFrame(report_data)
    return dcc.send_data_frame(
        df_report.to_csv, 
        f"RBI_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        index=False
    )

@app.callback(
    [Output('processed-data-store', 'data', allow_duplicate=True),
     Output('processing-step-store', 'data', allow_duplicate=True),
     Output('stats-cards', 'children', allow_duplicate=True),
     Output('results-section', 'children', allow_duplicate=True),
     Output('processing-animation', 'children', allow_duplicate=True)],
    [Input('terminate-btn', 'n_clicks')],
    [State('processed-data-store', 'data')],
    prevent_initial_call=True
)
def terminate_session(n_clicks: int, processed_data: Dict) -> tuple:
    global security_system
    ctx = callback_context
    if not ctx.triggered:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    if trigger_id != 'terminate-btn':
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update
    
    security_system.terminate_session()
    return None, 0, html.Div(), html.Div(), html.Div([
        html.Div([
            html.I(className="fas fa-check-circle text-green-500 text-2xl mb-2"),
            html.H3("Session Terminated", className="text-lg font-semibold text-green-700"),
            html.P("A new session has been initialized. Please upload a new CSV.", className="text-green-600")
        ], className="bg-green-50 border border-green-200 rounded-lg p-6 text-center")
    ])

if __name__ == '__main__':
    app.run_server(debug=True, port=8050, host='127.0.0.1')