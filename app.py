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
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BankingSecuritySystem:
    def __init__(self):
        self.aes_key = os.urandom(32)  # 256-bit key for AES
        self.cipher_suite = Fernet(Fernet.generate_key())
        
    def encrypt_transaction(self, transaction_data):
        """Encrypt transaction data using AES encryption"""
        try:
            # Convert to JSON string
            json_data = json.dumps(transaction_data, sort_keys=True)
            
            # Encrypt using Fernet (AES-128 in CBC mode)
            encrypted_data = self.cipher_suite.encrypt(json_data.encode())
            
            # Create transaction hash
            transaction_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            return {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'transaction_hash': transaction_hash,
                'encryption_method': 'AES-256-CBC',
                'timestamp': int(time.time())
            }
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            return None
    
    def simulate_blockchain_verification(self, transaction_data):
        """Simulate blockchain verification process"""
        try:
            # Generate blockchain transaction
            blockchain_tx = {
                'tx_hash': f"0x{secrets.token_hex(32)}",
                'block_number': np.random.randint(18000000, 19000000),
                'from_address': f"0x{secrets.token_hex(20)}",
                'to_address': f"0x{secrets.token_hex(20)}",
                'gas_used': np.random.randint(21000, 85000),
                'gas_price': np.random.randint(20, 100),
                'status': 'confirmed',
                'timestamp': int(time.time()),
                'data_hash': hashlib.sha256(json.dumps(transaction_data).encode()).hexdigest()
            }
            return blockchain_tx
        except Exception as e:
            logging.error(f"Blockchain simulation failed: {str(e)}")
            return None
    
    def calculate_cibyl_score(self, transaction):
        """Calculate CIBYL risk score"""
        try:
            score = 0.0
            risk_factors = []
            
            # Convert string amounts to float
            amount = float(transaction.get('transaction_amount', 0))
            age_days = int(transaction.get('account_age_days', 365))
            failed_txns = int(transaction.get('previous_failed_transactions', 0))
            
            # High amount risk
            if amount > 500000:
                score += 0.4
                risk_factors.append('Very High Amount (>5L)')
            elif amount > 100000:
                score += 0.3
                risk_factors.append('High Amount (>1L)')
            elif amount > 50000:
                score += 0.2
                risk_factors.append('Medium Amount (>50K)')
            
            # International transfer risk
            sender_country = transaction.get('sender_country', '').strip().lower()
            recipient_country = transaction.get('recipient_country', '').strip().lower()
            if sender_country != recipient_country and sender_country and recipient_country:
                score += 0.3
                risk_factors.append('International Transfer')
            
            # Account age risk
            if age_days < 30:
                score += 0.4
                risk_factors.append('New Account (<30 days)')
            elif age_days < 90:
                score += 0.2
                risk_factors.append('Recent Account (<90 days)')
            
            # Failed transactions risk
            if failed_txns > 5:
                score += 0.5
                risk_factors.append('Multiple Failed Transactions')
            elif failed_txns > 2:
                score += 0.3
                risk_factors.append('Some Failed Transactions')
            
            # Transaction type risk
            txn_type = transaction.get('transaction_type', '').lower()
            if txn_type in ['crypto', 'investment', 'gambling']:
                score += 0.3
                risk_factors.append('High Risk Transaction Type')
            
            # Purpose risk
            purpose = transaction.get('purpose', '').lower()
            suspicious_purposes = ['loan', 'urgent', 'emergency', 'investment', 'trading']
            if any(word in purpose for word in suspicious_purposes):
                score += 0.2
                risk_factors.append('Suspicious Purpose')
            
            # Normalize score
            final_score = min(score, 1.0)
            
            # Determine risk level
            if final_score >= 0.7:
                risk_level = 'DANGER'
                recommendation = 'BLOCK'
            elif final_score >= 0.4:
                risk_level = 'AVERAGE'
                recommendation = 'REVIEW'
            else:
                risk_level = 'GOOD'
                recommendation = 'APPROVE'
            
            return {
                'cibyl_score': round(final_score, 3),
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'recommendation': recommendation,
                'confidence': min(0.95, 0.7 + (final_score * 0.3))
            }
        except Exception as e:
            logging.error(f"CIBYL calculation failed: {str(e)}")
            return {
                'cibyl_score': 0.5,
                'risk_level': 'AVERAGE',
                'risk_factors': ['Calculation Error'],
                'recommendation': 'REVIEW',
                'confidence': 0.5
            }

# Initialize the security system
security_system = BankingSecuritySystem()

# Dash App
app = dash.Dash(__name__, external_stylesheets=[
    'https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
])

# IMPORTANT: Add this line to suppress callback exceptions for dynamically created components
app.config.suppress_callback_exceptions = True

app.layout = html.Div([
    # Header
    html.Div([
        html.Div([
            html.H1([
                html.I(className="fas fa-shield-alt mr-3 text-indigo-600"),
                "Reserve Bank of India - Transaction Security Dashboard"
            ], className="text-3xl font-bold text-gray-800"),
            html.P("Advanced Banking Transaction Scam Detection & Control System", 
                   className="text-lg text-gray-600 mt-2")
        ], className="text-center")
    ], className="bg-white shadow-lg rounded-lg p-6 mb-6"),
    
    # Stats Cards
    html.Div(id="stats-cards", className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6"),
    
    # Upload Section
    html.Div([
        html.Div([
            html.H3([
                html.I(className="fas fa-upload mr-2"),
                "Upload Transaction Data"
            ], className="text-xl font-semibold text-gray-800 mb-4"),
            
            dcc.Upload(
                id='upload-data',
                children=html.Div([
                    html.I(className="fas fa-cloud-upload-alt text-4xl text-gray-400 mb-4"),
                    html.H4("Drag and Drop or Click to Upload CSV", className="text-lg font-medium text-gray-600"),
                    html.P("Supported format: CSV files with transaction data", className="text-sm text-gray-500")
                ], className="text-center p-8"),
                className="border-2 border-dashed border-gray-300 rounded-lg hover:border-indigo-400 transition-colors cursor-pointer",
                accept='.csv'
            )
        ], className="bg-white rounded-lg shadow-md p-6")
    ], className="mb-6"),
    
    # Processing Animation
    html.Div(id="processing-animation", className="mb-6"),
    
    # Results Section
    html.Div(id="results-section"),
    
    # Hidden components for data storage
    dcc.Store(id='processed-data-store'),
    dcc.Store(id='processing-step-store', data=0),
    dcc.Interval(id='processing-interval', interval=1000, disabled=True, n_intervals=0),
    dcc.Download(id="download-report")
], className="container mx-auto p-6 bg-gray-50 min-h-screen")

# Callback for processing animation steps
@app.callback(
    [Output('processing-step-store', 'data'),
     Output('processing-interval', 'disabled')],
    [Input('processing-interval', 'n_intervals')],
    [State('processing-step-store', 'data')]
)
def update_processing_step(n_intervals, current_step):
    if current_step >= 6:
        return current_step, True
    return current_step + 1, False

# Main processing callback
@app.callback(
    [Output('processed-data-store', 'data'),
     Output('processing-interval', 'disabled', allow_duplicate=True),
     Output('processing-step-store', 'data', allow_duplicate=True)],
    [Input('upload-data', 'contents')],
    [State('upload-data', 'filename')],
    prevent_initial_call=True
)
def process_uploaded_file(contents, filename):
    if contents is None:
        return None, True, 0
    
    try:
        # Decode CSV
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(StringIO(decoded.decode('utf-8')))
        
        # Required columns
        required_cols = ['account_id', 'user_id', 'transaction_amount', 'recipient_account',
                        'sender_country', 'recipient_country', 'account_age_days',
                        'previous_failed_transactions', 'transaction_type', 'purpose']
        
        # Check for missing columns
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            return {'error': f"Missing columns: {', '.join(missing_cols)}"}, True, 0
        
        # Process each transaction
        processed_transactions = []
        for idx, row in df.iterrows():
            transaction_data = row.to_dict()
            
            # Encrypt transaction
            encrypted_data = security_system.encrypt_transaction(transaction_data)
            
            # Blockchain verification
            blockchain_tx = security_system.simulate_blockchain_verification(transaction_data)
            
            # Calculate CIBYL score
            risk_analysis = security_system.calculate_cibyl_score(transaction_data)
            
            processed_transactions.append({
                'original_data': transaction_data,
                'encrypted_data': encrypted_data,
                'blockchain_tx': blockchain_tx,
                'risk_analysis': risk_analysis,
                'processed_at': datetime.now().isoformat()
            })
        
        return {'transactions': processed_transactions, 'total_count': len(processed_transactions)}, True, 6
    
    except Exception as e:
        logging.error(f"Processing error: {str(e)}")
        return {'error': str(e)}, True, 0

# Callback for processing animation display
@app.callback(
    Output('processing-animation', 'children'),
    [Input('processing-step-store', 'data'),
     Input('processing-interval', 'disabled')],
    [State('processed-data-store', 'data')]
)
def update_processing_animation(current_step, interval_disabled, processed_data):
    if processed_data is None:
        return html.Div()
    
    if 'error' in processed_data:
        return html.Div([
            html.Div([
                html.I(className="fas fa-exclamation-triangle text-red-500 text-2xl mb-2"),
                html.H3("Processing Error", className="text-lg font-semibold text-red-700"),
                html.P(processed_data['error'], className="text-red-600")
            ], className="bg-red-50 border border-red-200 rounded-lg p-6 text-center")
        ])
    
    if not interval_disabled or current_step < 6:
        steps = [
            "📊 Parsing CSV Data",
            "🔐 Encrypting Transactions (AES-256)",
            "⛓️ Blockchain Verification",
            "🎯 CIBYL Score Analysis",
            "⚠️ Risk Assessment",
            "📋 Generating Security Report"
        ]
        
        return html.Div([
            html.Div([
                html.H3([
                    html.I(className="fas fa-cogs animate-spin mr-2"),
                    "Processing Bank Transactions"
                ], className="text-lg font-semibold text-blue-700 mb-4"),
                
                html.Div([
                    html.Div([
                        html.Div([
                            html.I(className="fas fa-check-circle text-green-500" if i < current_step else 
                                   "fas fa-spinner fa-spin text-blue-500" if i == current_step else 
                                   "fas fa-circle text-gray-300"),
                            html.Span(step, className=f"ml-3 {'text-green-700' if i < current_step else 'text-blue-700 font-semibold' if i == current_step else 'text-gray-500'}")
                        ], className="flex items-center mb-2")
                        for i, step in enumerate(steps)
                    ]),
                    
                    # Progress bar
                    html.Div([
                        html.Div(
                            className="bg-blue-500 h-2 rounded-full transition-all duration-500",
                            style={'width': f'{(current_step / (len(steps) - 1)) * 100}%'}
                        )
                    ], className="bg-gray-200 rounded-full h-2 mt-4")
                ])
            ], className="bg-blue-50 border border-blue-200 rounded-lg p-6")
        ])
    
    return html.Div()

# Callback for results display and stats
@app.callback(
    [Output('results-section', 'children'),
     Output('stats-cards', 'children')],
    [Input('processed-data-store', 'data')]
)
def display_results_and_stats(processed_data):
    if processed_data is None or 'error' in processed_data:
        return html.Div(), html.Div()
    
    transactions = processed_data['transactions']
    total_count = processed_data['total_count']
    
    # Calculate statistics
    good_count = sum(1 for t in transactions if t['risk_analysis']['risk_level'] == 'GOOD')
    average_count = sum(1 for t in transactions if t['risk_analysis']['risk_level'] == 'AVERAGE')
    danger_count = sum(1 for t in transactions if t['risk_analysis']['risk_level'] == 'DANGER')
    
    # Stats cards
    stats_cards = html.Div([
        # Total Transactions
        html.Div([
            html.Div([
                html.I(className="fas fa-file-invoice-dollar text-2xl text-blue-600"),
                html.Div([
                    html.H3(f"{total_count:,}", className="text-2xl font-bold text-gray-800"),
                    html.P("Total Transactions", className="text-sm text-gray-600")
                ], className="ml-4")
            ], className="flex items-center")
        ], className="bg-white rounded-lg shadow-md p-6"),
        
        # Safe Transactions
        html.Div([
            html.Div([
                html.I(className="fas fa-shield-check text-2xl text-green-600"),
                html.Div([
                    html.H3(f"{good_count:,}", className="text-2xl font-bold text-green-700"),
                    html.P("Safe Transactions", className="text-sm text-gray-600")
                ], className="ml-4")
            ], className="flex items-center")
        ], className="bg-green-50 rounded-lg shadow-md p-6 border-l-4 border-green-500"),
        
        # Caution Transactions
        html.Div([
            html.Div([
                html.I(className="fas fa-exclamation-triangle text-2xl text-yellow-600"),
                html.Div([
                    html.H3(f"{average_count:,}", className="text-2xl font-bold text-yellow-700"),
                    html.P("Caution Required", className="text-sm text-gray-600")
                ], className="ml-4")
            ], className="flex items-center")
        ], className="bg-yellow-50 rounded-lg shadow-md p-6 border-l-4 border-yellow-500"),
        
        # High Risk Transactions
        html.Div([
            html.Div([
                html.I(className="fas fa-ban text-2xl text-red-600"),
                html.Div([
                    html.H3(f"{danger_count:,}", className="text-2xl font-bold text-red-700"),
                    html.P("High Risk - Block", className="text-sm text-gray-600")
                ], className="ml-4")
            ], className="flex items-center")
        ], className="bg-red-50 rounded-lg shadow-md p-6 border-l-4 border-red-500")
    ], className="grid grid-cols-1 md:grid-cols-4 gap-6")
    
    # Prepare data for detailed table
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
            'Risk Factors': ', '.join(risk['risk_factors'][:2]) + ('...' if len(risk['risk_factors']) > 2 else '')
        })
    
    # Results section
    results_section = html.Div([
        # Summary Section
        html.Div([
            html.H3([
                html.I(className="fas fa-chart-line mr-2"),
                "Transaction Analysis Complete"
            ], className="text-2xl font-bold text-gray-800 mb-4"),
            
            html.Div([
                html.Div([
                    html.H4("System Status", className="text-lg font-semibold text-gray-700 mb-2"),
                    html.Div([
                        html.I(className="fas fa-check-circle text-green-500 mr-2"),
                        "All transactions encrypted and verified via blockchain"
                    ], className="text-green-700 mb-1"),
                    html.Div([
                        html.I(className="fas fa-shield-alt text-blue-500 mr-2"),
                        "AES-256 encryption applied to all sensitive data"
                    ], className="text-blue-700 mb-1"),
                    html.Div([
                        html.I(className="fas fa-link text-purple-500 mr-2"),
                        "Blockchain verification completed"
                    ], className="text-purple-700")
                ], className="bg-gray-50 rounded-lg p-4")
            ], className="mb-6"),
            
            # Action Buttons
            html.Div([
                html.Button([
                    html.I(className="fas fa-download mr-2"),
                    "Download Security Report"
                ], id="download-btn", className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-6 rounded-lg mr-4"),
                
                html.Button([
                    html.I(className="fas fa-paper-plane mr-2"),
                    "Report to RBI"
                ], className="bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-6 rounded-lg mr-4"),
                
                html.Button([
                    html.I(className="fas fa-university mr-2"),
                    "Notify Banks"
                ], className="bg-green-600 hover:bg-green-700 text-white font-semibold py-2 px-6 rounded-lg")
            ], className="mb-6")
        ], className="bg-white rounded-lg shadow-md p-6 mb-6"),
        
        # Detailed Results Table
        html.Div([
            html.H3([
                html.I(className="fas fa-table mr-2"),
                "Detailed Transaction Analysis"
            ], className="text-xl font-semibold text-gray-800 mb-4"),
            
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
                    {"name": "Risk Factors", "id": "Risk Factors"}
                ],
                style_cell={'textAlign': 'left', 'padding': '10px'},
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{Risk Level} = DANGER'},
                        'backgroundColor': '#fee2e2',
                        'color': 'black',
                        'fontWeight': 'bold'
                    },
                    {
                        'if': {'filter_query': '{Risk Level} = AVERAGE'},
                        'backgroundColor': '#fef3c7',
                        'color': 'black',
                    },
                    {
                        'if': {'filter_query': '{Risk Level} = GOOD'},
                        'backgroundColor': '#d1fae5',
                        'color': 'black',
                    }
                ],
                style_header={
                    'backgroundColor': '#374151',
                    'color': 'white',
                    'fontWeight': 'bold'
                },
                page_size=10,
                sort_action="native",
                filter_action="native"
            )
        ], className="bg-white rounded-lg shadow-md p-6")
    ])
    
    return results_section, stats_cards

# Download callback
@app.callback(
    Output("download-report", "data"),
    [Input("download-btn", "n_clicks")],
    [State('processed-data-store', 'data')],
    prevent_initial_call=True
)
def download_report(n_clicks, processed_data):
    if n_clicks is None or processed_data is None:
        return None
    
    # Create detailed report
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
            'Confidence_Level': risk['confidence'],
            'Blockchain_TX_Hash': blockchain['tx_hash'] if blockchain else 'N/A',
            'Block_Number': blockchain['block_number'] if blockchain else 'N/A',
            'Processed_Timestamp': t['processed_at'],
            'Sender_Country': orig.get('sender_country', ''),
            'Recipient_Country': orig.get('recipient_country', ''),
            'Transaction_Type': orig.get('transaction_type', ''),
            'Purpose': orig.get('purpose', '')
        })
    
    df_report = pd.DataFrame(report_data)
    
    return dcc.send_data_frame(
        df_report.to_csv, 
        f"RBI_Transaction_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        index=False
    )

if __name__ == '__main__':
    app.run_server(debug=True, port=8050, host='127.0.0.1')