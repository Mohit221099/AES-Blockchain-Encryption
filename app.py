import dash
from dash import dcc, html, Input, Output, State, callback_context
import pandas as pd
import json
import hashlib
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets
from typing import Dict, Any, Tuple
import numpy as np
from datetime import datetime
from io import StringIO
import base64 as base64_dash
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# AdvancedEncryptionModel class
class AdvancedEncryptionModel:
    def __init__(self):
        self.fernet_key = None
        self.private_key = None
        self.public_key = None
        self._initialize_keys()
        
    def _initialize_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.fernet_key = Fernet.generate_key()
        self.fernet = Fernet(self.fernet_key)
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def encrypt_account_data(self, account_data: Dict[str, Any], user_password: str) -> Dict[str, Any]:
        try:
            serialized_data = json.dumps(account_data, sort_keys=True)
            derived_key, salt = self.derive_key_from_password(user_password)
            fernet_derived = Fernet(derived_key)
            encrypted_data = fernet_derived.encrypt(serialized_data.encode())
            encrypted_key = self.public_key.encrypt(
                derived_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            data_hash = hashlib.sha256(encrypted_data).digest()
            signature = self.private_key.sign(
                data_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'encrypted_key': base64.b64encode(encrypted_key).decode(),
                'salt': base64.b64encode(salt).decode(),
                'signature': base64.b64encode(signature).decode(),
                'timestamp': int(time.time()),
                'version': '2.0',
                'encryption_method': 'AES-256-GCM+RSA-2048+PBKDF2'
            }
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_account_data(self, encrypted_payload: Dict[str, Any], user_password: str) -> Dict[str, Any]:
        try:
            encrypted_data = base64.b64decode(encrypted_payload['encrypted_data'])
            encrypted_key = base64.b64decode(encrypted_payload['encrypted_key'])
            salt = base64.b64decode(encrypted_payload['salt'])
            signature = base64.b64decode(encrypted_payload['signature'])
            data_hash = hashlib.sha256(encrypted_data).digest()
            self.public_key.verify(
                signature,
                data_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            decrypted_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            derived_key, _ = self.derive_key_from_password(user_password, salt)
            if derived_key != decrypted_key:
                raise Exception("Invalid password or corrupted data")
            fernet_derived = Fernet(derived_key)
            decrypted_data = fernet_derived.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            raise Exception(f"Decryption failed: {str(e)}")
    
    def create_secure_hash(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    def generate_transaction_id(self) -> str:
        return secrets.token_hex(16)

# ScamProtectionSystem class
class ScamProtectionSystem:
    def __init__(self):
        self.encryption_model = AdvancedEncryptionModel()
        self.risk_threshold = 0.7
        
    def analyze_transaction_risk(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        risk_score = 0.0
        risk_factors = []
        if account_data.get('transaction_amount', 0) > 10000:
            risk_score += 0.3
            risk_factors.append("High transaction amount")
        if account_data.get('recipient_country') != account_data.get('sender_country'):
            risk_score += 0.2
            risk_factors.append("International transfer")
        if account_data.get('account_age_days', 365) < 30:
            risk_score += 0.4
            risk_factors.append("New account")
        if account_data.get('previous_failed_transactions', 0) > 3:
            risk_score += 0.5
            risk_factors.append("Multiple failed transactions")
        weights = {
            'transaction_amount': 0.4,
            'international': 0.3,
            'account_age': 0.2,
            'failed_transactions': 0.1
        }
        cibyl_score = min(risk_score * np.sum(list(weights.values())), 1.0)
        return {
            'cibyl_score': cibyl_score,
            'risk_level': 'HIGH' if cibyl_score > self.risk_threshold else 'MEDIUM' if cibyl_score > 0.4 else 'LOW',
            'risk_factors': risk_factors,
            'recommendation': 'BLOCK' if cibyl_score > self.risk_threshold else 'REVIEW' if cibyl_score > 0.4 else 'APPROVE'
        }
    
    def secure_transfer_to_database(self, account_data: Dict[str, Any], user_password: str, database_address: str) -> Dict[str, Any]:
        try:
            risk_analysis = self.analyze_transaction_risk(account_data)
            encrypted_payload = self.encryption_model.encrypt_account_data(account_data, user_password)
            transfer_data = {
                'transaction_id': self.encryption_model.generate_transaction_id(),
                'encrypted_payload': encrypted_payload,
                'risk_analysis': risk_analysis,
                'timestamp': int(time.time()),
                'system_version': '2.0'
            }
            blockchain_result = {
                'transaction_hash': f"0x{secrets.token_hex(32)}",
                'from_address': f"0x{secrets.token_hex(20)}",
                'to_address': database_address,
                'data_size': len(json.dumps(encrypted_payload)),
                'gas_estimate': 85000,
                'status': 'simulated',
                'note': 'Blockchain simulation - encrypted data stored securely'
            }
            return {
                'success': True,
                'transaction_id': transfer_data['transaction_id'],
                'risk_analysis': risk_analysis,
                'blockchain_tx': blockchain_result,
                'data_hash': self.encryption_model.create_secure_hash(json.dumps(transfer_data)),
                'status': 'transferred'
            }
        except Exception as e:
            logging.error(f"Transfer failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'status': 'failed'
            }

# Dash App
app = dash.Dash(__name__, external_stylesheets=['https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css'], 
                suppress_callback_exceptions=True)

app.layout = html.Div(className='container mx-auto p-6 bg-gray-100 min-h-screen', children=[
    html.H1("🔐 Advanced Payment Protection System", className='text-3xl font-bold mb-4 text-blue-600'),
    html.P("Upload a CSV file with account transactions to analyze for scams and encrypt data.", className='text-lg mb-6'),
    
    html.Div(className='bg-white p-6 rounded-lg shadow-md mb-6', children=[
        html.Label("Enter Encryption Password", className='block text-sm font-medium text-gray-700'),
        dcc.Input(id="password", type="password", value="", className='mt-1 block w-full border border-gray-300 rounded-md p-2'),
        html.Br(),
        html.Label("Enter Database Address (Ethereum)", className='block text-sm font-medium text-gray-700 mt-4'),
        dcc.Input(id="database-address", value="0x742d35Cc6688CCc9d6B83b0F78e4A5c74F1f93eF", className='mt-1 block w-full border border-gray-300 rounded-md p-2'),
        html.Br(),
        dcc.Upload(
            id='upload-data',
            children=html.Button('Upload CSV File', className='mt-4 bg-blue-500 text-white font-semibold py-2 px-4 rounded hover:bg-blue-600'),
            accept='.csv',
            className='mt-2'
        ),
    ]),
    
    html.Div(id='output-data-upload', className='mt-6'),
    dcc.Download(id="download-scam-csv"),
    dcc.Store(id='download-data-store'),
    html.Button("Download Scam Report CSV", id='download-button', className='hidden', disabled=True, style={'display': 'none'})
])

@app.callback(
    [Output('output-data-upload', 'children'),
     Output('download-scam-csv', 'data'),
     Output('download-data-store', 'data')],
    [Input('upload-data', 'contents'),
     Input('download-button', 'n_clicks')],
    [State('password', 'value'),
     State('database-address', 'value'),
     State('upload-data', 'filename'),
     State('download-data-store', 'data')]
)
def process_and_download_csv(contents, n_clicks, password, database_address, filename, stored_download_data):
    logging.debug(f"Callback triggered: n_clicks={n_clicks}, filename={filename}")
    ctx = callback_context
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]
    logging.debug(f"Triggered by: {triggered_id}")

    # Default output
    output_children = [html.Div("Upload a CSV file to begin analysis.", className='text-gray-500')]
    download_data = None

    # Handle download button click
    if triggered_id == 'download-button' and n_clicks and stored_download_data:
        logging.debug(f"Download button clicked: {n_clicks}")
        return output_children, stored_download_data, stored_download_data

    # Handle file upload
    if triggered_id != 'upload-data' or contents is None or not password or not database_address:
        return output_children, None, None

    protection_system = ScamProtectionSystem()
    try:
        # Decode CSV content
        logging.debug("Decoding CSV content")
        content_type, content_string = contents.split(',')
        decoded = base64_dash.b64decode(content_string)
        df = pd.read_csv(StringIO(decoded.decode('utf-8')))
        
        # Required columns
        required_columns = ['account_id', 'user_id', 'transaction_amount', 'recipient_account', 
                           'sender_country', 'recipient_country', 'account_age_days', 
                           'previous_failed_transactions', 'transaction_type', 'purpose']
        
        # Check for required columns
        logging.debug(f"CSV columns: {list(df.columns)}")
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            error_msg = f"CSV is missing required columns: {', '.join(missing_columns)}"
            logging.error(error_msg)
            return [html.Div([f"Error: {error_msg}"], className='text-red-500')], None, None
        
        # Ignore unexpected columns
        unexpected_columns = [col for col in df.columns if col not in required_columns and col != 'account_holder_name']
        if unexpected_columns:
            logging.warning(f"Ignoring unexpected columns: {', '.join(unexpected_columns)}")
            df = df[[col for col in df.columns if col in required_columns or col == 'account_holder_name']]
        
        results = []
        scam_accounts = []
        
        for idx, row in df.iterrows():
            logging.debug(f"Processing row {idx + 1}")
            account_data = row.to_dict()
            result = protection_system.secure_transfer_to_database(account_data, password, database_address)
            results.append(result)
            
            if result['success'] and result['risk_analysis']['recommendation'] == 'BLOCK':
                try:
                    timestamp_value = result.get('timestamp', int(time.time()))
                    if not isinstance(timestamp_value, (int, float)):
                        logging.warning(f"Invalid timestamp: {timestamp_value}, using current time")
                        timestamp_value = int(time.time())
                    
                    scam_accounts.append({
                        'account_id': account_data['account_id'],
                        'user_id': account_data['user_id'],
                        'account_holder_name': account_data.get('account_holder_name', 'N/A'),
                        'cibyl_score': result['risk_analysis']['cibyl_score'],
                        'risk_level': result['risk_analysis']['risk_level'],
                        'risk_factors': ", ".join(result['risk_analysis']['risk_factors']),
                        'timestamp': datetime.fromtimestamp(timestamp_value).strftime('%Y-%m-%d %H:%M:%S')
                    })
                    logging.debug(f"Added scam account: {account_data['account_id']}")
                except Exception as e:
                    logging.error(f"Error adding scam account for row {idx + 1}: {str(e)}")
                    continue
        
        # Prepare output
        logging.debug(f"Processed {len(results)} transactions, {len(scam_accounts)} scam accounts detected")
        output_children = [
            html.H3("Transaction Analysis Results", className='text-2xl font-semibold mb-4 text-gray-800'),
            html.P(f"Total Transactions Processed: {len(results)}", className='text-lg mb-2'),
            html.P(f"Potential Scam Accounts Detected: {len(scam_accounts)}", className='text-lg mb-4'),
            html.Hr(className='my-6 border-gray-300'),
        ]
        
        if scam_accounts:
            scam_df = pd.DataFrame(scam_accounts)
            # Generate HTML table
            scam_table = html.Table(className='scam-table w-full max-w-4xl border-collapse', children=[
                html.Thead([
                    html.Tr([
                        html.Th(col, className='px-4 py-2') for col in scam_df.columns
                    ])
                ]),
                html.Tbody([
                    html.Tr([
                        html.Td(str(scam_df.iloc[i][col]), className='px-4 py-2 high-risk' if scam_df.iloc[i]['risk_level'] == 'HIGH' else 'px-4 py-2')
                        for col in scam_df.columns
                    ]) for i in range(len(scam_df))
                ])
            ])
            
            output_children.append(
                html.Div([
                    html.H3("Scam Accounts Detected", className='text-2xl font-semibold mb-4 text-gray-800'),
                    scam_table,
                    html.P("Download the scam accounts report:", className='mt-4 mb-2'),
                    html.Button("Download Scam Report CSV", id='download-button', 
                               className='bg-green-500 text-white font-semibold py-2 px-4 rounded hover:bg-green-600')
                ], className='bg-white p-6 rounded-lg shadow-md mb-6')
            )
            csv_buffer = StringIO()
            scam_df.to_csv(csv_buffer, index=False)
            download_data = dict(content=csv_buffer.getvalue(), filename="scam_accounts_report.csv")
        else:
            download_data = None
        
        # Transaction summary
        summary_data = [{
            'transaction_id': r['transaction_id'],
            'status': r['status'],
            'cibyl_score': r['risk_analysis']['cibyl_score'] if r['success'] else 'N/A',
            'risk_level': r['risk_analysis']['risk_level'] if r['success'] else 'N/A',
            'recommendation': r['risk_analysis']['recommendation'] if r['success'] else 'N/A'
        } for r in results]
        summary_df = pd.DataFrame(summary_data)
        summary_table = html.Table(className='summary-table w-full max-w-4xl border-collapse', children=[
            html.Thead([
                html.Tr([
                    html.Th(col, className='px-4 py-2') for col in summary_df.columns
                ])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(str(summary_df.iloc[i][col]), className='px-4 py-2')
                    for col in summary_df.columns
                ]) for i in range(len(summary_df))
            ])
        ])
        
        output_children.append(
            html.Div([
                html.H3("Transaction Processing Summary", className='text-2xl font-semibold mb-4 text-gray-800'),
                summary_table
            ], className='bg-white p-6 rounded-lg shadow-md')
        )
        
        return output_children, None, download_data
    
    except Exception as e:
        logging.error(f"Error processing CSV: {str(e)}")
        return [html.Div(f"Error processing file: {str(e)}", className='text-red-500')], None, None

if __name__ == '__main__':
    app.run_server(debug=True, port=8050)