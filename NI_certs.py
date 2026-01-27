import ssl
import socket

# Monkey patch for Python 3.12+ compatibility
if not hasattr(ssl, 'wrap_socket'):
    def wrap_socket(sock, keyfile=None, certfile=None, server_side=False,
                    cert_reqs=ssl.CERT_NONE, ssl_version=None,
                    ca_certs=None, do_handshake_on_connect=True,
                    suppress_ragged_eofs=True, ciphers=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if not server_side else ssl.PROTOCOL_TLS_SERVER)
        context.check_hostname = False
        context.verify_mode = cert_reqs
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        if ca_certs:
            context.load_verify_locations(ca_certs)
        if ciphers:
            context.set_ciphers(ciphers)
        return context.wrap_socket(sock, server_side=server_side,
                                    do_handshake_on_connect=do_handshake_on_connect,
                                    suppress_ragged_eofs=suppress_ragged_eofs)
    ssl.wrap_socket = wrap_socket

import pymumble_py3 as pymumble
from pymumble_py3.callbacks import PYMUMBLE_CLBK_USERCREATED, PYMUMBLE_CLBK_USERUPDATED, PYMUMBLE_CLBK_USERREMOVED
import time
import logging
import os
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Mumble server configuration
SERVER = "voice.wintercoalition.space"  # Change this to your server address
SERVER = "192.168.129.51"  # Change this to your server address
# SERVER = "voice.insidiousevil.space"  # Change this to your server address
PORT = 64738  # Default Mumble port
#USERNAME = "SW81SYs4SA"  # Change this to your desired username
#PASSWORD = "2hYF8cxemsqqjBE"  # Change this if your server requires a password

USERNAME = "superuser"  # Change this to your desired username
# PASSWORD = "EVILiSfuN!"  # Change this if your server requires a password

PASSWORD = "michael"  # Change this if your server requires a password
USERNAME = "michael"  # Change this to your desired username
USERNAME = "monitor"  # Change this to your desired username
PASSWORD = ""  # Change this if your server requires a password

# PASSWORD = ""  # Change this if your server requires a password

# Certificate files
CERT_FILE = "ni_cert.pem"
KEY_FILE = "ni_key.pem"

# CERT_FILE = "/tmp/monitor_private.pem"
# KEY_FILE = "/tmp/monitor_public.pem"
# CERT_FILE = "/tmp/monitor_public.pem"
# KEY_FILE = "/tmp/monitor_private.pem"
OUTPUT_FILE = "ni_data.json"

# Dictionary to store certificate hash -> list of usernames
cert_to_users = {}
user_certs = {}  # Keep for tracking user_id -> info


def on_user_created(user):
    """Callback when a new user joins the server"""
    cert_hash = user.get('hash', 'No certificate')
    cert_objf = cert_hash[:5] + cert_hash[-5:]
    mumble_name = user.get('name', 'Unknown')
    noise, sep, name = mumble_name.partition('[')
    user_name = sep + name if sep else mumble_name
    user_id = user.get('session', 'Unknown ID')
    
    user_certs[user_id] = {
        'name': user_name,
        'cert_hash': cert_hash,
        'cert_objf': cert_objf
    }
    
    # Add to cert_to_users mapping
    if cert_hash not in cert_to_users:
        cert_to_users[cert_hash] = []
    if user_name not in cert_to_users[cert_hash]:
        cert_to_users[cert_hash].append(user_name)
        cert_to_users[cert_hash].append(cert_objf)
    
    save_to_json()
    
    logger.info(f"User joined: {user_name} (SESSION: {user_id}, {cert_objf})")
    logger.info(f"Certificate Hash: {cert_hash}")


def on_user_updated(user, pos_arguments):
    """Callback when a user's information is updated"""
    cert_hash = user.get('hash', 'No certificate')
    cert_objf = cert_hash[:5] + cert_hash[-5:]
    user_name = user.get('name', 'Unknown')
    mumble_name = user.get('name', 'Unknown')
    noise, sep, name = mumble_name.partition('[')
    user_name = sep + name if sep else mumble_name
    user_id = user.get('session', 'Unknown ID')
    
    if user_id not in user_certs or user_certs[user_id]['cert_hash'] != cert_hash:
        user_certs[user_id] = {
            'name': user_name,
            'cert_hash': cert_hash,
            'cert_obfu': ('cert_objf', cert_hash)
        }
        
        # Add to cert_to_users mapping
        if cert_hash not in cert_to_users:
            cert_to_users[cert_hash] = []
        if user_name not in cert_to_users[cert_hash]:
            cert_to_users[cert_hash].append(user_name)
            cert_to_users[cert_hash].append(cert_objf)
        
        save_to_json()
        
        logger.info(f"User updated: {user_name} (SESSION: {user_id}, {cert_objf})")
        logger.info(f"Certificate Hash: {cert_hash}")

def on_user_removed(user, pos_arguments):
    """Callback when a user's information is updated"""
    cert_hash = user.get('hash', 'No certificate')
    cert_objf = cert_hash[:5] + cert_hash[-5:]
    user_name = user.get('name', 'Unknown')
    mumble_name = user.get('name', 'Unknown')
    noise, sep, name = mumble_name.partition('[')
    user_name = sep + name if sep else mumble_name
    user_id = user.get('session', 'Unknown ID')
    
    if user_id in user_certs:
        user_certs.pop(user_id)
        
        # Add to cert_to_users mapping
        if cert_hash in cert_to_users:
            cert_to_users.pop(cert_hash)
        save_to_json()
        
        logger.info(f"User left: {user_name} (SESSION: {user_id}, {cert_objf})")
        logger.info(f"Certificate Hash: {cert_hash}")

def collect_existing_users(mumble):
    """Collect certificate hashes from users already on the server"""
    logger.info("Adding missing certificates from online users...")
    
    for user_id, user in mumble.users.items():
        cert_hash = user.get('hash', 'No certificate')
        cert_objf = cert_hash[:5] + cert_hash[-5:]
        # user_name = user.get('name', 'Unknown')
        mumble_name = user.get('name', 'Unknown')
        noise, sep, name = mumble_name.partition('[')
        user_name = sep + name if sep else mumble_name
        
        if user_id not in user_certs or user_certs[user_id]['cert_hash'] != cert_hash:
            user_certs[user_id] = {
                'name': user_name,
                'cert_hash': cert_hash,
                'cert_obfu': ('cert_objf', cert_hash)
            }
        
            # Add to cert_to_users mapping
            if cert_hash not in cert_to_users:
                cert_to_users[cert_hash] = []
            if user_name not in cert_to_users[cert_hash]:
                cert_to_users[cert_hash].append(user_name)
                cert_to_users[cert_hash].append(cert_objf)
        
            logger.info(f"User collected: {user_name} (SESSION: {user_id}, {cert_objf})")
            logger.info(f"Certificate Hash: {cert_hash}")
    
    logger.info(f"\nTotal users found: {len(user_certs)}")
    save_to_json()


def save_to_json():
    """Save certificate data to JSON file"""
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(cert_to_users, f, indent=2)
    logger.debug(f"Data saved to {OUTPUT_FILE}")


from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os
import logging

logger = logging.getLogger(__name__)

def generate_certificate():
    """Generate a self-signed certificate for Mumble authentication"""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        logger.info("Using existing certificate files")
        return

    logger.info("Generating new certificate...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, USERNAME),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))

        #  THIS IS THE CRITICAL FIX
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )

        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    with open(KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Certificate generated: {CERT_FILE}, {KEY_FILE}")

def main():
    # Generate or load certificate
    generate_certificate()
    
    # Create Mumble client instance
    logger.info(f"Connecting to {SERVER}:{PORT} as {USERNAME}...")
    
    mumble = pymumble.Mumble(SERVER, user=USERNAME, port=PORT, password=PASSWORD,
                             certfile=CERT_FILE, keyfile=KEY_FILE, debug=False)
    
    # Register callbacks
    mumble.callbacks.set_callback(PYMUMBLE_CLBK_USERCREATED, on_user_created)
    mumble.callbacks.set_callback(PYMUMBLE_CLBK_USERUPDATED, on_user_updated)
    mumble.callbacks.set_callback(PYMUMBLE_CLBK_USERREMOVED, on_user_removed)
    
    # Connect to server
    mumble.start()
    mumble.is_ready()  # Wait for connection to be established
    
    logger.info("Connected to Mumble server!")
    
    # Collect certificates from existing users
    time.sleep(2)  # Give time for user list to populate
    collect_existing_users(mumble)
    
    logger.info("\nNow monitoring user connections... (Press Ctrl+C to exit)")
    
    # Keep the script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        logger.info(f"Total unique users encountered: {len(user_certs)}")
        logger.info(f"Total unique certificates: {len(cert_to_users)}")
        
        # Save final data
        save_to_json()
        
        # Print summary
        logger.info("\n=== Certificate Summary ===")
        for cert_hash, usernames in cert_to_users.items():
            logger.info(f"Certificate {cert_hash}:")
            for username in usernames:
                logger.info(f"  - {username}")
        
        logger.info(f"\nData saved to {OUTPUT_FILE}")
        mumble.stop()


if __name__ == "__main__":
    main()
