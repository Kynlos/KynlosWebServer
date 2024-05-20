import os
import logging
import datetime
import threading
from OpenSSL import crypto

def generate_self_signed_cert(certfile, keyfile, cert_config):
    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        logging.info("Generating self-signed certificate and key...")

        # Create a key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, cert_config.get('key_size', 2048))

        # Create a self-signed cert
        cert = crypto.X509()
        subject = cert.get_subject()
        for key, value in cert_config.get('subject', {}).items():
            setattr(subject, key, value)
        cert.set_serial_number(cert_config.get('serial_number', 1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(cert_config.get('valid_days', 3650) * 24 * 60 * 60)
        cert.set_issuer(subject)
        cert.set_pubkey(key)
        cert.sign(key, cert_config.get('signing_algorithm', 'sha256'))

        with open(certfile, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(keyfile, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        logging.info("Self-signed certificate and key generated.")

def check_cert_expiry(certfile, keyfile, cert_config, cert_renewal_days):
    """Checks if the certificate is about to expire and renews it if necessary."""
    if os.path.exists(certfile):
        with open(certfile, 'rb') as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        expiry_time = datetime.datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
        time_remaining = expiry_time - datetime.datetime.utcnow()
        if time_remaining.days <= cert_renewal_days:
            logging.warning("Certificate is expiring soon. Renewing certificate...")
            generate_self_signed_cert(certfile, keyfile, cert_config)
            logging.info("Certificate renewed successfully.")

def start_cert_renewal_timer(certfile, keyfile, cert_config, cert_renewal_days):
    timer = threading.Timer(3600 * 24, check_cert_expiry, args=(certfile, keyfile, cert_config, cert_renewal_days))
    timer.start()
    return timer
