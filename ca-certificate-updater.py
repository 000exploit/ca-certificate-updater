#!/usr/bin/env python3
"""
Root CA Certificate Updater

This script updates a provided root CA certificate by retrieving the latest
version from the issuing CA based on certificate DN information.
"""

import argparse
import logging
import os
import sys
import tempfile
import pytz
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ca_updater")


@dataclass
class CertificateInfo:
    """Data class to store certificate information."""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: int
    not_valid_before: datetime
    not_valid_after: datetime
    extensions: Dict[str, any]
    fingerprint_sha256: str
    raw_cert: x509.Certificate


class CertificateParser:
    """Responsible for parsing certificate files and extracting metadata."""

    def __init__(self):
        self.backend = default_backend()

    def parse_certificate_file(self, cert_path: str) -> CertificateInfo:
        """
        Parse a certificate file and return its information.
        
        Args:
            cert_path: Path to the certificate file
            
        Returns:
            CertificateInfo: Object containing certificate details
            
        Raises:
            FileNotFoundError: If certificate file doesn't exist
            ValueError: If certificate format is invalid
        """
        try:
            with open(cert_path, "rb") as cert_file:
                cert_data = cert_file.read()
                
            return self.parse_certificate_data(cert_data)
        except FileNotFoundError:
            logger.error(f"Certificate file not found: {cert_path}")
            raise
        except ValueError as e:
            logger.error(f"Invalid certificate format: {e}")
            raise
            
    def parse_certificate_data(self, cert_data: bytes) -> CertificateInfo:
        """
        Parse certificate data and return its information.
        
        Args:
            cert_data: Raw certificate data
            
        Returns:
            CertificateInfo: Object containing certificate details
            
        Raises:
            ValueError: If certificate format is invalid
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_data, self.backend)
        except ValueError:
            try:
                cert = x509.load_der_x509_certificate(cert_data, self.backend)
            except ValueError as e:
                logger.error("Certificate is neither in PEM nor DER format")
                raise ValueError("Invalid certificate format") from e
                
        # Extract subject and issuer
        subject = self._extract_name_attributes(cert.subject)
        issuer = self._extract_name_attributes(cert.issuer)
        
        # Extract extensions
        extensions = self._extract_extensions(cert)
        
        # Calculate fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        
        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=cert.serial_number,
            not_valid_before=cert.not_valid_before_utc,
            not_valid_after=cert.not_valid_after_utc,
            extensions=extensions,
            fingerprint_sha256=fingerprint,
            raw_cert=cert
        )
    
    def _extract_name_attributes(self, name: x509.Name) -> Dict[str, str]:
        """Extract attributes from a certificate name."""
        attributes = {}
        
        for attr in name:
            oid_name = attr.oid._name
            value = attr.value
            attributes[oid_name] = value
            
        return attributes
    
    def _extract_extensions(self, cert: x509.Certificate) -> Dict[str, any]:
        """Extract extensions from a certificate."""
        extensions = {}
        
        for ext in cert.extensions:
            ext_name = ext.oid._name
            extensions[ext_name] = ext.value
            
        return extensions


class CAInfoExtractor:
    """Extracts CA update information from certificate metadata."""
    
    # Custom OID for CA update URL (this is an example, using a private OID arc)
    CA_UPDATE_URL_OID = ExtensionOID.CRL_DISTRIBUTION_POINTS
    
    def extract_ca_update_info(self, cert_info: CertificateInfo) -> Optional[str]:
        """
        Extract CA update URL from certificate information.
        
        Args:
            cert_info: Certificate information
            
        Returns:
            Optional[str]: URL to fetch updated certificate or None if not found
        """
        # Strategy 1: Check for our custom X.509 extension
        update_url = self._extract_from_custom_extension(cert_info)
        if update_url:
            logger.info(f"Found CA update URL in custom extension: {update_url}")
            return update_url
            
        # Strategy 2: Try common well-known CA patterns
        update_url = self._extract_from_well_known_patterns(cert_info)
        if update_url:
            logger.info(f"Using well-known CA update URL pattern: {update_url}")
            return update_url
            
        # Strategy 3: Try to build URL from OU
        update_url = self._extract_from_ou(cert_info)
        if update_url:
            logger.info(f"Constructed CA update URL from OU: {update_url}")
            return update_url
            
        logger.warning("Could not determine CA update URL")
        return None
        
    def _extract_from_custom_extension(self, cert_info: CertificateInfo) -> Optional[str]:
        """Extract CA update URL from custom X.509 extension."""
        if self.CA_UPDATE_URL_OID._name in cert_info.extensions:
            # Here we should parse the actual extension value
            # For demonstration, we'll use CRL distribution points as an example
            crl_dp = cert_info.extensions.get(self.CA_UPDATE_URL_OID._name)
            if crl_dp and hasattr(crl_dp, "full_name") and crl_dp.full_name:
                for name in crl_dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        url = name.value
                        # Convert CRL URL to certificate URL (example transformation)
                        return url.replace("crl", "cert").replace(".crl", ".crt")
        return None
        
    def _extract_from_ou(self, cert_info: CertificateInfo) -> Optional[str]:
        """Extract CA update URL from OU field."""
        if "organizationalUnitName" in cert_info.issuer:
            ou = cert_info.issuer["organizationalUnitName"]
            if ou.startswith("www."):
                cn = cert_info.issuer.get("commonName", "")
                # Remove spaces and create a plausible URL
                cn_clean = cn.replace(" ", "").lower()
                return f"https://{ou}/certificates/{cn_clean}.crt"
        return None
        
    def _extract_from_well_known_patterns(self, cert_info: CertificateInfo) -> Optional[str]:
        """Extract CA update URL based on well-known CA patterns."""
        # Example for DigiCert
        org_name = cert_info.issuer.get("organizationName", "")
        if "DigiCert" in org_name:
            domain = "digicert.com"
            o = "DigiCert"
            return f"https://cacerts.{domain}/{o}RSA4096RootG5.crt.pem"
            
        # Add more well-known CAs as needed
        return None


class CertificateFetcher(ABC):
    """Abstract base class for certificate fetchers."""
    
    @abstractmethod
    def fetch_certificate(self, url: str) -> bytes:
        """
        Fetch certificate from a URL.
        
        Args:
            url: URL to fetch certificate from
            
        Returns:
            bytes: Raw certificate data
            
        Raises:
            ValueError: If certificate cannot be fetched
        """
        pass


class HTTPCertificateFetcher(CertificateFetcher):
    """Fetches certificates over HTTP/HTTPS."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        
    def fetch_certificate(self, url: str) -> bytes:
        """
        Fetch certificate from HTTP/HTTPS URL.
        
        Args:
            url: URL to fetch certificate from
            
        Returns:
            bytes: Raw certificate data
            
        Raises:
            ValueError: If certificate cannot be fetched
        """
        try:
            # Validate URL
            parsed_url = urlparse(url)
            if parsed_url.scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme}")
                
            logger.info(f"Fetching certificate from {url}")
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                raise ValueError(f"HTTP error {response.status_code}: {response.reason}")
                
            return response.content
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch certificate: {e}")
            raise ValueError(f"Failed to fetch certificate: {e}") from e


class CertificateVerifier:
    """Verifies if two certificates match and if new cert is valid."""
    
    def verify_certificates(self, old_cert: CertificateInfo, new_cert: CertificateInfo) -> Tuple[bool, str]:
        """
        Verify that new certificate is valid and matches the old one.
        
        Args:
            old_cert: Original certificate information
            new_cert: New certificate information
            
        Returns:
            Tuple[bool, str]: (is_valid, reason)
        """
        # Check if new certificate is expired
        now = datetime.now(pytz.UTC)
        if new_cert.not_valid_after <= now:
            return False, "New certificate is already expired"
            
        # Check if new certificate is newer than old one
        if new_cert.not_valid_after <= old_cert.not_valid_after:
            return False, "New certificate is not newer than the old one"
            
        # Check if issuer matches
        if new_cert.issuer != old_cert.issuer:
            return False, "Issuer does not match"
            
        # Check if subject matches
        if new_cert.subject != old_cert.subject:
            return False, "Subject does not match"
            
        # Additional checks as needed
        return True, "Verification successful"


class CertificateWriter:
    """Responsible for writing certificate to disk."""
    
    def write_certificate(self, cert_data: bytes, output_path: str) -> bool:
        """
        Write certificate data to file.
        
        Args:
            cert_data: Raw certificate data
            output_path: Path to write certificate to
            
        Returns:
            bool: True if successful
            
        Raises:
            IOError: If certificate cannot be written
        """
        # Create a temporary file first to avoid corrupting the original
        # if something goes wrong during writing
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
                temp_file.write(cert_data)
                
            # If we get here, the write was successful, so move the temp file
            # to the target location (atomic operation)
            os.replace(temp_path, output_path)
            logger.info(f"Certificate successfully written to {output_path}")
            return True
            
        except IOError as e:
            logger.error(f"Failed to write certificate: {e}")
            # Clean up temp file if it exists
            if 'temp_path' in locals():
                try:
                    os.unlink(temp_path)
                except:
                    pass
            raise
            
        return False


class CACertificateUpdater:
    """Main class coordinating the certificate update process."""
    
    def __init__(self):
        self.parser = CertificateParser()
        self.extractor = CAInfoExtractor()
        self.fetcher = HTTPCertificateFetcher()
        self.verifier = CertificateVerifier()
        self.writer = CertificateWriter()
        
    def update_certificate(self, cert_path: str) -> bool:
        """
        Update a CA certificate.
        
        Args:
            cert_path: Path to certificate file
            
        Returns:
            bool: True if certificate was updated successfully
        """
        try:
            # Step 1: Parse the certificate
            logger.info(f"Parsing certificate: {cert_path}")
            old_cert_info = self.parser.parse_certificate_file(cert_path)
            
            # Step 2: Extract information about the CA
            update_url = self.extractor.extract_ca_update_info(old_cert_info)
            if not update_url:
                logger.error("Could not determine CA update URL")
                return False
                
            # Step 3: Fetch the updated certificate
            new_cert_data = self.fetcher.fetch_certificate(update_url)
            new_cert_info = self.parser.parse_certificate_data(new_cert_data)
            
            # Step 4: Verify the new certificate
            is_valid, reason = self.verifier.verify_certificates(old_cert_info, new_cert_info)
            if not is_valid:
                logger.error(f"Certificate verification failed: {reason}")
                return False
                
            # Step 5: Write the new certificate
            self.writer.write_certificate(new_cert_data, cert_path)
            
            logger.info("Certificate updated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Certificate update failed: {e}")
            return False


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Update a root CA certificate.")
    parser.add_argument(
        "--cert", 
        required=True, 
        help="Path to the certificate file to update"
    )
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable verbose logging"
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    updater = CACertificateUpdater()
    success = updater.update_certificate(args.cert)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
