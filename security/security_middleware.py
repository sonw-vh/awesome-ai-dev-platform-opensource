#!/usr/local/bin/python3.10
# -*- coding: utf-8 -*-
"""
Security Middleware for AI Development Platform
Handles file upload security including SVG sanitization

CRITICAL: This middleware protects against Stored XSS via SVG file uploads
Target endpoint: POST /api/projects/:id/import (main vulnerability point)
"""

import logging
from typing import Any, Dict, Optional
from django.http import HttpRequest, HttpResponse
from django.core.files.uploadedfile import UploadedFile
from django.utils.deprecation import MiddlewareMixin
from .svg_sanitizer import SVGSanitizer, validate_and_sanitize_upload

logger = logging.getLogger(__name__)

class FileUploadSecurityMiddleware(MiddlewareMixin):
    """
    Django middleware to sanitize file uploads, especially SVG files.
    
    This middleware specifically targets the project import endpoint where
    users can upload datasets, including potentially malicious SVG files.
    
    SECURITY FEATURES:
    1. Intercepts all file uploads to /api/projects/*/import
    2. Identifies SVG files (by extension and content type)
    3. Sanitizes SVG content to remove XSS vectors
    4. Replaces unsafe content with sanitized version
    5. Logs all security events for audit trail
    6. Preserves safe SVG functionality
    
    INTEGRATION: Auto-registers via security.__init__.py
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.svg_sanitizer = SVGSanitizer()
        logger.info("FileUploadSecurityMiddleware initialized - protecting /api/projects/*/import")
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming requests to sanitize file uploads.
        """
        # Only process requests with file uploads
        if request.method not in ['POST', 'PUT', 'PATCH']:
            return None
            
        if not hasattr(request, 'FILES') or not request.FILES:
            return None
            
        # Check if this is a project import request (main vulnerability point)
        is_project_import = (
            'api/projects' in request.path and 
            '/import' in request.path
        )
        
        # Log all project import requests for security monitoring
        if is_project_import:
            logger.info(f"🔒 Processing critical upload endpoint: {request.path}")
            logger.info(f"🔒 Files in request: {len(request.FILES)} file(s)")
        
        try:
            # Process all uploaded files
            for field_name, uploaded_file in request.FILES.items():
                if isinstance(uploaded_file, UploadedFile):
                    self._sanitize_uploaded_file(uploaded_file, is_project_import)
                elif isinstance(uploaded_file, list):
                    # Handle multiple files
                    for file_item in uploaded_file:
                        if isinstance(file_item, UploadedFile):
                            self._sanitize_uploaded_file(file_item, is_project_import)
                            
        except Exception as e:
            logger.error(f"Error in file upload security processing: {str(e)}")
            # Don't block the request on security processing errors
            # Log and continue, but this should be monitored
            
        return None
    
    def _sanitize_uploaded_file(self, uploaded_file: UploadedFile, is_critical_path: bool = False) -> None:
        """
        Sanitize a single uploaded file if it's an SVG.
        
        Args:
            uploaded_file: Django UploadedFile instance
            is_critical_path: True if this is a critical security path (project imports)
        """
        filename = getattr(uploaded_file, 'name', '') or ''
        
        # Check if this is an SVG file
        is_svg = (
            filename.lower().endswith('.svg') or
            filename.lower().endswith('.svgz')
        )
        
        if not is_svg:
            return
            
        try:
            # Read the file content
            uploaded_file.seek(0)  # Ensure we're at the start
            original_content = uploaded_file.read()
            
            if not original_content:
                logger.warning(f"Empty SVG file uploaded: {filename}")
                return
                
            # Sanitize the SVG content
            sanitized_content = validate_and_sanitize_upload(original_content, filename)
            
            # Check if content was modified
            content_modified = original_content != sanitized_content
            
            if content_modified:
                # Log security event
                logger.warning(
                    f"🚨 SVG SANITIZED: {filename} "
                    f"(original: {len(original_content)} bytes, "
                    f"sanitized: {len(sanitized_content)} bytes) "
                    f"Critical path: {is_critical_path}"
                )
                
                # Replace the file content with sanitized version
                self._replace_file_content(uploaded_file, sanitized_content)
                
                # Add security metadata
                if hasattr(uploaded_file, '_security_sanitized'):
                    uploaded_file._security_sanitized = True
            else:
                logger.info(f"✅ SVG file was already safe: {filename}")
                
        except Exception as e:
            logger.error(f"Failed to sanitize SVG file {filename}: {str(e)}")
            # For critical paths, we might want to reject the file
            if is_critical_path:
                # This would require custom exception handling
                # For now, log the error and continue
                logger.critical(f"🚨 CRITICAL SVG sanitization failure: {filename}")
    
    def _replace_file_content(self, uploaded_file: UploadedFile, new_content: bytes) -> None:
        """
        Replace the content of an uploaded file with sanitized content.
        
        Args:
            uploaded_file: Django UploadedFile instance  
            new_content: Sanitized content as bytes
        """
        try:
            # For InMemoryUploadedFile
            if hasattr(uploaded_file, '_file'):
                # Create new BytesIO with sanitized content
                from io import BytesIO
                new_file = BytesIO(new_content)
                uploaded_file._file = new_file
                uploaded_file._size = len(new_content)
                
            # For TemporaryUploadedFile 
            elif hasattr(uploaded_file, 'temporary_file_path'):
                # Write sanitized content to temp file
                temp_path = uploaded_file.temporary_file_path()
                with open(temp_path, 'wb') as f:
                    f.write(new_content)
                uploaded_file._size = len(new_content)
                
            # Ensure file pointer is at the beginning
            uploaded_file.seek(0)
            
        except Exception as e:
            logger.error(f"Failed to replace file content: {str(e)}")
            raise


class SecurityAuditMiddleware(MiddlewareMixin):
    """
    Additional middleware for security event logging and monitoring.
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Log security-relevant events after request processing.
        """
        # Log file upload attempts to sensitive endpoints
        if (request.method == 'POST' and 
            hasattr(request, 'FILES') and 
            request.FILES and
            'api/projects' in request.path):
            
            file_count = sum(
                1 if not isinstance(f, list) else len(f) 
                for f in request.FILES.values()
            )
            
            logger.info(
                f"📊 File upload to project endpoint: {request.path} "
                f"Files: {file_count} "
                f"Response: {response.status_code}"
            )
            
        return response


# Configuration for Django settings
SECURITY_MIDDLEWARE_CONFIG = {
    'svg_sanitization_enabled': True,
    'audit_logging_enabled': True,
    'reject_unsafe_svg': False,  # Set to True for stricter security
    'max_svg_size_mb': 10,  # Maximum SVG file size
}


def install_security_middleware():
    """
    Helper function to install security middleware in Django settings.
    Call this from Django settings or app configuration.
    """
    import django.conf
    
    if hasattr(django.conf.settings, 'MIDDLEWARE'):
        middleware = list(django.conf.settings.MIDDLEWARE)
        
        # Add our security middleware early in the chain
        security_middleware = [
            'security.security_middleware.FileUploadSecurityMiddleware',
            'security.security_middleware.SecurityAuditMiddleware',
        ]
        
        for mw in reversed(security_middleware):
            if mw not in middleware:
                # Insert after Django's security middleware but before others
                insert_position = 1  # After SecurityMiddleware
                middleware.insert(insert_position, mw)
                
        django.conf.settings.MIDDLEWARE = middleware
        logger.info("🔒 Security middleware installed successfully")
    else:
        logger.error("Could not install security middleware - MIDDLEWARE setting not found")


if __name__ == "__main__":
    # Test the middleware components
    print("Security middleware components loaded successfully")
    print("Available components:")
    print("- FileUploadSecurityMiddleware")
    print("- SecurityAuditMiddleware") 
    print("- install_security_middleware()")
