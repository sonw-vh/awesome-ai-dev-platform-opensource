#!/usr/local/bin/python3.10
# -*- coding: utf-8 -*-
"""
AI Platform Security Module - SVG XSS Protection

Critical vulnerability fix for stored XSS via SVG file uploads.
Provides automatic Django middleware integration and SVG sanitization.
"""

import logging
logger = logging.getLogger(__name__)

from .svg_sanitizer import SVGSanitizer, sanitize_svg, validate_and_sanitize_upload
from .security_middleware import FileUploadSecurityMiddleware, SecurityAuditMiddleware

def initialize_security():
    """Initialize security components. Called automatically during app startup."""
    try:
        # Test core sanitization
        test_svg = b'<svg><script>alert("test")</script></svg>'
        sanitized = validate_and_sanitize_upload(test_svg, "test.svg")
        
        if b'script' not in sanitized:
            logger.info("AI Platform Security: SVG XSS protection active")
            return True
        else:
            logger.error("AI Platform Security: SVG sanitizer test failed!")
            return False
    except Exception as e:
        logger.error(f"AI Platform Security initialization failed: {e}")
        return False

# Auto-configure Django settings if available
try:
    from django.conf import settings
    if hasattr(settings, 'MIDDLEWARE'):
        middleware_list = list(settings.MIDDLEWARE)
        security_middleware = 'security.security_middleware.FileUploadSecurityMiddleware'
        if security_middleware not in middleware_list:
            middleware_list.insert(0, security_middleware)
            settings.MIDDLEWARE = middleware_list
            logger.info("Security middleware auto-configured")
except:
    pass  # Django not available or not configured yet

__version__ = "1.0.0"
__all__ = [
    'SVGSanitizer', 'sanitize_svg', 'validate_and_sanitize_upload',
    'FileUploadSecurityMiddleware', 'SecurityAuditMiddleware', 'initialize_security'
]
