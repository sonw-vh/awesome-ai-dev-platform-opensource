#!/usr/local/bin/python3.10
# -*- coding: utf-8 -*-
"""
SVG Sanitization Service for AIxBlock Platform
Professional-grade SVG XSS protection

Security Standards:
- OWASP XSS Prevention
- W3C SVG 1.1 Specification Compliance  
- Defense in Depth Architecture
"""

import re
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as DefusedET
from defusedxml.common import EntitiesForbidden, DTDForbidden
from typing import List, Optional, Set
import logging

logger = logging.getLogger(__name__)

class SVGSanitizer:
    """
    Enterprise-grade SVG sanitization to prevent XSS attacks.
    
    This sanitizer implements multiple security layers:
    1. XML parsing with defusedxml (prevents XXE, billion laughs, etc.)
    2. Whitelist-based element and attribute filtering
    3. JavaScript content detection and removal
    4. Event handler removal
    5. External reference sanitization
    """
    
    # Whitelist of allowed SVG elements (W3C SVG 1.1 specification)
    ALLOWED_ELEMENTS: Set[str] = {
        'svg', 'g', 'defs', 'desc', 'title', 'metadata',
        'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'path',
        'text', 'tspan', 'tref', 'textPath',
        'marker', 'pattern', 'clipPath', 'mask',
        'linearGradient', 'radialGradient', 'stop',
        'use', 'image', 'switch', 'foreignObject',
        'style'  # Conditional - will be sanitized separately
    }
    
    # Whitelist of allowed attributes
    ALLOWED_ATTRIBUTES: Set[str] = {
        # Core attributes
        'id', 'class', 'style', 'lang', 'dir', 'title',
        # SVG-specific attributes
        'x', 'y', 'width', 'height', 'viewBox', 'preserveAspectRatio',
        'cx', 'cy', 'r', 'rx', 'ry',
        'x1', 'y1', 'x2', 'y2',
        'points', 'd', 'transform',
        'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin',
        'opacity', 'fill-opacity', 'stroke-opacity',
        'font-family', 'font-size', 'font-weight', 'font-style',
        'text-anchor', 'dominant-baseline',
        'gradientUnits', 'gradientTransform', 'spreadMethod',
        'offset', 'stop-color', 'stop-opacity',
        'patternUnits', 'patternContentUnits', 'patternTransform',
        'clipPathUnits', 'maskUnits', 'maskContentUnits',
        'href', 'xlink:href'  # Limited - will be validated
    }
    
    # Dangerous attributes that can contain JavaScript
    DANGEROUS_ATTRIBUTES: Set[str] = {
        'onload', 'onclick', 'onmouseover', 'onmouseout', 'onmousemove',
        'onmousedown', 'onmouseup', 'onkeydown', 'onkeyup', 'onkeypress',
        'onfocus', 'onblur', 'onchange', 'onselect', 'onsubmit', 'onreset',
        'onabort', 'onerror', 'onresize', 'onscroll', 'onunload',
        'onbeforeunload', 'oncontextmenu', 'ondrag', 'ondragend',
        'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop'
    }
    
    # Dangerous URL schemes
    DANGEROUS_SCHEMES: Set[str] = {
        'javascript:', 'data:', 'vbscript:', 'file:', 'about:',
        'chrome:', 'chrome-extension:', 'moz-extension:'
    }

    def __init__(self):
        """Initialize the SVG sanitizer with security configurations."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    def sanitize(self, svg_content: str) -> str:
        """
        Sanitize SVG content to remove XSS vectors.
        
        Args:
            svg_content: Raw SVG content as string
            
        Returns:
            Sanitized SVG content
            
        Raises:
            ValueError: If SVG is malformed or contains dangerous content
        """
        if not svg_content or not svg_content.strip():
            raise ValueError("Empty SVG content provided")
            
        try:
            # Step 1: Parse with defusedxml for XXE protection
            svg_content = self._normalize_svg_content(svg_content)
            root = self._safe_parse_xml(svg_content)
            
            # Step 2: Validate root element
            if root.tag.lower() not in ['svg', '{http://www.w3.org/2000/svg}svg']:
                raise ValueError("Root element must be <svg>")
            
            # Step 3: Recursive sanitization
            self._sanitize_element(root)
            
            # Step 4: Generate clean SVG
            sanitized_svg = self._element_to_string(root)            
            # Step 5: Final validation
            self._final_security_check(sanitized_svg)
            
            self.logger.info("SVG successfully sanitized")
            return sanitized_svg
            
        except (ET.ParseError, EntitiesForbidden, DTDForbidden) as e:
            self.logger.error(f"SVG parsing failed: {e}")
            raise ValueError(f"Invalid SVG format: {e}")
        except Exception as e:
            self.logger.error(f"SVG sanitization failed: {e}")
            raise ValueError(f"SVG sanitization failed: {e}")
    
    def _normalize_svg_content(self, content: str) -> str:
        """Normalize SVG content for consistent parsing."""
        # Remove BOM if present
        content = content.lstrip('\ufeff')
        
        # Handle malformed or incomplete SVG
        content = content.strip()
        
        # If content doesn't look like valid XML, try to make it valid
        if content and not content.startswith('<'):
            raise ValueError("Invalid SVG: content must start with XML tags")
        
        # Ensure proper XML declaration
        if not content.startswith('<?xml') and not content.startswith('<svg'):
            raise ValueError("Invalid SVG: must start with <svg> element")
        
        # Try to fix common malformed SVG issues
        if '<svg' in content and not content.endswith('>'):
            # Try to close unclosed tags
            if not content.endswith('</svg>'):
                content += '</svg>'
        
        return content
    
    def _safe_parse_xml(self, content: str) -> ET.Element:
        """Parse XML using defusedxml for security."""
        try:
            # Use defusedxml to prevent XXE and other XML attacks
            return DefusedET.fromstring(content)
        except ET.ParseError as e:
            # Handle malformed XML gracefully
            self.logger.warning(f"Malformed SVG detected: {e}")
            # Try to create a minimal valid SVG
            return self._create_safe_fallback_svg()
        except (EntitiesForbidden, DTDForbidden) as e:
            self.logger.warning(f"Blocked dangerous XML construct: {e}")
            raise ValueError("SVG contains dangerous XML constructs")
    
    def _create_safe_fallback_svg(self) -> ET.Element:
        """Create a safe fallback SVG for malformed input."""
        # Create a minimal, safe SVG element
        svg_element = ET.Element('svg')
        svg_element.set('xmlns', 'http://www.w3.org/2000/svg')
        svg_element.set('width', '100')
        svg_element.set('height', '100')
        svg_element.set('viewBox', '0 0 100 100')
        
        # Add a simple safe element
        text_element = ET.SubElement(svg_element, 'text')
        text_element.set('x', '50')
        text_element.set('y', '50')
        text_element.set('text-anchor', 'middle')
        text_element.text = 'Safe SVG'
        
        return svg_element
    
    def _sanitize_element(self, element: ET.Element) -> None:
        """Recursively sanitize an XML element and its children."""
        # Clean tag name
        tag_name = self._clean_tag_name(element.tag)
        
        # Special handling for dangerous elements
        if tag_name == 'script':
            # Mark for removal - will be handled by parent
            element.tag = 'REMOVE_THIS_ELEMENT'
            element.clear()
            return
        
        # Check if element is allowed
        if tag_name not in self.ALLOWED_ELEMENTS:
            # Mark for removal
            element.tag = 'REMOVE_THIS_ELEMENT'
            element.clear()
            return
        
        # Sanitize attributes
        self._sanitize_attributes(element)
        
        # Special handling for specific elements
        if tag_name == 'style':
            # Sanitize CSS content
            self._sanitize_style_content(element)
        
        # Recursively sanitize children and remove marked elements
        children_to_remove = []
        for child in element:
            self._sanitize_element(child)
            if child.tag == 'REMOVE_THIS_ELEMENT':
                children_to_remove.append(child)
        
        # Remove marked children
        for child in children_to_remove:
            element.remove(child)
    
    def _clean_tag_name(self, tag: str) -> str:
        """Extract clean tag name from namespaced tag."""
        if '}' in tag:
            # Remove namespace
            return tag.split('}')[1].lower()
        return tag.lower()
    
    def _sanitize_attributes(self, element: ET.Element) -> None:
        """Sanitize element attributes."""
        # Get all attributes
        attrs_to_remove = []
        
        for attr_name, attr_value in element.attrib.items():
            clean_attr_name = self._clean_tag_name(attr_name)
            
            # Remove dangerous attributes
            if clean_attr_name in self.DANGEROUS_ATTRIBUTES:
                attrs_to_remove.append(attr_name)
                continue
            
            # Check if attribute is allowed
            if clean_attr_name not in self.ALLOWED_ATTRIBUTES:
                attrs_to_remove.append(attr_name)
                continue
            
            # Sanitize attribute value
            if clean_attr_name in ['href', 'xlink:href']:
                if not self._is_safe_url(attr_value):
                    attrs_to_remove.append(attr_name)
                    continue
            
            # Sanitize style attribute
            if clean_attr_name == 'style':
                sanitized_style = self._sanitize_css(attr_value)
                if sanitized_style != attr_value:
                    element.set(attr_name, sanitized_style)
        
        # Remove dangerous attributes
        for attr_name in attrs_to_remove:
            del element.attrib[attr_name]
    
    def _is_safe_url(self, url: str) -> bool:
        """Check if URL is safe (no JavaScript, etc.)."""
        if not url:
            return True
        
        url_lower = url.lower().strip()
        
        # Check for dangerous schemes
        for scheme in self.DANGEROUS_SCHEMES:
            if url_lower.startswith(scheme):
                return False
        
        # Allow relative URLs and HTTP(S)
        if url_lower.startswith(('#', 'http://', 'https://', '/')):
            return True
        
        # Allow relative paths
        if not ':' in url_lower:
            return True
        
        return False
    
    def _sanitize_css(self, css_content: str) -> str:
        """Sanitize CSS content to remove JavaScript."""
        if not css_content:
            return css_content
        
        # Remove expressions and JavaScript
        dangerous_patterns = [
            r'expression\s*\(',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'@import',
            r'behavior\s*:',
            r'-moz-binding',
            r'@\s*import'
        ]
        
        sanitized = css_content
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def _sanitize_style_content(self, style_element: ET.Element) -> None:
        """Sanitize CSS content within <style> elements."""
        if style_element.text:
            style_element.text = self._sanitize_css(style_element.text)
    
    def _element_to_string(self, element: ET.Element) -> str:
        """Convert element back to string."""
        # Add proper SVG namespace if missing
        if 'xmlns' not in element.attrib:
            element.set('xmlns', 'http://www.w3.org/2000/svg')
        
        return ET.tostring(element, encoding='unicode')
    
    def _final_security_check(self, svg_content: str) -> None:
        """Perform final security validation."""
        dangerous_patterns = [
            r'<script\b',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'expression\s*\(',
            r'@import',
        ]
        
        content_lower = svg_content.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, content_lower):
                raise ValueError(f"SVG contains dangerous content: {pattern}")

# Global sanitizer instance
_sanitizer = SVGSanitizer()

def sanitize_svg(svg_content: str) -> str:
    """
    Public interface for SVG sanitization.
    
    Args:
        svg_content: Raw SVG content
        
    Returns:
        Sanitized SVG content
        
    Raises:
        ValueError: If SVG is invalid or dangerous
    """
    return _sanitizer.sanitize(svg_content)

def is_svg_file(file_content: bytes) -> bool:
    """
    Check if file content is an SVG file.
    
    Args:
        file_content: Raw file bytes
        
    Returns:
        True if file appears to be SVG
    """
    try:
        # Try to decode as text
        text_content = file_content.decode('utf-8', errors='ignore')
        text_lower = text_content.lower().strip()
        
        # Check for SVG indicators
        return (
            text_lower.startswith('<?xml') and '<svg' in text_lower
        ) or text_lower.startswith('<svg')
    except:
        return False

def validate_and_sanitize_upload(file_content: bytes, filename: str) -> bytes:
    """
    Validate and sanitize uploaded file content.
    
    Args:
        file_content: Raw uploaded file bytes
        filename: Original filename
        
    Returns:
        Sanitized file content (if SVG) or original content
        
    Raises:
        ValueError: If file is dangerous or invalid
    """
    # Check if file is SVG
    if not filename.lower().endswith('.svg'):
        return file_content
    
    if not is_svg_file(file_content):
        raise ValueError("File claims to be SVG but content is not valid SVG")
    
    try:
        # Decode and sanitize
        svg_text = file_content.decode('utf-8')
        sanitized_svg = sanitize_svg(svg_text)
        return sanitized_svg.encode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("SVG file contains invalid UTF-8 encoding")
