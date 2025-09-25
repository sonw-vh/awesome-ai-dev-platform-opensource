import DOMPurify from 'dompurify';

/**
 * XSS Protection Utility
 * 
 * This utility provides safe HTML sanitization to prevent XSS attacks
 * by using DOMPurify to clean user input before rendering.
 */

// Configure DOMPurify with strict settings for maximum security
const sanitizeConfig = {
  // Only allow safe HTML tags
  ALLOWED_TAGS: [
    'p', 'br', 'strong', 'em', 'u', 'b', 'i', 'span', 'div',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
    'a', 'img'
  ],
  
  // Only allow safe attributes
  ALLOWED_ATTR: [
    'href', 'title', 'alt', 'src', 'class', 'id', 'style',
    'target', 'rel'
  ],
  
  // Remove dangerous attributes
  FORBID_ATTR: [
    'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur',
    'onchange', 'onsubmit', 'onreset', 'onselect', 'onkeydown', 'onkeyup',
    'onkeypress', 'onmousedown', 'onmouseup', 'onmousemove', 'onmouseout',
    'oncontextmenu', 'ondblclick', 'onabort', 'onbeforeunload', 'onerror',
    'onhashchange', 'onload', 'onpageshow', 'onpagehide', 'onresize',
    'onscroll', 'onunload', 'onbeforeprint', 'onafterprint'
  ],
  
  // Remove dangerous tags completely
  FORBID_TAGS: [
    'script', 'object', 'embed', 'applet', 'form', 'input', 'textarea',
    'select', 'option', 'button', 'iframe', 'frame', 'frameset',
    'link', 'meta', 'style', 'base', 'svg', 'math'
  ],
  
  // Additional security measures
  ALLOW_DATA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  SANITIZE_DOM: true,
  KEEP_CONTENT: true,
  RETURN_DOM: false,
  RETURN_DOM_FRAGMENT: false,
  RETURN_DOM_IMPORT: false
};

/**
 * Sanitizes HTML content to prevent XSS attacks
 * @param dirtyHtml - The potentially unsafe HTML string
 * @returns Sanitized HTML string safe for rendering
 */
export const sanitizeHtml = (dirtyHtml: string): string => {
  if (!dirtyHtml || typeof dirtyHtml !== 'string') {
    return '';
  }

  try {
    // Use DOMPurify to sanitize the HTML
    const cleanHtml = DOMPurify.sanitize(dirtyHtml, sanitizeConfig);
    return cleanHtml;
  } catch (error) {
    console.error('Error sanitizing HTML:', error);
    // Return empty string if sanitization fails
    return '';
  }
};

/**
 * Sanitizes HTML content and returns a safe HTML object for dangerouslySetInnerHTML
 * @param dirtyHtml - The potentially unsafe HTML string
 * @returns Object with __html property containing sanitized HTML
 */
export const createSafeHtml = (dirtyHtml: string): { __html: string } => {
  return {
    __html: sanitizeHtml(dirtyHtml)
  };
};

/**
 * Strips all HTML tags and returns plain text
 * @param htmlString - The HTML string to strip
 * @returns Plain text without HTML tags
 */
export const stripHtml = (htmlString: string): string => {
  if (!htmlString || typeof htmlString !== 'string') {
    return '';
  }

  try {
    // First sanitize to remove dangerous content
    const sanitized = sanitizeHtml(htmlString);
    // Then strip all remaining HTML tags
    return sanitized.replace(/<[^>]*>/g, '');
  } catch (error) {
    console.error('Error stripping HTML:', error);
    return '';
  }
};

/**
 * Validates if a string contains potentially dangerous content
 * @param input - The string to validate
 * @returns true if the string appears safe, false if potentially dangerous
 */
export const isSafeContent = (input: string): boolean => {
  if (!input || typeof input !== 'string') {
    return true;
  }

  // Check for common XSS patterns
  const dangerousPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /<object[^>]*>.*?<\/object>/gi,
    /<embed[^>]*>.*?<\/embed>/gi,
    /<applet[^>]*>.*?<\/applet>/gi,
    /<form[^>]*>.*?<\/form>/gi,
    /<input[^>]*>/gi,
    /<textarea[^>]*>.*?<\/textarea>/gi,
    /<select[^>]*>.*?<\/select>/gi,
    /<button[^>]*>.*?<\/button>/gi,
    /<link[^>]*>/gi,
    /<meta[^>]*>/gi,
    /<style[^>]*>.*?<\/style>/gi,
    /<base[^>]*>/gi,
    /<svg[^>]*>.*?<\/svg>/gi,
    /<math[^>]*>.*?<\/math>/gi,
    /on\w+\s*=/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /data:text\/html/gi,
    /data:application\/javascript/gi
  ];

  return !dangerousPatterns.some(pattern => pattern.test(input));
};

/**
 * React component for safely rendering HTML content
 * @param props - Component props
 * @returns JSX element with sanitized HTML
 */
export const SafeHtmlRenderer: React.FC<{ 
  html: string; 
  className?: string; 
  tag?: keyof JSX.IntrinsicElements;
}> = ({ html, className, tag: Tag = 'div' }) => {
  const safeHtml = createSafeHtml(html);
  
  return (
    <Tag 
      className={className}
      dangerouslySetInnerHTML={safeHtml}
    />
  );
};

export default {
  sanitizeHtml,
  createSafeHtml,
  stripHtml,
  isSafeContent,
  SafeHtmlRenderer
};
