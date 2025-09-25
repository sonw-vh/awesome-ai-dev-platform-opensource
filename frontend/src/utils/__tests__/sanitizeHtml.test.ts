import { sanitizeHtml, createSafeHtml, stripHtml, isSafeContent } from '../sanitizeHtml';

describe('XSS Sanitization Tests', () => {
  describe('sanitizeHtml', () => {
    test('should remove script tags', () => {
      const malicious = '<script>alert("XSS")</script><p>Safe content</p>';
      const result = sanitizeHtml(malicious);
      expect(result).toBe('<p>Safe content</p>');
      expect(result).not.toContain('<script>');
    });

    test('should remove SVG-based XSS', () => {
      const malicious = '<svg onload=alert("XSS")><text>Safe</text></svg>';
      const result = sanitizeHtml(malicious);
      expect(result).not.toContain('onload');
      expect(result).not.toContain('alert');
    });

    test('should remove event handlers', () => {
      const malicious = '<img src=x onerror=alert("XSS")>';
      const result = sanitizeHtml(malicious);
      expect(result).not.toContain('onerror');
      expect(result).not.toContain('alert');
    });

    test('should preserve safe HTML', () => {
      const safe = '<p>This is <strong>bold</strong> and <em>italic</em> text.</p>';
      const result = sanitizeHtml(safe);
      expect(result).toBe(safe);
    });
  });

  describe('createSafeHtml', () => {
    test('should return safe HTML object', () => {
      const malicious = '<script>alert("XSS")</script><p>Safe</p>';
      const result = createSafeHtml(malicious);
      expect(result.__html).toBe('<p>Safe</p>');
    });
  });

  describe('isSafeContent', () => {
    test('should detect dangerous content', () => {
      expect(isSafeContent('<script>alert("XSS")</script>')).toBe(false);
      expect(isSafeContent('<svg onload=alert("XSS")>')).toBe(false);
      expect(isSafeContent('<img onerror=alert("XSS")>')).toBe(false);
    });

    test('should allow safe content', () => {
      expect(isSafeContent('<p>Safe content</p>')).toBe(true);
      expect(isSafeContent('<strong>Bold text</strong>')).toBe(true);
    });
  });
});
