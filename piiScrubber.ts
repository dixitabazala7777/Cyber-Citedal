/**
 * DEEPSHIELD Enterprise — Client-Side PII & Secret Scrubbing Sanitizer (Feature 4)
 *
 * Redacts API keys, JWTs, credit card numbers, emails, passwords,
 * SSNs, phone numbers, and other sensitive data from text payloads
 * BEFORE they leave the browser. Generates a structured before/after diff.
 */

// ─── Redaction Types ──────────────────────────────────────────────────────
export type SecretCategory =
  | 'API_KEY'
  | 'JWT_TOKEN'
  | 'BEARER_TOKEN'
  | 'CREDIT_CARD'
  | 'EMAIL'
  | 'SSN'
  | 'PHONE'
  | 'IPV4_ADDRESS'
  | 'AWS_ACCESS_KEY'
  | 'AWS_SECRET_KEY'
  | 'GITHUB_TOKEN'
  | 'SLACK_TOKEN'
  | 'PRIVATE_KEY_BLOCK'
  | 'PASSWORD_FIELD'
  | 'GENERIC_SECRET';

export interface RedactionMatch {
  id: string;
  category: SecretCategory;
  original: string;
  redacted: string;
  position: { start: number; end: number; line: number };
  confidence: 'high' | 'medium' | 'low';
}

export interface ScrubResult {
  originalText: string;
  scrubbedText: string;
  redactions: RedactionMatch[];
  totalRedactions: number;
  categories: Record<SecretCategory, number>;
  processingTimeMs: number;
}

export interface DiffLine {
  lineNumber: number;
  type: 'unchanged' | 'redacted';
  original: string;
  scrubbed: string;
  redactionCount: number;
}

// ─── Pattern Definitions ──────────────────────────────────────────────────
interface SecretPattern {
  category: SecretCategory;
  regex: RegExp;
  confidence: 'high' | 'medium' | 'low';
  redactFn?: (match: string) => string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // ── JWT Tokens ───
  {
    category: 'JWT_TOKEN',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    confidence: 'high',
    redactFn: (m) => `[REDACTED_JWT_${m.slice(-6)}]`,
  },
  // ── Bearer Tokens ───
  {
    category: 'BEARER_TOKEN',
    regex: /Bearer\s+[A-Za-z0-9_\-.~+/]+=*/gi,
    confidence: 'high',
    redactFn: () => 'Bearer [REDACTED_TOKEN]',
  },
  // ── AWS Access Key IDs ───
  {
    category: 'AWS_ACCESS_KEY',
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    confidence: 'high',
    redactFn: (m) => `[REDACTED_AWS_KEY_${m.slice(0, 4)}***]`,
  },
  // ── AWS Secret Keys ───
  {
    category: 'AWS_SECRET_KEY',
    regex: /\b[A-Za-z0-9/+=]{40}\b/g,
    confidence: 'low', // High false positive rate; only flag near context
  },
  // ── GitHub Tokens ───
  {
    category: 'GITHUB_TOKEN',
    regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/g,
    confidence: 'high',
    redactFn: (m) => `[REDACTED_GH_TOKEN_${m.slice(0, 4)}***]`,
  },
  // ── Slack Tokens ───
  {
    category: 'SLACK_TOKEN',
    regex: /\bxox[bpras]-[A-Za-z0-9-]{10,}/g,
    confidence: 'high',
    redactFn: () => '[REDACTED_SLACK_TOKEN]',
  },
  // ── Private Key Blocks ───
  {
    category: 'PRIVATE_KEY_BLOCK',
    regex: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----/g,
    confidence: 'high',
    redactFn: () => '[REDACTED_PRIVATE_KEY_BLOCK]',
  },
  // ── Credit Card Numbers (Luhn-compatible) ───
  {
    category: 'CREDIT_CARD',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    confidence: 'high',
    redactFn: (m) => `[REDACTED_CC_****${m.slice(-4)}]`,
  },
  // ── SSN (US) ───
  {
    category: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    confidence: 'high',
    redactFn: () => '[REDACTED_SSN_***-**-****]',
  },
  // ── Email Addresses ───
  {
    category: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    confidence: 'high',
    redactFn: (m) => {
      const [, domain] = m.split('@');
      return `[REDACTED_EMAIL_***@${domain}]`;
    },
  },
  // ── Phone Numbers (US/Intl) ───
  {
    category: 'PHONE',
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    confidence: 'medium',
    redactFn: () => '[REDACTED_PHONE_***-***-****]',
  },
  // ── IPv4 Addresses ───
  {
    category: 'IPV4_ADDRESS',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    confidence: 'medium',
    redactFn: (m) => {
      const octets = m.split('.');
      return `[REDACTED_IP_${octets[0]}.***.***.${octets[3]}]`;
    },
  },
  // ── Generic API Keys (key=..., api_key=..., apikey:...) ───
  {
    category: 'API_KEY',
    regex: /\b(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=]{16,})['"]?/gi,
    confidence: 'high',
    redactFn: (m) => {
      const eqIndex = m.search(/[:=]/);
      const prefix = m.slice(0, eqIndex + 1);
      return `${prefix} [REDACTED_API_KEY]`;
    },
  },
  // ── Password fields (password=..., passwd:..., pwd:...) ───
  {
    category: 'PASSWORD_FIELD',
    regex: /\b(?:password|passwd|pwd|pass)\s*[:=]\s*['"]?([^\s'"]{4,})['"]?/gi,
    confidence: 'high',
    redactFn: (m) => {
      const eqIndex = m.search(/[:=]/);
      const prefix = m.slice(0, eqIndex + 1);
      return `${prefix} [REDACTED_PASSWORD]`;
    },
  },
  // ── Generic hex secrets (32+ hex chars) ───
  {
    category: 'GENERIC_SECRET',
    regex: /\b[0-9a-fA-F]{32,}\b/g,
    confidence: 'low',
    redactFn: (m) => `[REDACTED_HEX_${m.slice(0, 6)}***${m.slice(-4)}]`,
  },
];

// ─── Core Scrubber ────────────────────────────────────────────────────────
let redactionCounter = 0;

export function scrubText(text: string): ScrubResult {
  const startTime = performance.now();
  const redactions: RedactionMatch[] = [];
  const categories: Record<string, number> = {};
  let scrubbedText = text;

  // Process patterns from highest confidence to lowest
  const sortedPatterns = [...SECRET_PATTERNS].sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return order[a.confidence] - order[b.confidence];
  });

  // Track redacted ranges to avoid double-redacting
  const redactedRanges: { start: number; end: number }[] = [];

  for (const pattern of sortedPatterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;

      // Skip if this range overlaps with an already-redacted region
      const overlaps = redactedRanges.some(
        (r) => start < r.end && end > r.start
      );
      if (overlaps) continue;

      // Skip low-confidence matches that are too short
      if (pattern.confidence === 'low' && match[0].length < 32) continue;

      const lineNumber = text.slice(0, start).split('\n').length;
      const redactedValue = pattern.redactFn
        ? pattern.redactFn(match[0])
        : `[REDACTED_${pattern.category}]`;

      redactions.push({
        id: `pii-${Date.now()}-${++redactionCounter}`,
        category: pattern.category,
        original: match[0],
        redacted: redactedValue,
        position: { start, end, line: lineNumber },
        confidence: pattern.confidence,
      });

      categories[pattern.category] = (categories[pattern.category] || 0) + 1;
      redactedRanges.push({ start, end });
    }
  }

  // Apply redactions in reverse order (to preserve positions)
  const sortedRedactions = [...redactions].sort(
    (a, b) => b.position.start - a.position.start
  );
  for (const r of sortedRedactions) {
    scrubbedText =
      scrubbedText.slice(0, r.position.start) +
      r.redacted +
      scrubbedText.slice(r.position.end);
  }

  return {
    originalText: text,
    scrubbedText,
    redactions,
    totalRedactions: redactions.length,
    categories: categories as Record<SecretCategory, number>,
    processingTimeMs: performance.now() - startTime,
  };
}

// ─── Diff Generator ───────────────────────────────────────────────────────
export function generateDiff(result: ScrubResult): DiffLine[] {
  const originalLines = result.originalText.split('\n');
  const scrubbedLines = result.scrubbedText.split('\n');
  const diff: DiffLine[] = [];

  const maxLines = Math.max(originalLines.length, scrubbedLines.length);
  for (let i = 0; i < maxLines; i++) {
    const orig = originalLines[i] || '';
    const scrubbed = scrubbedLines[i] || '';
    const redactionCount = result.redactions.filter(
      (r) => r.position.line === i + 1
    ).length;

    diff.push({
      lineNumber: i + 1,
      type: orig !== scrubbed ? 'redacted' : 'unchanged',
      original: orig,
      scrubbed: scrubbed,
      redactionCount,
    });
  }

  return diff;
}

/** Quick check — returns true if text contains any detectable PII/secrets */
export function containsPII(text: string): boolean {
  return scrubText(text).totalRedactions > 0;
}
