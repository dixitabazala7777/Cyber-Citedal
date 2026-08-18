/**
 * DEEPSHIELD Enterprise — AI Prompt-Injection & Indirect Jailbreak Guard (Feature 1)
 *
 * Client-side scanner detecting:
 * - Zero-width Unicode characters (ZWJ, ZWNJ, ZWS, ZWSP, BOM, etc.)
 * - Base64-encoded instruction injection blocks
 * - System role spoofing / delimiter override attempts
 * - Prompt leaking / extraction patterns
 * - Indirect injection via markdown/HTML formatting
 */

// ─── Detection Result Types ───────────────────────────────────────────────
export type ThreatCategory =
  | 'ZERO_WIDTH_INJECTION'
  | 'BASE64_INSTRUCTION'
  | 'ROLE_SPOOFING'
  | 'DELIMITER_OVERRIDE'
  | 'PROMPT_EXTRACTION'
  | 'ENCODING_OBFUSCATION'
  | 'INDIRECT_INJECTION'
  | 'PAYLOAD_SMUGGLING';

export interface JailbreakFinding {
  id: string;
  category: ThreatCategory;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  matchedPattern: string;
  position: { start: number; end: number };
  recommendation: string;
}

export interface ScanResult {
  clean: boolean;
  riskScore: number; // 0–100
  findings: JailbreakFinding[];
  sanitizedPrompt: string;
  scanDurationMs: number;
  totalChecks: number;
}

// ─── Zero-Width Character Map ─────────────────────────────────────────────
const ZERO_WIDTH_CHARS: Record<string, string> = {
  '\u200B': 'ZWSP (Zero Width Space)',
  '\u200C': 'ZWNJ (Zero Width Non-Joiner)',
  '\u200D': 'ZWJ (Zero Width Joiner)',
  '\u200E': 'LRM (Left-to-Right Mark)',
  '\u200F': 'RLM (Right-to-Left Mark)',
  '\u2060': 'WJ (Word Joiner)',
  '\u2061': 'Function Application',
  '\u2062': 'Invisible Times',
  '\u2063': 'Invisible Separator',
  '\u2064': 'Invisible Plus',
  '\uFEFF': 'BOM (Byte Order Mark)',
  '\u00AD': 'Soft Hyphen',
  '\u034F': 'Combining Grapheme Joiner',
  '\u061C': 'Arabic Letter Mark',
  '\u180E': 'Mongolian Vowel Separator',
};

const ZERO_WIDTH_REGEX = new RegExp(
  `[${Object.keys(ZERO_WIDTH_CHARS).join('')}]`,
  'g'
);

// ─── Role Spoofing & Delimiter Patterns ───────────────────────────────────
const ROLE_SPOOFING_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /\b(system|assistant|developer)\s*[:]\s*/gi, label: 'Role prefix injection' },
  { regex: /<<\s*SYS\s*>>/gi, label: 'Llama2 system tag' },
  { regex: /\[INST\]/gi, label: 'Llama instruction delimiter' },
  { regex: /<\|im_start\|>/gi, label: 'ChatML start token' },
  { regex: /<\|im_end\|>/gi, label: 'ChatML end token' },
  { regex: /<\|system\|>/gi, label: 'System role override tag' },
  { regex: /<\|user\|>/gi, label: 'User role injection tag' },
  { regex: /<\|assistant\|>/gi, label: 'Assistant role injection tag' },
  { regex: /###\s*(system|instruction|human|assistant)\b/gi, label: 'Markdown heading role injection' },
  { regex: /\bignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?|guidelines?)\b/gi, label: 'Instruction override attempt' },
  { regex: /\byou\s+are\s+(now|no longer|actually)\b/gi, label: 'Identity reassignment' },
  { regex: /\b(forget|disregard|override)\s+(everything|all|your)\b/gi, label: 'Memory wipe attempt' },
  { regex: /\bpretend\s+(you|to\s+be|that)\b/gi, label: 'Persona impersonation' },
  { regex: /\bjailbreak(ed)?\b/gi, label: 'Explicit jailbreak keyword' },
  { regex: /\bDAN\s*(mode)?\b/g, label: 'DAN (Do Anything Now) prompt' },
];

// ─── Prompt Extraction Patterns ───────────────────────────────────────────
const EXTRACTION_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /\b(repeat|echo|print|output|show|display|reveal|tell\s+me)\s+(your|the|all)?\s*(system\s*prompt|instructions|rules|initial\s*prompt|original\s*prompt)\b/gi, label: 'System prompt extraction' },
  { regex: /\bwhat\s+(are|were)\s+your\s+(instructions|rules|guidelines|system\s*prompt)\b/gi, label: 'Instruction query' },
  { regex: /\btranslate\s+your\s+(system\s*prompt|instructions|rules)\b/gi, label: 'Translation extraction' },
  { regex: /\bencode\s+(your|the)\s+(system\s*prompt|instructions)\s*(in|to|as)\s*(base64|hex|rot13|binary)\b/gi, label: 'Encoding extraction' },
];

// ─── Payload Smuggling Patterns ───────────────────────────────────────────
const SMUGGLING_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /<!--[\s\S]*?-->/g, label: 'HTML comment injection' },
  { regex: /<script[\s\S]*?<\/script>/gi, label: 'Script tag injection' },
  { regex: /\{\{[\s\S]*?\}\}/g, label: 'Template injection (Handlebars/Jinja)' },
  { regex: /\$\{[\s\S]*?\}/g, label: 'Template literal injection' },
  { regex: /\\\n/g, label: 'Escaped newline smuggling' },
];

// ─── Base64 Detection ─────────────────────────────────────────────────────
function detectBase64Blocks(text: string): { decoded: string; start: number; end: number }[] {
  const results: { decoded: string; start: number; end: number }[] = [];
  // Match Base64-like strings (min 20 chars to reduce false positives)
  const b64Regex = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  let match: RegExpExecArray | null;

  while ((match = b64Regex.exec(text)) !== null) {
    try {
      const decoded = atob(match[0]);
      // Check if decoded content contains suspicious instruction-like text
      const hasInstructions = /\b(ignore|system|forget|override|execute|eval|function|import|require)\b/i.test(decoded);
      const isPrintable = /^[\x20-\x7E\s]{4,}$/.test(decoded);

      if (isPrintable && (hasInstructions || decoded.length > 30)) {
        results.push({
          decoded,
          start: match.index,
          end: match.index + match[0].length,
        });
      }
    } catch {
      // Not valid Base64 — ignore
    }
  }

  return results;
}

// ─── Unicode Encoding Obfuscation ─────────────────────────────────────────
function detectEncodingObfuscation(text: string): { label: string; start: number; end: number }[] {
  const findings: { label: string; start: number; end: number }[] = [];

  // Homoglyph detection: Cyrillic characters that look like Latin
  const cyrillicHomoglyphs = /[\u0400-\u04FF]/g;
  let m: RegExpExecArray | null;
  while ((m = cyrillicHomoglyphs.exec(text)) !== null) {
    findings.push({ label: `Cyrillic homoglyph: U+${m[0].charCodeAt(0).toString(16).toUpperCase()}`, start: m.index, end: m.index + 1 });
  }

  // Fullwidth Latin characters
  const fullwidth = /[\uFF01-\uFF5E]/g;
  while ((m = fullwidth.exec(text)) !== null) {
    findings.push({ label: `Fullwidth Latin: U+${m[0].charCodeAt(0).toString(16).toUpperCase()}`, start: m.index, end: m.index + 1 });
  }

  // Combining diacritical marks stacking (Zalgo text)
  const zalgo = /[\u0300-\u036F]{3,}/g;
  while ((m = zalgo.exec(text)) !== null) {
    findings.push({ label: 'Zalgo text (stacked diacriticals)', start: m.index, end: m.index + m[0].length });
  }

  return findings;
}

// ─── Main Scanner ─────────────────────────────────────────────────────────
let findingCounter = 0;
function makeFindingId(): string {
  return `jb-${Date.now()}-${++findingCounter}`;
}

export function scanPromptForJailbreak(prompt: string): ScanResult {
  const startTime = performance.now();
  const findings: JailbreakFinding[] = [];
  let sanitized = prompt;
  let totalChecks = 0;

  // ── 1. Zero-Width Character Injection ──────────────────────────────────
  totalChecks++;
  const zwMatches: { char: string; index: number; name: string }[] = [];
  let zwMatch: RegExpExecArray | null;
  const zwRegex = new RegExp(ZERO_WIDTH_REGEX.source, 'g');
  while ((zwMatch = zwRegex.exec(prompt)) !== null) {
    zwMatches.push({
      char: zwMatch[0],
      index: zwMatch.index,
      name: ZERO_WIDTH_CHARS[zwMatch[0]] || `U+${zwMatch[0].charCodeAt(0).toString(16).toUpperCase()}`,
    });
  }
  if (zwMatches.length > 0) {
    findings.push({
      id: makeFindingId(),
      category: 'ZERO_WIDTH_INJECTION',
      severity: zwMatches.length > 5 ? 'critical' : 'high',
      description: `${zwMatches.length} zero-width character(s) detected: ${zwMatches.slice(0, 3).map(z => z.name).join(', ')}${zwMatches.length > 3 ? ` (+${zwMatches.length - 3} more)` : ''}`,
      matchedPattern: zwMatches.map(z => z.name).join(', '),
      position: { start: zwMatches[0].index, end: zwMatches[zwMatches.length - 1].index + 1 },
      recommendation: 'Strip all zero-width Unicode characters before LLM processing.',
    });
    // Sanitize: remove zero-width chars
    sanitized = sanitized.replace(ZERO_WIDTH_REGEX, '');
  }

  // ── 2. Base64 Instruction Blocks ───────────────────────────────────────
  totalChecks++;
  const b64Blocks = detectBase64Blocks(prompt);
  for (const block of b64Blocks) {
    findings.push({
      id: makeFindingId(),
      category: 'BASE64_INSTRUCTION',
      severity: 'critical',
      description: `Base64-encoded instruction block detected. Decoded: "${block.decoded.slice(0, 80)}${block.decoded.length > 80 ? '…' : ''}"`,
      matchedPattern: prompt.slice(block.start, Math.min(block.end, block.start + 40)) + '…',
      position: block,
      recommendation: 'Reject or decode and re-scan Base64 payloads before LLM submission.',
    });
  }

  // ── 3. Role Spoofing & Delimiter Overrides ─────────────────────────────
  for (const pattern of ROLE_SPOOFING_PATTERNS) {
    totalChecks++;
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(prompt)) !== null) {
      findings.push({
        id: makeFindingId(),
        category: m[0].match(/<\||\[INST\]|<<\s*SYS/i) ? 'DELIMITER_OVERRIDE' : 'ROLE_SPOOFING',
        severity: 'high',
        description: `${pattern.label}: "${m[0]}"`,
        matchedPattern: m[0],
        position: { start: m.index, end: m.index + m[0].length },
        recommendation: 'Strip model-specific delimiters and role assignment patterns.',
      });
    }
  }

  // ── 4. Prompt Extraction Attempts ──────────────────────────────────────
  for (const pattern of EXTRACTION_PATTERNS) {
    totalChecks++;
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(prompt)) !== null) {
      findings.push({
        id: makeFindingId(),
        category: 'PROMPT_EXTRACTION',
        severity: 'medium',
        description: `${pattern.label}: "${m[0]}"`,
        matchedPattern: m[0],
        position: { start: m.index, end: m.index + m[0].length },
        recommendation: 'Block requests attempting to extract system instructions.',
      });
    }
  }

  // ── 5. Encoding Obfuscation (Homoglyphs, Zalgo, Fullwidth) ─────────────
  totalChecks++;
  const encodingFindings = detectEncodingObfuscation(prompt);
  if (encodingFindings.length > 0) {
    findings.push({
      id: makeFindingId(),
      category: 'ENCODING_OBFUSCATION',
      severity: encodingFindings.length > 10 ? 'high' : 'medium',
      description: `${encodingFindings.length} encoding obfuscation artifact(s): ${encodingFindings.slice(0, 3).map(f => f.label).join(', ')}`,
      matchedPattern: encodingFindings.slice(0, 3).map(f => f.label).join(', '),
      position: { start: encodingFindings[0].start, end: encodingFindings[encodingFindings.length - 1].end },
      recommendation: 'Normalize Unicode to NFC and strip non-Latin homoglyphs.',
    });
  }

  // ── 6. Payload Smuggling (HTML comments, script tags, templates) ───────
  for (const pattern of SMUGGLING_PATTERNS) {
    totalChecks++;
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(prompt)) !== null) {
      findings.push({
        id: makeFindingId(),
        category: 'PAYLOAD_SMUGGLING',
        severity: pattern.label.includes('Script') ? 'critical' : 'medium',
        description: `${pattern.label}: "${m[0].slice(0, 60)}${m[0].length > 60 ? '…' : ''}"`,
        matchedPattern: m[0].slice(0, 40),
        position: { start: m.index, end: m.index + m[0].length },
        recommendation: 'Sanitize HTML/template syntax before model ingestion.',
      });
    }
  }

  // ── Risk Score Computation ─────────────────────────────────────────────
  const severityWeights: Record<string, number> = { critical: 30, high: 20, medium: 10, low: 5 };
  let rawScore = findings.reduce((sum, f) => sum + (severityWeights[f.severity] || 5), 0);
  const riskScore = Math.min(100, rawScore);

  const scanDurationMs = performance.now() - startTime;

  return {
    clean: findings.length === 0,
    riskScore,
    findings,
    sanitizedPrompt: sanitized,
    scanDurationMs,
    totalChecks,
  };
}

/** Quick check — returns true if prompt is likely clean */
export function isPromptClean(prompt: string): boolean {
  return scanPromptForJailbreak(prompt).clean;
}
