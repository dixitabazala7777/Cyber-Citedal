import { sanitizeDecoyLoad, getHoneypotDecoyState } from '../components/HoneypotDecoyBar';

type TestFn = () => void | Promise<void>;

class MiniTestSuite {
  private passedCount = 0;
  private failedCount = 0;
  private queue: Array<{ name: string; fn: TestFn }> = [];

  describe(name: string, fn: () => void) {
    console.log(`\n\x1b[36m[SUITE] ${name}\x1b[0m`);
    fn();
  }

  it(name: string, fn: TestFn) {
    this.queue.push({ name, fn });
  }

  expect(actual: unknown) {
    return {
      toBe: (expected: unknown) => {
        if (actual !== expected) {
          throw new Error(`Expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`);
        }
      }
    };
  }

  async runAll() {
    for (const item of this.queue) {
      try {
        await item.fn();
        console.log(`  \x1b[32m✓ PASSED: ${item.name}\x1b[0m`);
        this.passedCount++;
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        console.error(`  \x1b[31m✗ FAILED: ${item.name}\x1b[0m`);
        console.error(`    Error: ${errorMsg}`);
        this.failedCount++;
      }
    }

    console.log(`\n\x1b[35m=== HONEYPOT DECOY BAR TEST SUMMARY ===\x1b[0m`);
    console.log(`Total tests: ${this.passedCount + this.failedCount}`);
    console.log(`Passed: \x1b[32m${this.passedCount}\x1b[0m`);
    console.log(`Failed: \x1b[31m${this.failedCount}\x1b[0m`);
    if (this.failedCount > 0) {
      process.exit(1);
    }
  }
}

const suite = new MiniTestSuite();

async function runTests() {
  suite.describe('HoneypotDecoyBar: sanitizeDecoyLoad Edge Cases & Bug Prevention', () => {
    suite.it('Test Case 1: Safely handle null and undefined with default fallback (0)', () => {
      suite.expect(sanitizeDecoyLoad(null)).toBe(0);
      suite.expect(sanitizeDecoyLoad(undefined)).toBe(0);
      suite.expect(sanitizeDecoyLoad(null, 25)).toBe(25);
    });

    suite.it('Test Case 2: Safely handle NaN, empty strings, and non-numeric objects', () => {
      suite.expect(sanitizeDecoyLoad(NaN)).toBe(0);
      suite.expect(sanitizeDecoyLoad('corrupted_feed')).toBe(0);
      suite.expect(sanitizeDecoyLoad('')).toBe(0);
      suite.expect(sanitizeDecoyLoad({})).toBe(0);
      suite.expect(sanitizeDecoyLoad([])).toBe(0);
    });

    suite.it('Test Case 3: Parse clean numeric and formatted percentage strings', () => {
      suite.expect(sanitizeDecoyLoad('48.5%')).toBe(48.5);
      suite.expect(sanitizeDecoyLoad(' 72.1 ')).toBe(72.1);
      suite.expect(sanitizeDecoyLoad('100%')).toBe(100);
    });

    suite.it('Test Case 4: Strictly clamp out-of-bounds inputs (<0 and >100)', () => {
      suite.expect(sanitizeDecoyLoad(-30)).toBe(0);
      suite.expect(sanitizeDecoyLoad(145)).toBe(100);
      suite.expect(sanitizeDecoyLoad(0)).toBe(0);
      suite.expect(sanitizeDecoyLoad(100)).toBe(100);
    });
  });

  suite.describe('HoneypotDecoyBar: Dynamic Status Colors & Threat Thresholds', () => {
    suite.it('Test Case 5: Idle / Low (< 30%) triggers Subdued Cyber Blue (#0EA5E9) & ARMED status', () => {
      const idle0 = getHoneypotDecoyState(0);
      suite.expect(idle0.status).toBe('ARMED');
      suite.expect(idle0.colorHex).toBe('#0EA5E9');
      suite.expect(idle0.colorName).toBe('cyber-blue');
      suite.expect(idle0.pulseGlow).toBe(false);

      const idle29 = getHoneypotDecoyState(29.9);
      suite.expect(idle29.status).toBe('ARMED');
      suite.expect(idle29.colorHex).toBe('#0EA5E9');
    });

    suite.it('Test Case 6: Moderate (30% - 70%) triggers Warning Amber (#F59E0B) & ENGAGED status', () => {
      const moderate30 = getHoneypotDecoyState(30);
      suite.expect(moderate30.status).toBe('ENGAGED');
      suite.expect(moderate30.colorHex).toBe('#F59E0B');
      suite.expect(moderate30.colorName).toBe('amber');
      suite.expect(moderate30.pulseGlow).toBe(false);

      const moderate50 = getHoneypotDecoyState(50);
      suite.expect(moderate50.status).toBe('ENGAGED');

      const moderate70 = getHoneypotDecoyState(70);
      suite.expect(moderate70.status).toBe('ENGAGED');
      suite.expect(moderate70.colorHex).toBe('#F59E0B');
    });

    suite.it('Test Case 7: Heavy Attack (> 70%) triggers Alert Crimson (#EF4444) pulsing glow & CRITICAL status', () => {
      const heavy71 = getHoneypotDecoyState(70.1);
      suite.expect(heavy71.status).toBe('CRITICAL');
      suite.expect(heavy71.colorHex).toBe('#EF4444');
      suite.expect(heavy71.colorName).toBe('crimson');
      suite.expect(heavy71.pulseGlow).toBe(true);

      const heavy100 = getHoneypotDecoyState(100);
      suite.expect(heavy100.status).toBe('CRITICAL');
      suite.expect(heavy100.pulseGlow).toBe(true);
    });
  });

  await suite.runAll();
}

runTests();
