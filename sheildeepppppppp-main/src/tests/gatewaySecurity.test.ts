/**
 * DeepShield-Core Gateway Security Test Suite
 * Fully functional, zero-dependency typescript testing utility to simulate Layer 1 identity and device verification.
 */

interface MockRequest {
  headers: Record<string, string>;
  bodySize: number; // in bytes
  url: string;
}

interface MockResponse {
  statusCode: number;
  body: Record<string, unknown>;
  headers: Record<string, string>;
}

// Simulated Whitelisted Device Certificate fingerprint
const TRUSTED_CERT_SHA256 = "f8b31a89c36290356cbb015fa4d38c691307b22ee015a9e334bc6ad734fe0ce2";

/**
 * Simplified TypeScript simulation of DeepShield's FastAPI IdentityCheckMiddleware
 */
async function simulateIdentityCheckMiddleware(request: MockRequest): Promise<MockResponse> {
  const startTime = Date.now();

  // --- 1. Payload Size Pre-Inspection (Early Exit <1ms) ---
  const contentLength = request.bodySize;
  if (contentLength > 51200) { // 50KB limit
    return {
      statusCode: 413,
      body: { error: "Payload Too Large", code: "GATEWAY_PAYLOAD_LIMIT_BREACHED" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  // --- 2. mTLS Fingerprint Verification (Early Exit <2ms) ---
  const clientVerify = request.headers["X-Client-Verify"];
  const clientCertSha = request.headers["X-Client-Cert-SHA256"];

  if (!clientVerify || clientVerify !== "SUCCESS" || !clientCertSha) {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_MTLS_FAILED" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  if (clientCertSha !== TRUSTED_CERT_SHA256) {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_DEVICE_UNTRUSTED" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  // --- 3. OAuth2 Bearer JWT Token Scope Validation (Early Exit <5ms) ---
  const authHeader = request.headers["Authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_UNAUTHORIZED" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  const token = authHeader.split(" ")[1];

  // Mock Decode logic representing JWT cryptchecks
  if (token === "EXPIRED_TOKEN") {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_CREDENTIALS_INVALID", detail: "Token expired" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  if (token === "TAMPERED_TOKEN") {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_CREDENTIALS_INVALID", detail: "Signature validation failed" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  // Simulate claims payload extraction
  let claims: { scopes: string[]; vector_partition: string; sub: string } | null = null;
  if (token === "VALID_INFERENCE_TOKEN") {
    claims = {
      sub: "pipeline-agent-77",
      scopes: ["crimegpt:write", "defense:execute"],
      vector_partition: "partition_alpha"
    };
  } else if (token === "INSUFFICIENT_SCOPES_TOKEN") {
    claims = {
      sub: "pipeline-agent-guest",
      scopes: ["read_only"],
      vector_partition: "partition_alpha"
    };
  }

  if (!claims) {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_CREDENTIALS_INVALID" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  // --- 4. Context-Aware Scope & Database Claims Verification ---
  const requiredScopes = ["crimegpt:write", "defense:execute"];
  const hasScope = requiredScopes.every(scope => claims?.scopes.includes(scope));
  if (!hasScope) {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_SCOPES_INSUFFICIENT" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  const targetPartition = request.headers["X-Target-Partition"];
  if (targetPartition && claims.vector_partition !== targetPartition) {
    return {
      statusCode: 403,
      body: { error: "Access Denied", code: "GATEWAY_PARTITION_VIOLATION" },
      headers: { "X-Response-Time-Ms": `${Date.now() - startTime}ms` }
    };
  }

  const latency = Date.now() - startTime;
  return {
    statusCode: 200,
    body: {
      status: "GRANTED",
      identity: claims.sub,
      active_partition: claims.vector_partition,
      payload: "Verified air-gapped vector pipeline stream connected."
    },
    headers: {
      "X-Response-Time-Ms": `${latency}ms`
    }
  };
}

// Custom Micro Test Framework to enable compilation and run capabilities
type TestFn = () => Promise<void> | void;

class TestSuite {
  private currentSuiteName = "";
  private passedCount = 0;
  private failedCount = 0;

  describe(name: string, fn: () => void) {
    this.currentSuiteName = name;
    console.log(`\n\x1b[36m[SUITE] ${name}\x1b[0m`);
    fn();
  }

  async it(name: string, fn: TestFn) {
    try {
      await fn();
      console.log(`  \x1b[32m✓ PASSED: ${name}\x1b[0m`);
      this.passedCount++;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      console.error(`  \x1b[31m✗ FAILED: ${name}\x1b[0m`);
      console.error(`    Error: ${errorMsg}`);
      this.failedCount++;
    }
  }

  expect(actual: unknown) {
    return {
      toBe: (expected: unknown) => {
        if (actual !== expected) {
          throw new Error(`Expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`);
        }
      },
      toBeLessThan: (expected: number) => {
        if (typeof actual !== "number" || actual >= expected) {
          throw new Error(`Expected value to be less than ${expected} but got ${actual}`);
        }
      }
    };
  }

  printSummary() {
    console.log(`\n\x1b[35m=== GATEWAY SECURITY TEST SUMMARY ===\x1b[0m`);
    console.log(`Total tests: ${this.passedCount + this.failedCount}`);
    console.log(`Passed: \x1b[32m${this.passedCount}\x1b[0m`);
    console.log(`Failed: \x1b[31m${this.failedCount}\x1b[0m`);
  }
}

export interface TestCaseResult {
  name: string;
  category: string;
  expectedStatus: number;
  actualStatus: number;
  latencyMs: number;
  passed: boolean;
  message: string;
}

export async function runGatewaySecurityTests(): Promise<TestCaseResult[]> {
  const results: TestCaseResult[] = [];

  // Test Case 1: Expired JWT Token
  {
    const start = Date.now();
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 2048,
      headers: {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert-SHA256": TRUSTED_CERT_SHA256,
        "Authorization": "Bearer EXPIRED_TOKEN"
      }
    };
    const response = await simulateIdentityCheckMiddleware(request);
    const latency = Date.now() - start;
    results.push({
      name: "Expired OAuth2 JWT Token",
      category: "JWT_DECODE",
      expectedStatus: 403,
      actualStatus: response.statusCode,
      latencyMs: latency || 1,
      passed: response.statusCode === 403 && (response.body.code === "GATEWAY_CREDENTIALS_INVALID"),
      message: "Verifies expired JWT token gets immediately dropped with 403 Forbidden under 10ms."
    });
  }

  // Test Case 2: Missing mTLS Headers
  {
    const start = Date.now();
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 2048,
      headers: {
        "Authorization": "Bearer VALID_INFERENCE_TOKEN"
      }
    };
    const response = await simulateIdentityCheckMiddleware(request);
    const latency = Date.now() - start;
    results.push({
      name: "Missing Client mTLS Headers",
      category: "MTLS_HANDSHAKE",
      expectedStatus: 403,
      actualStatus: response.statusCode,
      latencyMs: latency || 1,
      passed: response.statusCode === 403 && response.body.code === "GATEWAY_MTLS_FAILED",
      message: "Verifies traffic missing hardware verification certificates gets blocked out-of-band."
    });
  }

  // Test Case 3: Oversized Payload
  {
    const start = Date.now();
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 52000,
      headers: {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert-SHA256": TRUSTED_CERT_SHA256,
        "Authorization": "Bearer VALID_INFERENCE_TOKEN"
      }
    };
    const response = await simulateIdentityCheckMiddleware(request);
    const latency = Date.now() - start;
    results.push({
      name: "Oversized Payload Block",
      category: "NGINX_CAP_50KB",
      expectedStatus: 413,
      actualStatus: response.statusCode,
      latencyMs: latency || 1,
      passed: response.statusCode === 413 && response.body.code === "GATEWAY_PAYLOAD_LIMIT_BREACHED",
      message: "Enforces strict 50KB maximum size caps to protect downstream nodes from memory exhaustion."
    });
  }

  // Test Case 4: Valid Request Path
  {
    const start = Date.now();
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 1024,
      headers: {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert-SHA256": TRUSTED_CERT_SHA256,
        "Authorization": "Bearer VALID_INFERENCE_TOKEN"
      }
    };
    const response = await simulateIdentityCheckMiddleware(request);
    const latency = Date.now() - start;
    results.push({
      name: "Authorized Secure Session Pass",
      category: "VALID_STATE",
      expectedStatus: 200,
      actualStatus: response.statusCode,
      latencyMs: latency || 1,
      passed: response.statusCode === 200 && response.body.status === "GRANTED",
      message: "Verifies authentic device credentials with valid JWT access scopes successfully resolve."
    });
  }

  return results;
}

// Execute the security suites
const suite = new TestSuite();

suite.describe("DeepShield-Core Layer 1 Boundary Verification Gate", () => {
  
  suite.it("Test Case 1: Expired JWT Token early rejection and fast circuit breaker under 10ms", async () => {
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 2048,
      headers: {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert-SHA256": TRUSTED_CERT_SHA256,
        "Authorization": "Bearer EXPIRED_TOKEN"
      }
    };

    const response = await simulateIdentityCheckMiddleware(request);
    suite.expect(response.statusCode).toBe(403);
    suite.expect(response.body.code).toBe("GATEWAY_CREDENTIALS_INVALID");

    // Enforce <10ms validation latency constraint
    const latencyString = response.headers["X-Response-Time-Ms"];
    const latencyMs = parseInt(latencyString);
    suite.expect(latencyMs).toBeLessThan(10);
  });

  suite.it("Test Case 2: Reject request immediately when missing client hardware mTLS headers", async () => {
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 2048,
      headers: {
        "Authorization": "Bearer VALID_INFERENCE_TOKEN"
        // missing 'X-Client-Cert-SHA256' and 'X-Client-Verify'
      }
    };

    const response = await simulateIdentityCheckMiddleware(request);
    suite.expect(response.statusCode).toBe(403);
    suite.expect(response.body.code).toBe("GATEWAY_MTLS_FAILED");
  });

  suite.it("Test Case 3: Oversized request payload (>50KB) discarded before deep processing", async () => {
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 52000, // 52KB (threshold is 50KB / 51,200 bytes)
      headers: {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert-SHA256": TRUSTED_CERT_SHA256,
        "Authorization": "Bearer VALID_INFERENCE_TOKEN"
      }
    };

    const response = await simulateIdentityCheckMiddleware(request);
    suite.expect(response.statusCode).toBe(413);
    suite.expect(response.body.code).toBe("GATEWAY_PAYLOAD_LIMIT_BREACHED");
  });

  suite.it("Test Case 4: Process full valid secure request with approved device CA and JWT permissions", async () => {
    const request: MockRequest = {
      url: "/api/v1/inference",
      bodySize: 1024,
      headers: {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert-SHA256": TRUSTED_CERT_SHA256,
        "Authorization": "Bearer VALID_INFERENCE_TOKEN"
      }
    };

    const response = await simulateIdentityCheckMiddleware(request);
    suite.expect(response.statusCode).toBe(200);
    suite.expect(response.body.status).toBe("GRANTED");
    suite.expect(response.body.identity).toBe("pipeline-agent-77");
  });

});

suite.printSummary();
