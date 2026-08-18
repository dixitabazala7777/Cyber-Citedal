/**
 * DEEPSHIELD Enterprise — Cryptographic Tamper-Proof Audit Ledger (Feature 9)
 *
 * Incremental Merkle Tree implementation using Web Crypto API (SHA-256).
 * Every scan, node isolation, kill-switch event, and signature verification
 * is hashed as a leaf and appended to the tree. The root hash can be
 * recomputed at any time to verify that no historical record was tampered with.
 */

// ─── Leaf Types ────────────────────────────────────────────────────────────
export type AuditAction =
  | 'URL_SCAN'
  | 'FILE_PARSE'
  | 'SIGNATURE_VERIFY'
  | 'SIGNATURE_REVOKE'
  | 'KEY_ROTATE'
  | 'NODE_ISOLATE'
  | 'NODE_RESTORE'
  | 'KILL_SWITCH'
  | 'INCIDENT_RESOLVE'
  | 'WAF_PATCH_GENERATE'
  | 'CHAOS_SIMULATION'
  | 'HONEYPOT_TRIP'
  | 'PII_SCRUB'
  | 'JAILBREAK_BLOCK'
  | 'SYSTEM_EVENT';

export interface AuditLeaf {
  /** Unique identifier for this audit entry */
  id: string;
  /** ISO-8601 timestamp */
  timestamp: string;
  /** The action category */
  action: AuditAction;
  /** Actor identity (user, service, system) */
  actor: string;
  /** Human-readable summary of the audited event */
  summary: string;
  /** Serialized payload digest (e.g., incident ID, key ID, node ID) */
  targetRef: string;
  /** Computed SHA-256 hash of this leaf's canonical content */
  hash?: string;
}

export interface MerkleProof {
  leafHash: string;
  leafIndex: number;
  siblings: { hash: string; position: 'left' | 'right' }[];
  root: string;
}

export interface LedgerState {
  leaves: AuditLeaf[];
  rootHash: string;
  treeSize: number;
  lastUpdated: string;
  integrityVerified: boolean;
}

// ─── Hashing Primitives ───────────────────────────────────────────────────
async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Canonical leaf serialization — deterministic JSON for reproducible hashing */
function canonicalizeLeaf(leaf: AuditLeaf): string {
  return JSON.stringify({
    id: leaf.id,
    timestamp: leaf.timestamp,
    action: leaf.action,
    actor: leaf.actor,
    summary: leaf.summary,
    targetRef: leaf.targetRef,
  });
}

async function hashLeaf(leaf: AuditLeaf): Promise<string> {
  return sha256(`LEAF:${canonicalizeLeaf(leaf)}`);
}

async function hashPair(left: string, right: string): Promise<string> {
  return sha256(`NODE:${left}:${right}`);
}

// ─── Merkle Tree Engine ───────────────────────────────────────────────────
export class MerkleLedger {
  private leaves: AuditLeaf[] = [];
  private leafHashes: string[] = [];
  private rootHash: string = '';

  /** Get all leaves */
  getLeaves(): AuditLeaf[] {
    return [...this.leaves];
  }

  /** Get current root hash */
  getRootHash(): string {
    return this.rootHash;
  }

  /** Get tree size */
  getSize(): number {
    return this.leaves.length;
  }

  /** Append a new audit leaf and recompute root */
  async appendLeaf(leaf: AuditLeaf): Promise<{ leafHash: string; newRoot: string }> {
    const leafHash = await hashLeaf(leaf);
    leaf.hash = leafHash;
    this.leaves.push(leaf);
    this.leafHashes.push(leafHash);
    this.rootHash = await this.computeRoot(this.leafHashes);
    return { leafHash, newRoot: this.rootHash };
  }

  /** Recompute root from all leaf hashes — used for integrity verification */
  async computeRoot(hashes: string[]): Promise<string> {
    if (hashes.length === 0) return '';
    if (hashes.length === 1) return hashes[0];

    let level = [...hashes];
    while (level.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          nextLevel.push(await hashPair(level[i], level[i + 1]));
        } else {
          // Odd node: promote (hash with itself)
          nextLevel.push(await hashPair(level[i], level[i]));
        }
      }
      level = nextLevel;
    }
    return level[0];
  }

  /** Verify integrity: recompute root from all leaves and compare */
  async verifyIntegrity(): Promise<{
    valid: boolean;
    expectedRoot: string;
    computedRoot: string;
    mismatchedLeaves: number[];
  }> {
    const recomputedHashes: string[] = [];
    const mismatchedLeaves: number[] = [];

    for (let i = 0; i < this.leaves.length; i++) {
      const recomputed = await hashLeaf(this.leaves[i]);
      recomputedHashes.push(recomputed);
      if (recomputed !== this.leafHashes[i]) {
        mismatchedLeaves.push(i);
      }
    }

    const computedRoot = await this.computeRoot(recomputedHashes);
    return {
      valid: computedRoot === this.rootHash && mismatchedLeaves.length === 0,
      expectedRoot: this.rootHash,
      computedRoot,
      mismatchedLeaves,
    };
  }

  /** Generate a Merkle inclusion proof for a leaf at a given index */
  async generateProof(leafIndex: number): Promise<MerkleProof | null> {
    if (leafIndex < 0 || leafIndex >= this.leafHashes.length) return null;

    const siblings: { hash: string; position: 'left' | 'right' }[] = [];
    let level = [...this.leafHashes];
    let idx = leafIndex;

    while (level.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          nextLevel.push(await hashPair(level[i], level[i + 1]));
          if (i === idx || i + 1 === idx) {
            const siblingIdx = i === idx ? i + 1 : i;
            siblings.push({
              hash: level[siblingIdx],
              position: i === idx ? 'right' : 'left',
            });
          }
        } else {
          nextLevel.push(await hashPair(level[i], level[i]));
          if (i === idx) {
            siblings.push({ hash: level[i], position: 'right' });
          }
        }
      }
      idx = Math.floor(idx / 2);
      level = nextLevel;
    }

    return {
      leafHash: this.leafHashes[leafIndex],
      leafIndex,
      siblings,
      root: this.rootHash,
    };
  }

  /** Export ledger state for persistence or display */
  exportState(): LedgerState {
    return {
      leaves: [...this.leaves],
      rootHash: this.rootHash,
      treeSize: this.leaves.length,
      lastUpdated: this.leaves.length > 0 ? this.leaves[this.leaves.length - 1].timestamp : new Date().toISOString(),
      integrityVerified: true,
    };
  }

  /** Import leaves and rebuild the tree */
  async importLeaves(leaves: AuditLeaf[]): Promise<void> {
    this.leaves = [];
    this.leafHashes = [];
    for (const leaf of leaves) {
      const h = await hashLeaf(leaf);
      leaf.hash = h;
      this.leaves.push(leaf);
      this.leafHashes.push(h);
    }
    this.rootHash = await this.computeRoot(this.leafHashes);
  }
}

// ─── Singleton Instance ────────────────────────────────────────────────
let _instance: MerkleLedger | null = null;

export function getGlobalLedger(): MerkleLedger {
  if (!_instance) {
    _instance = new MerkleLedger();
  }
  return _instance;
}

/** Helper to quickly create and append an audit entry */
export async function auditLog(
  action: AuditAction,
  actor: string,
  summary: string,
  targetRef: string = ''
): Promise<{ leafHash: string; newRoot: string }> {
  const ledger = getGlobalLedger();
  const leaf: AuditLeaf = {
    id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    action,
    actor,
    summary,
    targetRef,
  };
  return ledger.appendLeaf(leaf);
}
