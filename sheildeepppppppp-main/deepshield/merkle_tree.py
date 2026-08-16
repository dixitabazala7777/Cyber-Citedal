"""
DEEPSHIELD Enterprise — Incremental Merkle Tree (Python Backend)

Server-side Merkle tree for tamper-proof audit ledger.
Mirrors the client-side implementation in src/lib/merkleLedger.ts.
Uses SHA-256 from hashlib for deterministic, reproducible hashing.
"""

import hashlib
import json
import time
import uuid
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger("DeepShield.MerkleTree")


class AuditLeaf:
    """A single leaf in the Merkle audit ledger."""

    def __init__(
        self,
        action: str,
        actor: str,
        summary: str,
        target_ref: str = "",
        leaf_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        self.id = leaf_id or f"audit-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
        self.timestamp = timestamp or time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        self.action = action
        self.actor = actor
        self.summary = summary
        self.target_ref = target_ref
        self.hash: Optional[str] = None

    def canonicalize(self) -> str:
        """Deterministic JSON for reproducible hashing."""
        return json.dumps({
            "id": self.id,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "summary": self.summary,
            "targetRef": self.target_ref,
        }, separators=(",", ":"), sort_keys=False)

    def compute_hash(self) -> str:
        """Compute SHA-256 leaf hash."""
        data = f"LEAF:{self.canonicalize()}"
        self.hash = hashlib.sha256(data.encode()).hexdigest()
        return self.hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "summary": self.summary,
            "targetRef": self.target_ref,
            "hash": self.hash,
        }


def _hash_pair(left: str, right: str) -> str:
    """Hash two child nodes to produce parent node."""
    data = f"NODE:{left}:{right}"
    return hashlib.sha256(data.encode()).hexdigest()


class MerkleTree:
    """Incremental Merkle tree for tamper-proof audit proofs."""

    def __init__(self):
        self.leaves: List[AuditLeaf] = []
        self.leaf_hashes: List[str] = []
        self.root_hash: str = ""

    def append_leaf(self, leaf: AuditLeaf) -> Dict[str, str]:
        """Append a leaf and recompute root."""
        leaf_hash = leaf.compute_hash()
        self.leaves.append(leaf)
        self.leaf_hashes.append(leaf_hash)
        self.root_hash = self._compute_root(self.leaf_hashes)
        return {"leaf_hash": leaf_hash, "new_root": self.root_hash}

    def _compute_root(self, hashes: List[str]) -> str:
        """Compute Merkle root from leaf hashes."""
        if not hashes:
            return ""
        if len(hashes) == 1:
            return hashes[0]

        level = list(hashes)
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    next_level.append(_hash_pair(level[i], level[i + 1]))
                else:
                    next_level.append(_hash_pair(level[i], level[i]))
            level = next_level
        return level[0]

    def verify_integrity(self) -> Dict[str, Any]:
        """Recompute root from all leaves and compare with stored root."""
        recomputed_hashes = []
        mismatched = []

        for i, leaf in enumerate(self.leaves):
            recomputed = leaf.compute_hash()
            recomputed_hashes.append(recomputed)
            if recomputed != self.leaf_hashes[i]:
                mismatched.append(i)

        computed_root = self._compute_root(recomputed_hashes)
        return {
            "valid": computed_root == self.root_hash and len(mismatched) == 0,
            "expected_root": self.root_hash,
            "computed_root": computed_root,
            "mismatched_leaves": mismatched,
            "total_leaves": len(self.leaves),
        }

    def get_state(self) -> Dict[str, Any]:
        """Export current ledger state."""
        return {
            "leaves": [l.to_dict() for l in self.leaves],
            "root_hash": self.root_hash,
            "tree_size": len(self.leaves),
            "last_updated": self.leaves[-1].timestamp if self.leaves else None,
        }


# ─── Singleton Instance ────────────────────────────────────────────────
_instance: Optional[MerkleTree] = None


def get_merkle_tree() -> MerkleTree:
    global _instance
    if _instance is None:
        _instance = MerkleTree()
    return _instance


def audit_log(action: str, actor: str, summary: str, target_ref: str = "") -> Dict[str, str]:
    """Quick helper to append an audit entry."""
    tree = get_merkle_tree()
    leaf = AuditLeaf(action=action, actor=actor, summary=summary, target_ref=target_ref)
    return tree.append_leaf(leaf)
