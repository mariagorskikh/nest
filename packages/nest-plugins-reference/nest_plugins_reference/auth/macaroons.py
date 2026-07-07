# SPDX-License-Identifier: Apache-2.0
"""Macaroons-style delegatable capability tokens with cascading revocation."""

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from nest_core.types import AgentId


class AuthError(Exception):
    """Base exception for auth failures."""
    pass

class RevokedAncestorError(AuthError):
    pass

class ScopeEscalationError(AuthError):
    pass

class AudienceConfusionError(AuthError):
    pass

class TokenExpiredError(AuthError):
    pass


class MacaroonAuth:
    """
    Delegatable auth token system using HMAC chaining.
    """
    def __init__(self, secret: str = "default-macaroon-secret"):
        self.secret = secret.encode()
        self._revoked: set[str] = set()

    def _sign(self, key: bytes, msg: bytes) -> str:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    def issue(self, audience: AgentId, scopes: list[str], ttl: float) -> str:
        """Issue a root capability token."""
        now = time.time()
        claims = {
            "jti": str(uuid.uuid4()),
            "aud": str(audience),
            "scopes": scopes,
            "exp": now + ttl,
            "iss": "root"
        }
        claims_b64 = base64.b64encode(json.dumps(claims).encode()).decode()
        sig = self._sign(self.secret, claims_b64.encode())
        
        # Token is a JSON list of layers, base64 encoded
        layer = {"claims": claims_b64, "sig": sig}
        return base64.b64encode(json.dumps([layer]).encode()).decode()

    def delegate(
        self, parent_token: str, audience: AgentId, scopes_subset: list[str], ttl: float
    ) -> str:
        """
        Delegate a subset of capabilities to a new child token.
        Child's signature is chained to the parent's signature.
        """
        layers = json.loads(base64.b64decode(parent_token).decode())
        parent_claims = json.loads(base64.b64decode(layers[-1]["claims"]).decode())
        
        # 1. Attack Vector: Scope Escalation Prevention
        parent_scopes = set(parent_claims.get("scopes", []))
        if not set(scopes_subset).issubset(parent_scopes):
            raise ScopeEscalationError("Child requests broader scopes than parent")
        
        # 2. Enforce Time Bounds (Child TTL <= Parent TTL)
        now = time.time()
        parent_exp = parent_claims.get("exp", 0)
        child_exp = now + ttl
        if child_exp > parent_exp:
            child_exp = parent_exp
            
        new_claims = {
            "jti": str(uuid.uuid4()),
            "aud": str(audience),
            "scopes": scopes_subset,
            "exp": child_exp,
            "iss": parent_claims["aud"]
        }
        new_claims_b64 = base64.b64encode(json.dumps(new_claims).encode()).decode()
        
        # HMAC chaining: sign new claims using parent's signature as the key
        parent_sig = layers[-1]["sig"]
        new_sig = self._sign(parent_sig.encode(), new_claims_b64.encode())
        
        layers.append({"claims": new_claims_b64, "sig": new_sig})
        return base64.b64encode(json.dumps(layers).encode()).decode()

    def verify(self, token: str, audience: AgentId) -> dict[str, Any]:
        """
        Verify a token chain. Validates signatures, expiration, revocation, and audience.
        """
        try:
            layers = json.loads(base64.b64decode(token).decode())
        except (ValueError, TypeError):
            raise AuthError("Malformed token")

        current_key = self.secret
        now = time.time()
        
        for layer in layers:
            claims_b64 = layer["claims"]
            
            # Verify signature chain
            expected_sig = self._sign(current_key, claims_b64.encode())
            if not hmac.compare_digest(expected_sig, layer["sig"]):
                raise AuthError("Signature invalid or chain broken")
            
            claims = json.loads(base64.b64decode(claims_b64).decode())
            
            # 1. Check expiration
            if claims.get("exp", 0) < now:
                raise TokenExpiredError("A token in the chain has expired")
            
            # 2. Check cascading revocation
            if claims["jti"] in self._revoked:
                raise RevokedAncestorError(f"Token ancestor {claims['jti']} was revoked")
            
            current_key = expected_sig.encode()
            
        # 3. Attack Vector: Audience Confusion Prevention
        final_claims = json.loads(base64.b64decode(layers[-1]["claims"]).decode())
        if final_claims.get("aud") != str(audience):
            raise AudienceConfusionError("Token presented to the wrong audience")
            
        return final_claims

    def revoke(self, token: str) -> None:
        """Revoke a specific token layer, automatically cascading to descendants."""
        layers = json.loads(base64.b64decode(token).decode())
        final_claims = json.loads(base64.b64decode(layers[-1]["claims"]).decode())
        self._revoked.add(final_claims["jti"])