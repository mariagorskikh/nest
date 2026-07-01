# SPDX-License-Identifier: Apache-2.0
"""Auth layer interface: authentication and authorization.

Example::

    class MyAuth(Auth):
        async def issue(self, subject, scopes):
            return Token(jwt.encode({"sub": subject, "scopes": scopes}, key))
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nest_core.types import AgentId, AuthContext, Token


@runtime_checkable
class Auth(Protocol):
    """Authentication and authorization for agents.

    Example::

        auth: Auth = JwtAuth(identity)
        token = await auth.issue(AgentId("a1"), ["read", "write"])
    """

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue an auth token for a subject with given scopes.

        Example::

            token = await auth.issue(AgentId("a1"), ["read"])
        """
        ...

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token and return its auth context.

        Example::

            ctx = await auth.verify(token, AgentId("a1"))
        """
        ...

    async def revoke(self, token: Token) -> None:
        """Revoke a previously issued token.

        Example::

            await auth.revoke(token)
        """
        ...
