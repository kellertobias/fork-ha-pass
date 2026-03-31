"""Add passkeys and passkey_opted_out column

Revision ID: 003
Revises: 002
Create Date: 2026-03-31
"""
from typing import Sequence, Union

from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add passkey_opted_out column to tokens
    try:
        op.execute("ALTER TABLE tokens ADD COLUMN passkey_opted_out BOOLEAN DEFAULT 0")
    except Exception:
        pass # In case it already exists

    # Create passkeys table
    op.execute("""
        CREATE TABLE passkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
            credential_id TEXT NOT NULL UNIQUE,
            public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_passkeys_token_id ON passkeys(token_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS passkeys")
