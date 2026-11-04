"""``python -m aegis.audit verify [--audit PATH] [--all]`` — walk the hash chain and report the first break.

``python -m aegis.audit retire --segments N`` — retention: drop the N oldest rotated segments after verifying them.
A retention checkpoint (``<audit>.retention``, HMAC-signed with ``AEGIS_AUDIT_KEY``, else ``AEGIS_DECISION_KEY`` —
never the console token) records the hash the kept chain starts from and the anchors that went with the dropped rows,
so ``verify --all`` stays meaningful. ``retire`` refuses without a key; ``verify`` with a checkpoint but no key exits 3
("unverifiable: no key"), never 0. Never delete segments by hand: verification would report the log as truncated.

``python -m aegis.audit resign`` — key rotation: put the new key in ``AEGIS_AUDIT_KEY`` and the old one in
``AEGIS_AUDIT_KEY_PREVIOUS`` (comma-separated; ``console:<token>`` for a checkpoint signed before round 8 with the
console-token-derived key), then resign. ``--trust-unverified`` signs an unsigned legacy checkpoint once (recorded).
"""
