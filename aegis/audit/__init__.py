"""``python -m aegis.audit verify [--audit PATH] [--all]`` — walk the hash chain and report the first break.

``python -m aegis.audit retire --segments N`` — retention: drop the N oldest rotated segments after verifying them.
A retention checkpoint (``<audit>.retention``, HMAC-signed when AEGIS_DECISION_KEY / AEGIS_CONSOLE_TOKEN is set)
records the hash the kept chain starts from and the anchors that went with the dropped rows, so ``verify --all``
stays meaningful. Never delete segments by hand: verification would report the log as truncated.
"""
