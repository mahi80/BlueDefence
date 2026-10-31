"""Roadmap 1.5 — shadow-mode comparison: receipts vs. what the SOC decided.

`python -m aegis.shadow report --dashboard` (or `--receipts <jsonl> --audit <jsonl>`)
prints, per (connector, action type, mode), how many "would have done" receipts
exist, how many a human agreed or disagreed with, and whether the group meets the
thresholds to flip live. See `report.py`.
"""

from .report import ActionRequests, Group, ShadowReport, Thresholds, build_report, render_text, to_json

__all__ = ["ActionRequests", "Group", "ShadowReport", "Thresholds", "build_report", "render_text", "to_json"]
