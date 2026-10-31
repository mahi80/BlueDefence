"""Persistence sinks: ship hash-chained SOC artifacts to the ACP dashboard (roadmap Phase 0.3)."""

from .dashboard import DashboardSink, sink_from_env

__all__ = ["DashboardSink", "sink_from_env"]
