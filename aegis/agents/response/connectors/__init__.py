"""Enforcement connectors — turn a ResponseAgent decision into a vendor action (roadmap Phase 1).

Phase 1.1 is the contract every vendor connector implements plus the
registry the ResponseAgent dispatches through:

    Connector.apply(action)     → Receipt   (idempotent, TTL'd, dry-run aware)
    Connector.rollback(receipt) → Receipt
    Connector.renew(receipt)    → Receipt
    ConnectorRegistry           action_type → connector, expiry sweeper

Vendor connectors subclass ``Connector`` and implement ``_do_apply`` /
``_do_rollback`` only. Phase 1.2 ships ``waf.py`` (Imperva Cloud WAF, F5
BIG-IP AWAF) and ``soar.py`` (Cortex XSOAR, Sentinel playbooks), each
talking through an injectable ``transport``; ``cloud_waf.py`` adds Cloudflare, AWS WAF and Azure WAF;
``mock_vendor.py`` / ``mock_cloud_waf.py`` hold
stateful in-process fakes of those tenants (``AEGIS_*_VENDOR=mock``).
"""

from .base import (
    Connector, ConnectorError, ConnectorRegistry, LoggingConnector, Receipt, STATUS_REFUSED,
    enforcement_mode, registry_from_env,
)
from .soar import SentinelPlaybookConnector, XsoarConnector, parse_playbook_map, soar_from_env
from .cloud_waf import AwsWafConnector, AzureWafConnector, CloudflareWafConnector
from .waf import F5WafConnector, ImpervaWafConnector, waf_from_env
from .edr import (CrowdStrikeConnector, DefenderConnector, SentinelOneConnector, TrendVisionOneConnector,
                  crowdstrike_from_env)
from .firewall import FeedConnector, FortiGateConnector, PanosConnector, feed_from_env, firewall_from_env
from .payhold import PaymentHoldConnector, payhold_from_env
from .identity import ActiveDirectoryConnector, CyberArkConnector, EntraConnector, idp_from_env, pam_from_env
from .swg import ZscalerConnector, zscaler_from_env

__all__ = [
    "Connector", "ConnectorError", "ConnectorRegistry", "LoggingConnector", "Receipt", "STATUS_REFUSED",
    "enforcement_mode", "registry_from_env",
    "ImpervaWafConnector", "F5WafConnector", "waf_from_env",
    "CloudflareWafConnector", "AwsWafConnector", "AzureWafConnector",
    "XsoarConnector", "SentinelPlaybookConnector", "parse_playbook_map", "soar_from_env",
    "CrowdStrikeConnector", "crowdstrike_from_env", "ZscalerConnector", "zscaler_from_env",
    "DefenderConnector", "SentinelOneConnector", "PanosConnector", "FortiGateConnector", "firewall_from_env",
    "EntraConnector", "CyberArkConnector", "idp_from_env", "pam_from_env",
    "PaymentHoldConnector", "payhold_from_env",
    "TrendVisionOneConnector", "FeedConnector", "feed_from_env", "ActiveDirectoryConnector",
]
