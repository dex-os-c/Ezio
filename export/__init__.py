"""
export — Phase 5 intelligence export module.

Re-exports the public API from stix, misp, sigma, yara_export, snort_export,
and ioc_package sub-modules.
"""

from export.stix import (
    bundle_to_dict,
    bundle_to_json,
    investigation_to_stix_bundle,
)
from export.misp import (
    investigation_to_misp_event,
    misp_event_to_json,
)
from export.sigma import (
    entities_to_sigma_rules,
    export_sigma_rules,
    render_sigma_rules,
    sigma_rule_to_yaml,
)
from export.yara_export import (
    generate_yara_rules,
)
from export.snort_export import (
    generate_snort_rules,
    SID_RANGE_MIN as SNORT_SID_BASE,
    SID_RANGE_MAX as SNORT_SID_END,
)
from export.ioc_package import (
    build_package_filename,
    generate_ioc_package,
    redact_credential,
)

__all__ = [
    # stix
    "investigation_to_stix_bundle",
    "bundle_to_json",
    "bundle_to_dict",
    # misp
    "investigation_to_misp_event",
    "misp_event_to_json",
    # sigma
    "entities_to_sigma_rules",
    "sigma_rule_to_yaml",
    "render_sigma_rules",
    "export_sigma_rules",
    # yara
    "generate_yara_rules",
    # snort / suricata
    "generate_snort_rules",
    "SNORT_SID_BASE",
    "SNORT_SID_END",
    # ioc package
    "generate_ioc_package",
    "build_package_filename",
    "redact_credential",
]
