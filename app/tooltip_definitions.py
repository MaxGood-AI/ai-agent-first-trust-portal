"""Tooltip definitions for portal table headers."""

TOOLTIPS = {
    # Controls page
    "control_category": "The Trust Services Criteria (TSC) category: Security, Availability, Confidentiality, Privacy, or Processing Integrity.",
    "control_state": "Whether this control is actively implemented. 'Adopted' means the control is in place and operational.",
    "maturity_level": "Implementation maturity on a 1-3 scale. 1 = basic/initial, 2 = defined/repeatable, 3 = optimized/measured.",
    "frequency": "How often this control is assessed: monthly, quarterly, or annually.",

    # Tests / Status page
    "test_status": "The most recent test result. Passed = control verified working. Failed = issue found. Pending = not yet tested. N/A = not applicable.",
    "evidence_status": "Whether compliance evidence for this test is current. Missing = no evidence submitted. Submitted = evidence on file. Outdated = evidence older than the review period. Due Soon = evidence expiring soon.",

    # Systems page
    "system_risk_score": "A calculated value (0-100) representing the combined risk based on data sensitivity, exposure, and criticality. Higher scores indicate greater risk.",
    "system_type": "Whether this system is an application (software), infrastructure (hosting/networking), or both.",
    "system_provider": "The vendor or team that provides and maintains this system.",

    # Vendors page
    "vendor_status": "The current vendor relationship status: Active (in use), Inactive (no longer used), Under Review (being evaluated).",
    "is_subprocessor": "Whether this vendor processes personal data on behalf of the organization. Subprocessors must be disclosed under GDPR and PIPEDA.",
    "vendor_classification": "The sensitivity levels of data shared with this vendor.",

    # Risks page
    "risk_score": "A calculated value combining likelihood (1-5) and impact (1-5) scores. Higher scores indicate greater risk and higher remediation priority.",
    "risk_likelihood": "How likely this risk is to occur, on a scale of 1 (rare) to 5 (almost certain).",
    "risk_impact": "The potential business impact if this risk materializes, on a scale of 1 (minimal) to 5 (catastrophic).",
    "risk_treatment": "The chosen approach: Mitigate (reduce), Accept (acknowledge), Transfer (insure/outsource), or Avoid (eliminate the activity).",
    "risk_status": "Current state: Open (active risk), Mitigated (controls in place), Accepted (risk acknowledged), Closed (no longer relevant).",

    # Policies page
    "policy_category": "The Trust Services Criteria (TSC) area this policy addresses.",
    "policy_version": "The current version number. Incremented when the policy is materially updated.",
}
