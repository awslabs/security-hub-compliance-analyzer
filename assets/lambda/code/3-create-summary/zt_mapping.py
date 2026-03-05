"""
DoD Zero Trust Activity to NIST SP 800-53 Rev. 5 Control Mapping

Maps DoD Zero Trust Capability Execution Roadmap activities to the
NIST 800-53 controls that Security Hub CSPM evaluates. This enables
SHCA to generate a Zero Trust evidence report showing which ZT
activities have automated compliance evidence.

Reference:
- DoD Zero Trust Strategy (2022)
- DoD Zero Trust Capability Execution Roadmap
- NIST SP 800-207 Zero Trust Architecture
- NIST SP 800-53 Rev. 5
"""

ZT_PILLAR_COLORS = {
    "User": "#2e86c1",
    "Device": "#8e44ad",
    "Network": "#27ae60",
    "App/Workload": "#d35400",
    "Data": "#c0392b",
    "Visibility": "#2c3e50",
    "Automation": "#16a085",
}

# Each entry: (activity_id, pillar, level, description, [nist_controls])
ZT_ACTIVITIES = [
    # === USER PILLAR ===
    ("User.1.1", "User", "Target", "MFA for enterprise identity authentication",
     ["IA-2(1)", "IA-2(2)", "IA-2(6)"]),
    ("User.1.2", "User", "Target", "MFA for privileged user authentication",
     ["IA-2(1)", "AC-6(10)", "AC-6(2)"]),
    ("User.1.3", "User", "Target", "Credential lifecycle management",
     ["IA-5(1)", "AC-2(3)", "AC-2(1)"]),
    ("User.2.1", "User", "Target", "Least privilege access enforcement",
     ["AC-6", "AC-3", "AC-5"]),
    ("User.2.2", "User", "Target", "Role-based access control",
     ["AC-3(7)", "AC-3(15)", "AC-6(9)"]),
    ("User.3.1", "User", "Target", "Continuous user activity monitoring",
     ["AU-6(1)", "AU-6(3)", "SI-4(5)"]),
    ("User.4.1", "User", "Advanced", "Identity federation and governance",
     ["AC-2", "IA-2", "IA-5"]),
    ("User.5.1", "User", "Advanced", "Privileged access management",
     ["AC-6(10)", "AC-6(2)", "AC-2(4)"]),

    # === DEVICE PILLAR ===
    ("Device.1.1", "Device", "Target", "Device inventory and compliance validation",
     ["CM-8", "CM-8(1)", "CM-8(3)"]),
    ("Device.1.2", "Device", "Target", "Automated patch management",
     ["SI-2", "SI-2(2)", "SI-2(3)"]),
    ("Device.2.1", "Device", "Target", "Device health and posture assessment",
     ["CM-8(2)", "CM-2", "CM-2(2)"]),
    ("Device.3.1", "Device", "Target", "Endpoint detection and response",
     ["SI-4", "SI-4(1)", "SI-4(5)"]),
    ("Device.4.1", "Device", "Target", "Configuration management and hardening",
     ["CM-7", "CM-6(1)", "CM-3"]),
    ("Device.5.1", "Device", "Advanced", "Instance metadata and runtime hardening",
     ["CM-7", "SC-7(5)", "AC-3"]),

    # === NETWORK PILLAR ===
    ("Net.1.1", "Network", "Target", "Network micro-segmentation",
     ["SC-7", "SC-7(21)", "AC-4"]),
    ("Net.1.2", "Network", "Target", "Default deny network policy",
     ["SC-7(5)", "AC-4", "SC-7(11)"]),
    ("Net.1.3", "Network", "Target", "Encrypted network connections",
     ["SC-8", "SC-8(1)", "SC-8(2)", "SC-23", "SC-23(3)"]),
    ("Net.2.1", "Network", "Target", "Network traffic monitoring and logging",
     ["AU-2", "AU-12", "AC-4(26)", "SI-4(20)"]),
    ("Net.3.1", "Network", "Target", "Restrict public network exposure",
     ["AC-21", "SC-7(3)", "SC-7(20)"]),
    ("Net.4.1", "Network", "Target", "Web application and API protection",
     ["SC-7(10)", "AC-4(21)", "SI-7(8)"]),
    ("Net.5.1", "Network", "Advanced", "VPC endpoint private connectivity",
     ["SC-7(9)", "CA-9(1)", "SC-7(16)"]),
    ("Net.5.2", "Network", "Advanced", "TLS policy enforcement",
     ["SC-12(3)", "SC-13", "SC-23(5)"]),

    # === APPLICATION & WORKLOAD PILLAR ===
    ("App.1.1", "App/Workload", "Target", "Application access authorization",
     ["AC-3", "AC-3(7)", "AC-4"]),
    ("App.1.2", "App/Workload", "Target", "API security and logging",
     ["AU-2", "AU-12", "AC-4(26)"]),
    ("App.2.1", "App/Workload", "Target", "Container and workload isolation",
     ["SC-7", "AC-4", "CM-7"]),
    ("App.3.1", "App/Workload", "Target", "Software supply chain security",
     ["SA-3", "SI-7(6)", "SA-11(1)"]),
    ("App.4.1", "App/Workload", "Target", "Application runtime protection",
     ["SI-2(3)", "SA-15(2)", "SA-15(8)"]),
    ("App.5.1", "App/Workload", "Advanced", "Secure development lifecycle",
     ["SA-3", "SA-11(1)", "SA-11(6)"]),

    # === DATA PILLAR ===
    ("Data.1.1", "Data", "Target", "Data at rest encryption",
     ["SC-28", "SC-28(1)", "SC-13"]),
    ("Data.1.2", "Data", "Target", "Data in transit encryption",
     ["SC-8", "SC-8(1)", "SC-12(3)", "SC-23"]),
    ("Data.2.1", "Data", "Target", "Data access controls and classification",
     ["AC-3", "AC-21", "AC-4"]),
    ("Data.3.1", "Data", "Target", "Data backup and recovery",
     ["CP-9", "CP-10", "CP-6", "CP-6(1)"]),
    ("Data.3.2", "Data", "Target", "Data resilience and availability",
     ["CP-6(2)", "CP-2", "CP-2(2)", "SC-36"]),
    ("Data.4.1", "Data", "Target", "Data integrity protection",
     ["SI-7(1)", "SI-7(3)", "SI-7(7)", "AU-9"]),
    ("Data.5.1", "Data", "Target", "Cryptographic key management",
     ["SC-12", "SC-12(2)", "SC-28(3)"]),

    # === VISIBILITY & ANALYTICS PILLAR ===
    ("VA.1.1", "Visibility", "Target", "Centralized security logging",
     ["AU-2", "AU-3", "AU-12", "AU-6(3)"]),
    ("VA.1.2", "Visibility", "Target", "Log integrity and protection",
     ["AU-9", "AU-9(2)", "SI-7(1)"]),
    ("VA.1.3", "Visibility", "Target", "Log retention and archival",
     ["AU-11", "SI-12"]),
    ("VA.2.1", "Visibility", "Target", "Continuous security monitoring",
     ["CA-7", "SI-4", "SI-4(5)"]),
    ("VA.2.2", "Visibility", "Target", "Security event correlation and analysis",
     ["AU-6(1)", "AU-6(4)", "AU-6(5)", "SI-4(2)"]),
    ("VA.3.1", "Visibility", "Target", "Automated alerting and notification",
     ["SI-4(12)", "IR-4(1)", "IR-4(5)"]),
    ("VA.4.1", "Visibility", "Advanced", "Threat detection and intelligence",
     ["SI-3(8)", "SI-4(4)", "SI-4(13)", "SI-4(22)"]),
    ("VA.5.1", "Visibility", "Advanced", "Security posture assessment",
     ["CA-7", "SI-20", "SA-8(19)", "SA-8(21)"]),

    # === AUTOMATION & ORCHESTRATION PILLAR ===
    ("AO.1.1", "Automation", "Target", "Automated compliance assessment",
     ["CA-7", "CM-6(1)", "CM-3"]),
    ("AO.2.1", "Automation", "Target", "Automated vulnerability remediation",
     ["SI-2", "SI-2(2)", "SI-2(4)", "SI-2(5)"]),
    ("AO.3.1", "Automation", "Target", "Automated resilience and scaling",
     ["CP-10", "CP-2(2)", "SC-5(2)", "SI-13(5)"]),
    ("AO.4.1", "Automation", "Target", "Configuration drift detection",
     ["CM-3(6)", "CM-8", "CM-8(3)"]),
    ("AO.5.1", "Automation", "Advanced", "Resource deletion protection",
     ["SC-5(2)", "CP-9", "SI-13"]),
]


def get_zt_activity_for_nist_control(nist_control_id):
    """Return list of ZT activities that map to a given NIST control."""
    results = []
    for activity_id, pillar, level, desc, nist_controls in ZT_ACTIVITIES:
        if nist_control_id in nist_controls:
            results.append({
                "activity_id": activity_id,
                "pillar": pillar,
                "level": level,
                "description": desc,
            })
    return results


def get_all_nist_controls_for_activity(activity_id):
    """Return the NIST controls mapped to a ZT activity."""
    for aid, pillar, level, desc, nist_controls in ZT_ACTIVITIES:
        if aid == activity_id:
            return nist_controls
    return []
