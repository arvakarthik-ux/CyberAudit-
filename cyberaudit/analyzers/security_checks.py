from cyberaudit.models.finding import Finding


def run_checks(facts):
    findings = []
    # Firewall checks
    fw = facts.get("firewall")
    if isinstance(fw, dict) and fw.get("error"):
        findings.append(Finding(
            id="FIREWALL-ERR",
            title="Could not read firewall status",
            severity="LOW",
            category="Firewall",
            evidence=fw.get("error"),
            recommendation="Run as Administrator or check PowerShell availability."
        ))
    else:
        # fw may be list or dict
        profiles = fw if isinstance(fw, list) else [fw]
        for p in profiles:
            name = p.get("Name") if isinstance(p, dict) else str(p)
            enabled = p.get("Enabled") if isinstance(p, dict) else None
            if enabled in (False, "False", 0):
                findings.append(Finding(
                    id=f"FIREWALL-{name.upper()}",
                    title=f"Firewall profile {name} is disabled",
                    severity="HIGH",
                    category="Firewall",
                    evidence=f"Profile {name} Enabled: {enabled}",
                    recommendation=f"Enable the Windows Firewall profile: {name}"
                ))

    # Defender checks
    df = facts.get("defender")
    if isinstance(df, dict) and df.get("error"):
        findings.append(Finding(
            id="DEF-ERR",
            title="Could not read Microsoft Defender status",
            severity="LOW",
            category="Defender",
            evidence=df.get("error"),
            recommendation="Run as Administrator or check PowerShell availability."
        ))
    else:
        # df may be dict
        service_enabled = df.get("AMServiceEnabled") if isinstance(df, dict) else None
        rt = df.get("RealTimeProtectionEnabled") if isinstance(df, dict) else None
        if service_enabled in (False, "False", 0):
            findings.append(Finding(
                id="DEF-001",
                title="Microsoft Defender service is disabled",
                severity="HIGH",
                category="Defender",
                evidence=f"AMServiceEnabled: {service_enabled}",
                recommendation="Enable Microsoft Defender service or install a supported AV solution."
            ))
        if rt in (False, "False", 0):
            findings.append(Finding(
                id="DEF-002",
                title="Real-time protection is disabled",
                severity="HIGH",
                category="Defender",
                evidence=f"RealTimeProtectionEnabled: {rt}",
                recommendation="Enable real-time protection in Microsoft Defender."
            ))

    # Network checks: listening ports — deduplicate by (port, pid, local)
    net = facts.get("network", {})
    listening = net.get("listening", []) if isinstance(net, dict) else []
    seen = set()
    for l in listening:
        try:
            port = int(l.get("port"))
        except Exception:
            continue
        key = (port, str(l.get("pid")), str(l.get("local")))
        if key in seen:
            continue
        seen.add(key)

        # RDP
        if port == 3389:
            findings.append(Finding(
                id="NET-3389",
                title="RDP port is listening",
                severity="HIGH",
                category="Network",
                evidence=f"Port {port} (pid {l.get('pid')}) is listening on {l.get('local')}",
                recommendation="If RDP is not required, disable the service or restrict it via firewall."
            ))
        # SMB
        if port in (139, 445):
            findings.append(Finding(
                id=f"NET-{port}",
                title=f"SMB-related port {port} is listening",
                severity="MEDIUM",
                category="Network",
                evidence=f"Port {port} (pid {l.get('pid')}) is listening",
                recommendation="Ensure SMB is required and patched; consider limiting exposure."
            ))

    return findings
