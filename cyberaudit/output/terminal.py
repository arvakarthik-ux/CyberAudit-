def print_result(result: dict):
    system = result.get("system", {})
    findings = result.get("findings", [])
    score = result.get("score", 0)

    print("\nCyberAudit Windows Security Assessment")
    print(f"Host: {system.get('hostname') or system.get('node')}")
    ts = result.get('timestamp')
    if ts:
        print(f"Scan time (UTC): {ts}")
    sid = result.get('scan_id')
    if sid:
        print(f"Scan ID: {sid}")
    print(f"Scan score: {score}/100")
    print("")

    if not findings:
        print("No findings. System appears healthy (based on implemented checks).\n")
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(f.get('severity', 'LOW').upper(), 3))

    for f in findings_sorted:
        sev = f.get('severity')
        title = f.get('title')
        evidence = f.get('evidence')
        rec = f.get('recommendation')
        print(f"[{sev}] {title}")
        print(f"  Evidence: {evidence}")
        print(f"  Recommendation: {rec}\n")
