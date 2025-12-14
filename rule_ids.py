def rule_based_alert(flow):
    """
    Simple rules to detect suspicious traffic.
    Returns alert (0 or 1) and reason text.
    """
    # Example rules:
    # Rule 1: High traffic rate (DDoS)
    if flow.get("Flow Packets/s", 0) > 1000:
        return 1, "High traffic rate (possible DDoS)"

    # Rule 2: Too many SYN flags (port scanning)
    if flow.get("SYN Flag Count", 0) > 50:
        return 1, "High SYN flag count (possible port scan)"

    # Rule 3: Abnormal packet size
    if flow.get("Packet Length Mean", 0) > 1500:
        return 1, "Abnormal packet length"

    # Add more rules as needed

    return 0, "No signature-based alerts"
