from rule_ids import rule_based_alert

def hybrid_decision(flow, ml_prob, ml_threshold=0.7):
    """
    Combines ML prediction and rule-based detection.
    Returns final alert (0/1) and reason text.
    """
    # ML decision
    ml_alert = 1 if ml_prob > ml_threshold else 0
    ml_reason = f"ML-based anomaly detected (prob={ml_prob:.2f})"

    # Rule-based decision
    rule_alert, rule_reason = rule_based_alert(flow)

    # Combine: alert if either ML or rule triggers
    if ml_alert and rule_alert:
        final_alert = 1
        reason = f"{ml_reason} + {rule_reason}"
    elif ml_alert:
        final_alert = 1
        reason = ml_reason
    elif rule_alert:
        final_alert = 1
        reason = rule_reason
    else:
        final_alert = 0
        reason = "No alerts"

    return final_alert, reason
