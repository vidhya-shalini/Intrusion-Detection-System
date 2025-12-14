import numpy as np

def calculate_risk(ml_prob, alert):
    """
    Calculate risk score as percentage (0-100%)
    Combines ML probability + rule-based alert
    """
    base_score = ml_prob * 100  # ML confidence
    if alert == 1:
        risk_score = min(100, base_score + 20)  # boost if rule triggered
    else:
        risk_score = base_score
    return int(risk_score)

def explain_features(model, feature_names, top_n=3):
    """
    Returns top N features contributing to prediction.
    Uses Random Forest feature importances.
    """
    importances = model.feature_importances_
    feature_importance_list = list(zip(feature_names, importances))
    feature_importance_list.sort(key=lambda x: x[1], reverse=True)
    return feature_importance_list[:top_n]
