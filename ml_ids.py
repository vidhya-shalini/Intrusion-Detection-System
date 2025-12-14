from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

def train_model(X, y):
    """
    Train Random Forest classifier on the dataset.
    Returns trained model.
    """
    model = RandomForestClassifier(
        n_estimators=100, 
        max_depth=10, 
        random_state=42
    )
    model.fit(X, y)
    return model

def evaluate_model(model, X, y):
    """
    Evaluate trained model and print metrics.
    """
    y_pred = model.predict(X)
    print("Accuracy:", accuracy_score(y, y_pred))
    print(classification_report(y, y_pred))

def predict_proba(model, X):
    """
    Predict attack probability (0-1) for each row
    """
    return model.predict_proba(X)[:, 1]  # probability of class 1 (attack)
