import pandas as pd
import os

FEEDBACK_FILE = r"feedback_log.csv"  # path to save feedback

def save_feedback(df_feedback):
    """
    Save user feedback to CSV.
    df_feedback: DataFrame with columns ['Flow_ID', 'Hybrid_Alert', 'Feedback']
    """
    if os.path.exists(FEEDBACK_FILE):
        existing = pd.read_csv(FEEDBACK_FILE)
        combined = pd.concat([existing, df_feedback], ignore_index=True)
    else:
        combined = df_feedback
    combined.to_csv(FEEDBACK_FILE, index=False)
