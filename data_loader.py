import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

# ----------------- REQUIRED FEATURES -----------------
FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Packet Length Mean', 'Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count'
]

LABEL_COLUMN = 'Label'  # Must exist in dataset

# ----------------- LOAD & PREPROCESS FUNCTION -----------------
def load_data(csv_path_or_df):
    """
    Loads CSV (or dataframe) and returns:
    X_scaled, y, original_df, scaler
    """
    # Load dataframe
    if isinstance(csv_path_or_df, str):
        df = pd.read_csv(csv_path_or_df)
    else:
        df = csv_path_or_df.copy()

    # ----------------- CLEAN COLUMN NAMES -----------------
    df.columns = df.columns.str.strip()           # Remove leading/trailing spaces
    df.columns = df.columns.str.replace("_", " ") # Replace underscores with spaces
    df.columns = df.columns.str.title()           # Capitalize words

    # ----------------- CHECK REQUIRED FEATURES -----------------
    missing_features = [f for f in FEATURES + [LABEL_COLUMN] if f not in df.columns]
    if missing_features:
        raise ValueError(f"Missing required columns in dataset: {missing_features}")

    # ----------------- HANDLE MISSING / INF VALUES -----------------
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=FEATURES + [LABEL_COLUMN], inplace=True)

    # ----------------- EXTRACT FEATURES & LABELS -----------------
    X = df[FEATURES]
    y = df[LABEL_COLUMN].apply(lambda x: 0 if str(x).upper() in ['BENIGN', 'NORMAL'] else 1)

    # ----------------- SCALE FEATURES -----------------
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y, df, scaler
