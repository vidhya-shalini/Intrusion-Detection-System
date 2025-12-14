import streamlit as st
import pandas as pd
import numpy as np

from data_loader import load_data
from ml_ids import train_model, predict_proba
from hybrid_ids import hybrid_decision
from risk_explain import calculate_risk, explain_features
from feedback import save_feedback

# ----------------- PAGE CONFIG -----------------
st.set_page_config(
    page_title="Hybrid IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("## 🛡️ Hybrid IDS Dashboard", unsafe_allow_html=True)
st.write("ML + Rule-based IDS with Explainable Alerts & Feedback")

# ----------------- SIDEBAR -----------------
source_option = st.sidebar.radio(
    "Choose data source:",
    ("Sample dataset", "Upload CSV")
)

if source_option == "Sample dataset":
    df_full = pd.read_csv("cicids2017_sample.csv", nrows=5000)
    input_df = df_full.sample(500, random_state=42)
else:
    uploaded = st.sidebar.file_uploader("Upload CSV", type=["csv"])
    if uploaded is not None:
        input_df = pd.read_csv(uploaded)
    else:
        st.warning("Upload a CSV file or choose sample dataset.")
        st.stop()

# Clean columns
input_df.columns = input_df.columns.str.strip().str.replace("_"," ").str.title()

# ----------------- INPUT PREVIEW -----------------
st.subheader("🔍 Input Data Preview")
st.dataframe(input_df.head(), use_container_width=True)

# ----------------- RUN ANALYSIS -----------------
if st.button("🚀 Run IDS Analysis"):
    st.info("Running hybrid IDS analysis...")

    # Step 1: Preprocess
    X, y, raw_df, scaler = load_data(input_df)

    # Step 2: ML Model
    model = train_model(X, y)
    attack_probs = predict_proba(model, X)
    raw_df["ML_Prob"] = attack_probs

    # Step 3: Hybrid IDS
    alerts, reasons = [], []
    for i, row in raw_df.iterrows():
        alert, reason = hybrid_decision(row, row["ML_Prob"])
        alerts.append(alert)
        reasons.append(reason)
    raw_df["Hybrid_Alert"] = alerts
    raw_df["Reason"] = reasons

    # Step 4: Risk Score & Explanation
    risk_scores, top_features_list = [], []
    for i, row in raw_df.iterrows():
        risk = calculate_risk(row["ML_Prob"], row["Hybrid_Alert"])
        risk_scores.append(risk)
        top_features_list.append(explain_features(model, FEATURES))
    raw_df["RiskScore(%)"] = risk_scores
    raw_df["TopFeatures"] = top_features_list

    # ----------------- SUMMARY METRICS -----------------
    st.markdown("### 📊 Summary Metrics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Flows", len(raw_df))
    col2.metric("Predicted Attacks", int(raw_df["Hybrid_Alert"].sum()))
    col3.metric("Predicted Benign", int(len(raw_df)-raw_df["Hybrid_Alert"].sum()))

    # ----------------- DISTRIBUTION -----------------
    st.markdown("### 📈 Prediction Distribution")
    st.bar_chart(raw_df["Hybrid_Alert"].map({0:"BENIGN",1:"ATTACK"}).value_counts())

    # ----------------- DETAILED ALERTS -----------------
    st.markdown("### 🚨 Detailed Alerts")
    view_cols = ["Flow Duration","Total Fwd Packets","Total Backward Packets",
                 "Hybrid_Alert","Reason","RiskScore(%)","TopFeatures"]
    st.dataframe(raw_df[view_cols], use_container_width=True)

    # ----------------- FEEDBACK -----------------
    st.markdown("### 📝 Provide Feedback on Alerts")
    feedback_df = pd.DataFrame(columns=["Flow_ID","Hybrid_Alert","Feedback"])
    for i, row in raw_df.iterrows():
        if row["Hybrid_Alert"]==1:
            fb = st.radio(f"Flow {i} - {row['Reason']}", ("True Alert","False Positive"), key=f"fb_{i}", horizontal=True)
            feedback_df.loc[i] = [i, row["Hybrid_Alert"], fb]

    if st.button("💾 Submit Feedback"):
        save_feedback(feedback_df)
        st.success("Feedback saved!")

else:
    st.info("Click 🚀 Run IDS Analysis to generate alerts")
