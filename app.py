import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import plotly.express as px

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="AI Threat Hunter",
    page_icon="🎯",
    layout="wide"
)

st.title("🎯 AI Threat Hunter")

st.markdown("""
This utility leverages an **Unsupervised Isolation Forest** model to identify
potential Command & Control (C2) beaconing activity and suspicious network flows.

The model dynamically profiles the uploaded network telemetry and automatically
determines anomalous behavior without requiring a manually configured threshold.
""")

# --------------------------------------------------
# FEATURE ENGINEERING + ML SCORING
# --------------------------------------------------

def process_and_score_data(df):

    st.text("[*] Processing raw telemetry and extracting security features...")

    required_base_columns = [
        'total_length_of_fwd_packets',
        'total_length_of_bwd_packets',
        'total_fwd_packets',
        'total_backward_packets'
    ]

    missing_base = [c for c in required_base_columns if c not in df.columns]

    if missing_base:
        st.error(
            f"Uploaded data is missing required columns: {missing_base}"
        )
        return None

    # -----------------------------
    # Feature Engineering
    # -----------------------------

    df['threat_byte_ratio'] = (
        df['total_length_of_fwd_packets']
        /
        (df['total_length_of_bwd_packets'] + 1e-9)
    )

    df['threat_packet_ratio'] = (
        df['total_fwd_packets']
        /
        (df['total_backward_packets'] + 1e-9)
    )

    critical_features = [
        'threat_byte_ratio',
        'threat_packet_ratio',
        'flow_duration',
        'flow_bytes/s',
        'flow_packets/s',
        'fwd_packet_length_mean',
        'fwd_packet_length_std',
        'bwd_packet_length_std',
        'average_packet_size'
    ]

    missing_features = [
        col for col in critical_features
        if col not in df.columns
    ]

    if missing_features:
        st.error(
            f"Uploaded data is missing critical columns: {missing_features}"
        )
        return None

    X_raw = df[critical_features].copy()

    # Clean data
    X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_raw.fillna(0, inplace=True)

    # -----------------------------
    # Standardization
    # -----------------------------

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    st.text("[*] Dynamically profiling current network baseline...")

    # -----------------------------
    # Isolation Forest
    # -----------------------------

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    # Raw anomaly score
    df['anomaly_score'] = model.decision_function(X_scaled)

    # Native Isolation Forest classification
    # -1 = anomaly
    #  1 = normal
    df['is_anomaly'] = model.predict(X_scaled)

    # -----------------------------
    # Threat Confidence
    # -----------------------------

    score_min = df['anomaly_score'].min()
    score_max = df['anomaly_score'].max()

    df['threat_confidence'] = (
        (score_max - df['anomaly_score'])
        /
        (score_max - score_min + 1e-9)
    ) * 100

    return df


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.header("Data Ingestion")

uploaded_file = st.sidebar.file_uploader(
    "Upload Network Flow CSV",
    type=["csv"]
)

st.sidebar.markdown("---")

if st.sidebar.button(
    "Run Sample (sample_traffic.csv)"
):
    uploaded_file = "./data/sample_traffic.csv"

# --------------------------------------------------
# EXECUTION
# --------------------------------------------------

if uploaded_file is not None:

    try:

        raw_data = pd.read_csv(
            uploaded_file,
            low_memory=False
        )

    except FileNotFoundError:

        st.warning(
            "Default baseline file not found. Please upload a CSV."
        )

        st.stop()

    with st.spinner("Hunting for anomalies..."):

        scored_data = process_and_score_data(raw_data)

    if scored_data is not None:

        threats = scored_data[
            scored_data['is_anomaly'] == -1
        ].sort_values(
            by='threat_confidence',
            ascending=False
        )

        top_suspicious = scored_data.sort_values(
            by='threat_confidence',
            ascending=False
        ).head(100)

        normal_count = len(
            scored_data[
                scored_data['is_anomaly'] == 1
            ]
        )

        threat_count = len(threats)

        st.divider()

        # --------------------------------------------------
        # DASHBOARD METRICS
        # --------------------------------------------------

        st.subheader("📊 Threat Intelligence Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Connections Analyzed",
            f"{len(scored_data):,}"
        )

        col2.metric(
            "Benign Traffic",
            f"{normal_count:,}"
        )

        col3.metric(
            "Anomalies Detected",
            f"{threat_count:,}"
        )

        # --------------------------------------------------
        # VISUALIZATION
        # --------------------------------------------------

        st.subheader(
            "📡 Connection Timeline & Anomaly Distribution"
        )

        if 'timestamp' in scored_data.columns:

            scored_data['timestamp'] = pd.to_datetime(
                scored_data['timestamp'],
                errors='coerce'
            )

            fig = px.scatter(
                scored_data,
                x='timestamp',
                y='anomaly_score',
                color=scored_data['is_anomaly'].astype(str),
                color_discrete_map={
                    '-1': 'red',
                    '1': 'blue'
                },
                hover_data=[
                    col for col in [
                        'src_ip',
                        'dst_ip',
                        'threat_confidence',
                        'threat_byte_ratio'
                    ]
                    if col in scored_data.columns
                ],
                title="Isolation Forest Detection Results",
                labels={
                    "anomaly_score": "Anomaly Score",
                    "is_anomaly": "Classification"
                }
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        # --------------------------------------------------
        # HIGH-RISK CONNECTIONS
        # --------------------------------------------------

        st.subheader(
            "🚨 Top Model-Detected Threats"
        )

        display_cols = [
            col for col in [
                'timestamp',
                'src_ip',
                'dst_ip',
                'anomaly_score',
                'threat_confidence',
                'threat_byte_ratio',
                'threat_packet_ratio'
            ]
            if col in threats.columns
        ]

        if len(threats) > 0:

            st.dataframe(
                threats[display_cols].head(25),
                use_container_width=True
            )

        else:

            st.success(
                "Isolation Forest did not identify any anomalous connections."
            )

        # --------------------------------------------------
        # THREAT HUNTING VIEW
        # --------------------------------------------------

        st.subheader(
            "🔍 Top 100 Most Suspicious Connections"
        )

        hunt_cols = [
            col for col in [
                'timestamp',
                'src_ip',
                'dst_ip',
                'threat_confidence',
                'anomaly_score',
                'threat_byte_ratio',
                'threat_packet_ratio'
            ]
            if col in top_suspicious.columns
        ]

        st.dataframe(
            top_suspicious[hunt_cols],
            use_container_width=True
        )

else:

    st.info(
        "👈 Upload a CSV file in the sidebar to begin the threat hunt."
    )