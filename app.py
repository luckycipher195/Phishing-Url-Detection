
import streamlit as st
import pandas as pd

from url_checker import (
    predict_url,
    detect_suspicious_patterns,
    calculate_risk
)

from database import (
    initialize_database,
    find_existing_scan,
    save_scan,
    get_all_scans
)


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="PhishGuard | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

initialize_database()


# ==========================================
# CUSTOM CSS
# ==========================================

st.markdown("""
<style>

.stApp {
    background: #080d19;
    color: #e2e8f0;
}

[data-testid="stSidebar"] {
    background: #101827;
    border-right: 1px solid #263449;
}

.block-container {
    max-width: 1250px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

.main-title {
    font-size: 42px;
    font-weight: 850;
    color: #38bdf8;
}

.subtitle {
    color: #94a3b8;
    font-size: 15px;
}

.section-title {
    color: #e2e8f0;
    font-size: 23px;
    font-weight: 700;
    margin-top: 15px;
}

.metric-card {
    background: #111c2e;
    border: 1px solid #263449;
    border-radius: 14px;
    padding: 20px;
    min-height: 125px;
}

.metric-label {
    color: #94a3b8;
    font-size: 14px;
}

.risk-high {
    color: #fb7185;
    font-size: 30px;
    font-weight: 800;
}

.risk-medium {
    color: #fbbf24;
    font-size: 30px;
    font-weight: 800;
}

.risk-low {
    color: #4ade80;
    font-size: 30px;
    font-weight: 800;
}

div.stButton > button {
    background: #0284c7;
    color: white;
    border: none;
    border-radius: 9px;
    font-weight: 700;
    min-height: 42px;
}

div.stButton > button:hover {
    background: #0369a1;
    color: white;
}

hr {
    border-color: #263449;
}

</style>
""", unsafe_allow_html=True)


# ==========================================
# SIDEBAR
# ==========================================

with st.sidebar:

    st.markdown("## 🛡️ PhishGuard")

    st.caption("ADVANCED URL SECURITY SYSTEM")

    st.markdown("---")

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Scan History",
            "About Project"
        ]
    )

    st.markdown("---")

    st.markdown("### System Status")

    st.success("ML Model Loaded")

    st.success("Permanent Database Active")

    st.info("Rule-Based Detection Active")

    st.caption("Version 2.1")


# ==========================================
# HEADER
# ==========================================

col1, col2 = st.columns([3, 1])

with col1:

    st.markdown(
        '<div class="main-title">🛡️ PhishGuard</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'Advanced Phishing URL Detection & Security Analysis'
        '</div>',
        unsafe_allow_html=True
    )

with col2:

    st.caption("HYBRID DETECTION SYSTEM")

    st.markdown("🟢 System Ready")

st.markdown("---")


# ==========================================
# DASHBOARD
# ==========================================

if page == "Dashboard":

    st.markdown(
        '<div class="section-title">'
        '🔍 Website Security Scanner'
        '</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Analyse a URL using Machine Learning "
        "and rule-based security checks."
    )

    with st.form("scanner_form"):

        url = st.text_input(
            "Website URL",
            placeholder="https://example.com"
        )

        submitted = st.form_submit_button(
            "🔎 SCAN URL",
            use_container_width=True
        )

    # ======================================
    # URL ANALYSIS
    # ======================================

    if submitted:

        if not url.strip():

            st.error("Please enter a URL.")

        else:

            try:

                clean_url = url.strip()

                with st.spinner("Analysing URL security..."):

                    # Check database BEFORE saving
                    previous_record = find_existing_scan(
                        clean_url
                    )

                    # Machine Learning prediction
                    (
                        prediction,
                        phishing_score,
                        legitimate_score,
                        features
                    ) = predict_url(clean_url)

                    # Rule-based analysis
                    suspicious = detect_suspicious_patterns(
                        clean_url
                    )

                    # Final risk assessment
                    risk = calculate_risk(
                        prediction,
                        suspicious
                    )

                    # Save or update permanent record
                    database_status = save_scan(
                        url=clean_url,
                        prediction=prediction,
                        phishing_score=phishing_score,
                        legitimate_score=legitimate_score,
                        risk_level=risk,
                        suspicious_indicators=suspicious
                    )

                    # Retrieve updated record
                    current_record = find_existing_scan(
                        clean_url
                    )

                    st.session_state.latest_scan = {
                        "url": clean_url,
                        "prediction": prediction,
                        "phishing_score": phishing_score,
                        "legitimate_score": legitimate_score,
                        "risk": risk,
                        "suspicious": suspicious,
                        "features": features,
                        "database_status": database_status,
                        "record": current_record
                    }

            except Exception as error:

                st.error(
                    f"Unable to analyse URL: {error}"
                )

    # ======================================
    # DISPLAY RESULTS
    # ======================================

    if "latest_scan" in st.session_state:

        result = st.session_state.latest_scan

        record = result["record"]

        st.markdown("---")

        st.markdown(
            '<div class="section-title">'
            '📊 Security Analysis Results'
            '</div>',
            unsafe_allow_html=True
        )

        st.code(result["url"], language=None)

        # DATABASE ALERT

        if result["database_status"] == "EXISTING":

            st.warning(
                "⚠️ PREVIOUSLY RECORDED URL — "
                "This URL already exists in the PhishGuard database."
            )

        else:

            st.success(
                "✅ NEW URL RECORDED — "
                "This URL has been added to the database."
            )

        # SUMMARY CARDS

        c1, c2, c3 = st.columns(3)

        with c1:

            st.metric(
                "Phishing Score",
                f'{result["phishing_score"]:.2f}%'
            )

        with c2:

            st.metric(
                "Legitimate Score",
                f'{result["legitimate_score"]:.2f}%'
            )

        with c3:

            st.metric(
                "Detection Risk",
                result["risk"]
            )

        # FINAL RISK

        st.markdown("### 🎯 Final Security Assessment")

        left, right = st.columns(2)

        with left:

            if result["risk"] == "HIGH":

                st.markdown(
                    '<div class="metric-card">'
                    '<div class="metric-label">SECURITY STATUS</div>'
                    '<div class="risk-high">HIGH RISK</div>'
                    '<p>Potential phishing indicators detected.</p>'
                    '</div>',
                    unsafe_allow_html=True
                )

            elif result["risk"] == "MEDIUM":

                st.markdown(
                    '<div class="metric-card">'
                    '<div class="metric-label">SECURITY STATUS</div>'
                    '<div class="risk-medium">MEDIUM RISK</div>'
                    '<p>Suspicious URL patterns detected.</p>'
                    '</div>',
                    unsafe_allow_html=True
                )

            else:

                st.markdown(
                    '<div class="metric-card">'
                    '<div class="metric-label">SECURITY STATUS</div>'
                    '<div class="risk-low">LOW RISK</div>'
                    '<p>No major warning indicators detected.</p>'
                    '</div>',
                    unsafe_allow_html=True
                )

        with right:

            st.markdown("#### 🤖 ML Prediction")

            if result["prediction"] == 0:

                st.error("PHISHING DETECTED")

            else:

                st.success("PREDICTED LEGITIMATE")

            st.write("Phishing probability")

            st.progress(
                min(max(result["phishing_score"] / 100, 0), 1)
            )

            st.write("Legitimate probability")

            st.progress(
                min(max(result["legitimate_score"] / 100, 0), 1)
            )

        # REPEAT URL INFORMATION

        st.markdown("---")

        st.markdown("### 🗄️ Permanent Threat Record")

        h1, h2, h3 = st.columns(3)

        with h1:

            st.metric(
                "Total Scans",
                record["scan_count"]
            )

        with h2:

            st.metric(
                "First Detected",
                record["first_seen"][:10]
            )

        with h3:

            st.metric(
                "Last Scanned",
                record["last_seen"][:10]
            )

        st.caption(
            "Times are stored in UTC in the database."
        )

        # RULE-BASED ANALYSIS

        st.markdown("---")

        st.markdown("### ⚙️ Rule-Based Security Analysis")

        if result["suspicious"]:

            st.warning(
                f'{len(result["suspicious"])} suspicious '
                'indicator(s) detected.'
            )

            for reason in result["suspicious"]:

                st.write(f"⚠️ {reason}")

        else:

            st.success(
                "No suspicious patterns found by the current rules."
            )

        # FEATURE ANALYSIS

        st.markdown("---")

        st.markdown("### 🧬 URL Feature Analysis")

        feature_df = pd.DataFrame(
            list(result["features"].items()),
            columns=["Feature", "Value"]
        )

        tab1, tab2 = st.tabs(
            ["Feature Table", "Feature Chart"]
        )

        with tab1:

            st.dataframe(
                feature_df,
                use_container_width=True,
                hide_index=True
            )

        with tab2:

            numeric_features = feature_df[
                feature_df["Value"].apply(
                    lambda value: isinstance(value, (int, float))
                    and not isinstance(value, bool)
                )
            ].copy()

            if not numeric_features.empty:

                chart_df = numeric_features.set_index(
                    "Feature"
                )

                st.bar_chart(chart_df)

            else:

                st.info("No numeric features available.")

        st.info(
            "Security Notice: ML scores are predictions, "
            "not guarantees of website safety. LOW RISK "
            "does not prove that a website is safe."
        )


# ==========================================
# SCAN HISTORY
# ==========================================

elif page == "Scan History":

    st.markdown(
        '<div class="section-title">📜 Permanent Scan History</div>',
        unsafe_allow_html=True
    )

    records = get_all_scans()

    if records:

        history_df = pd.DataFrame(records)

        st.metric(
            "Total Unique URLs Recorded",
            len(records)
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            "Records are stored permanently in the local SQLite database."
        )

    else:

        st.info(
            "No scan records available. Analyse a URL from the Dashboard."
        )


# ==========================================
# ABOUT PROJECT
# ==========================================

elif page == "About Project":

    st.markdown(
        '<div class="section-title">ℹ️ About PhishGuard</div>',
        unsafe_allow_html=True
    )

    st.write(
        "PhishGuard is an Advanced Phishing URL Detection System "
        "developed using Python and Machine Learning."
    )

    st.markdown("### Detection Components")

    st.markdown("""
    - **Machine Learning:** Random Forest classification model.
    - **Feature Extraction:** Analyses URL characteristics.
    - **Rule-Based Detection:** Checks suspicious URL patterns.
    - **Hybrid Risk Assessment:** Combines ML predictions and rules.
    - **Permanent Threat Records:** Stores previous URL scan results.
    - **Repeat URL Detection:** Identifies URLs already in the database.
    """)

    st.markdown("### Technology Stack")

    st.write(
        "Python | Pandas | Scikit-learn | Joblib | Streamlit | SQLite"
    )

    st.warning(
        "This project is intended for educational and "
        "cybersecurity research purposes."
    )


# ==========================================
# FOOTER
# ==========================================

st.markdown("---")

st.markdown(
    """
    <div style="text-align:center; color:#64748b; font-size:13px;">
        🛡️ PhishGuard | Advanced Phishing URL Detection System
        <br>
        Developed using Python, Machine Learning, SQLite and Streamlit
        <br>
        Educational & Cybersecurity Research Project
    </div>
    """,
    unsafe_allow_html=True
)
