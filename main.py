import os
import streamlit as st
from database import reset_databases, load_scan_results_from_db, load_risk_count_from_db, clean_database
from analysis import scan_directory, generate_rag_response
from ui import show_analysis_ui, show_rag_qa, show_risk_dashboard

def main():
    st.title("Intelligent CI/CD Security Analysis Platform")

    if 'db_initialized' not in st.session_state:
        reset_databases(force_reset=True)
        st.session_state.db_initialized = True

    if 'scan_results' not in st.session_state or st.session_state.scan_results == []:
        st.session_state.scan_results = load_scan_results_from_db()
    if 'risk_count' not in st.session_state or st.session_state.risk_count == {}:
        st.session_state.risk_count = load_risk_count_from_db()
    if 'show_confirm' not in st.session_state:
        st.session_state.show_confirm = False
    if 'debug_mode' not in st.session_state:
        st.session_state.debug_mode = False

    with st.sidebar:
        st.header("Scan Settings")
        st.session_state.model_type = st.radio("AI Model Selection", ["OLLAMA", "Gemini"])
        scan_dir = st.text_input("Scan Directory Path", "./sample_configs")
        st.session_state.debug_mode = st.checkbox("Enable Debug Mode", value=False)
        
        if st.button("Start Security Scan"):
            if os.path.exists(scan_dir):
                if st.session_state.scan_results:
                    st.session_state.show_confirm = True
                else:
                    with st.spinner("Scanning in progress..."):
                        results, risks = scan_directory(scan_dir, st.session_state.model_type)
                        st.session_state.scan_results = results
                        st.session_state.risk_count = risks
                    st.success("Scan completed!")
            else:
                st.error("Directory does not exist!")

        if st.session_state.show_confirm:
            st.warning("Do you want to clear previous scan results before starting a new scan?")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Yes, clear previous results"):
                    clean_database()
                    st.session_state.scan_results = []
                    st.session_state.risk_count = {}
                    st.session_state.show_confirm = False
                    st.success("Previous scan results cleared!")
                    with st.spinner("Scanning in progress..."):
                        results, risks = scan_directory(scan_dir, st.session_state.model_type)
                        st.session_state.scan_results = results
                        st.session_state.risk_count = risks
                    st.success("Scan completed!")
            with col2:
                if st.button("No, keep previous results"):
                    st.session_state.show_confirm = False
                    st.info("Previous scan results retained.")
                    with st.spinner("Scanning in progress..."):
                        results, risks = scan_directory(scan_dir, st.session_state.model_type)
                        st.session_state.scan_results = results
                        st.session_state.risk_count = risks
                    st.success("Scan completed!")

    tab1, tab2, tab3 = st.tabs(["Analysis Results", "Risk Dashboard", "Intelligent Q&A"])
    
    with tab1:
        show_analysis_ui()
    
    with tab2:
        if st.session_state.risk_count:
            show_risk_dashboard(st.session_state.risk_count)
        else:
            st.info("Please run a scan to display data")
    
    with tab3:
        show_rag_qa(generate_rag_response, st.session_state.model_type)

if __name__ == "__main__":
    main()