import streamlit as st
import pandas as pd
import plotly.express as px
from database import query_vectors, get_db_connection  # Added get_db_connection

def show_analysis_ui():
    st.subheader("File Analysis Results")
    search_query = st.text_input("Search file path or risk ID:")
    
    with get_db_connection() as conn:  # Use context manager for connection
        query = '''
        SELECT file_path, risks, analysis 
        FROM scan_results
        WHERE file_path LIKE ? OR risks LIKE ?
        ORDER BY timestamp DESC
        LIMIT 20
        '''
        params = (f"%{search_query}%", f"%{search_query}%")
        
        df = pd.read_sql_query(query, conn, params=params)
        
        if not df.empty:
            for _, row in df.iterrows():
                with st.expander(row['file_path']):
                    st.markdown(f"**Detected risks**: {eval(row['risks'])}")
                    st.markdown(f"**Analysis results**:\n{row['analysis']}")
        else:
            st.info("No matching results found")

def show_rag_qa(generate_rag_response_func, model_type):
    st.subheader("Security Analysis Q&A System")
    question = st.text_input("Enter your security question:")
    
    if question:
        if st.session_state.get('debug_mode', False):
            with st.expander("Debug Information"):
                context = query_vectors(question)
                st.write("Original context:", context)
                try:
                    from database import collection
                    results = collection.query(
                        query_texts=[question],
                        include=["metadatas"]
                    )
                    st.write("Matched metadata:", results['metadatas'][0])
                except Exception as e:
                    st.error(f"Metadata query failed: {str(e)}")
        context = query_vectors(question)
        answer = generate_rag_response_func(question, context, model_type)
        
        with st.container(border=True):
            st.markdown(f"**Question**: {question}")
            st.markdown(f"**Answer**:\n{answer}")
            if context and isinstance(context, list):
                st.divider()
                st.markdown("**Reference context**:")
                for doc in context[0]:
                    st.markdown(f"- `{doc[:100]}...`")

def show_risk_dashboard(risk_count):
    st.subheader("Risk Distribution Visualization")
    
    if not isinstance(risk_count, dict):
        st.error("Risk count data is invalid. Expected a dictionary, but got a different type.")
        return
    
    data = []
    for risk_name, severities in risk_count.items():
        if not isinstance(severities, dict):
            st.warning(f"Invalid severity data for risk '{risk_name}'. Skipping this risk.")
            continue
        for severity, count in severities.items():
            if count > 0:
                data.append({"Risk Name": risk_name, "Severity": severity, "Count": count})
    
    if not data:
        st.info("No risks detected.")
        return
    
    df = pd.DataFrame(data)
    
    tab1, tab2, tab3 = st.tabs(["Heatmap", "Treemap", "Scatter Plot"])
    
    with tab1:
        heatmap_data = df.pivot(index="Risk Name", columns="Severity", values="Count").fillna(0)
        fig = px.imshow(
            heatmap_data,
            labels=dict(x="Severity", y="Risk Name", color="Count"),
            title="Risk Heatmap by Severity",
            color_continuous_scale="Reds"
        )
        st.plotly_chart(fig)
    
    with tab2:
        fig = px.treemap(
            df,
            path=["Risk Name", "Severity"],
            values="Count",
            title="Risk Treemap by Severity",
            color="Severity",
            color_discrete_map={"Low": "#00CC96", "Medium": "#EF553B", "High": "#FF0000"}
        )
        st.plotly_chart(fig)
    
    with tab3:
        fig = px.scatter(
            df,
            x="Risk Name",
            y="Count",
            color="Severity",
            size="Count",
            title="Risk Scatter Plot by Severity",
            color_discrete_map={"Low": "#00CC96", "Medium": "#EF553B", "High": "#FF0000"}
        )
        st.plotly_chart(fig)