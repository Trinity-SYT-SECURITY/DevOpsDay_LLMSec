import sqlite3
import chromadb
import streamlit as st
from embedding import OllamaEmbeddingFunction
import os
import re

# Initialize ChromaDB (can remain global as it's thread-safe)
chroma_client = chromadb.PersistentClient(path="chroma_db")
collection = chroma_client.get_or_create_collection(
    name="cicd_docs",
    embedding_function=OllamaEmbeddingFunction()
)

def get_db_connection():
    """Create or return a new SQLite connection for the current thread."""
    return sqlite3.connect('cicd_scan.db', check_same_thread=False)

def reset_databases(force_reset=False):
    """Reset SQLite and ChromaDB only if forced or initial run."""
    global collection
    if force_reset:
        st.write("Resetting databases...")
        with get_db_connection() as conn:
            conn.execute('DROP TABLE IF EXISTS scan_results')
            conn.execute('''CREATE TABLE scan_results
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          file_path TEXT,
                          content TEXT,
                          risks TEXT,
                          analysis TEXT,
                          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            conn.commit()
        
        try:
            chroma_client.delete_collection("cicd_docs")
        except:
            pass
        collection = chroma_client.get_or_create_collection(
            name="cicd_docs",
            embedding_function=OllamaEmbeddingFunction()
        )
        st.write("Databases reset completed.")

def store_in_database(file_path, content, risks, analysis):
    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO scan_results (file_path, content, risks, analysis)
            VALUES (?, ?, ?, ?)
        ''', (file_path, content, str(risks), analysis))
        conn.commit()

def store_in_vector_db(file_path, content, analysis, detect_owasp_risks_func):
    try:
        normalized_path = file_path.replace('\\', '/')
        st.write(f"Normalized path: {normalized_path}")
        existing_ids = collection.get()['ids']
        st.write(f"Existing IDs before deletion: {existing_ids}")
        to_delete = [id for id in existing_ids if id.startswith(normalized_path)]
        if to_delete:
            collection.delete(ids=to_delete)
            st.write(f"Deleted IDs: {to_delete}")

        metadata_base = {
            "file_path": file_path,
            "filename": os.path.basename(file_path).lower(),
            "directory": os.path.dirname(file_path),
            "risks": str(detect_owasp_risks_func(analysis, content)),
            "content_type": "cicd_config"
        }

        from utils import chunk_text
        chunks = chunk_text(content)
        documents = []
        metadatas = []
        ids = []

        for i, chunk in enumerate(chunks):
            chunk_id = f"{normalized_path}_chunk_{i}"
            chunk_metadata = metadata_base.copy()
            chunk_metadata["chunk_id"] = i
            documents.append(chunk)
            metadatas.append(chunk_metadata)
            ids.append(chunk_id)

        summary_doc = f"""
        [File Path] {file_path}
        [Filename] {metadata_base['filename']}
        [Content Summary] {content[:2000]}
        [Risk Analysis] {analysis[:1000]}
        """
        documents.append(summary_doc)
        metadatas.append(metadata_base)
        ids.append(normalized_path)

        st.write(f"Adding to ChromaDB: {ids}")
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        st.success(f"Successfully stored data for {file_path}")
        
        stored_ids = collection.get()['ids']
        st.write(f"Stored IDs after addition: {stored_ids}")
    except Exception as e:
        st.error(f"Vector storage failed: {str(e)}")
        raise

def query_vectors(question):
    try:
        from embedding import OllamaEmbeddingFunction
        # Match any filename, with or without an extension
        filename_match = re.search(r'\b(\w+(?:\.\w+)?)\b', question, re.IGNORECASE)
        target_filename = filename_match.group(1).lower() if filename_match else None

        embedding_func = OllamaEmbeddingFunction()
        query_embedding = embedding_func([question])[0]
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=5,
            include=["documents", "metadatas"]
        )
        
        if results['documents'] and results['metadatas']:
            filtered_docs = []
            st.write("Query results metadata:", results['metadatas'][0])  # Debug output
            for doc, meta in zip(results['documents'][0], results['metadatas'][0]):
                stored_filename = meta.get('filename', '').lower()
                if target_filename:
                    if target_filename == stored_filename:  # Exact match takes priority
                        filtered_docs = [doc]
                        break
                    elif target_filename in stored_filename or stored_filename in target_filename:
                        filtered_docs.append(doc)
            if filtered_docs:
                return [filtered_docs]
            # Fallback to top results if no exact match
            return [results['documents'][0]]
        return ["No related files found."]
    except Exception as e:
        st.error(f"Vector query failed: {str(e)}")
        return ["No related files found."]

def clean_database():
    with get_db_connection() as conn:
        conn.execute('DELETE FROM scan_results')
        conn.commit()
    try:
        existing_ids = collection.get()['ids']
        if existing_ids:
            collection.delete(ids=existing_ids)
        else:
            st.info("No vector data to clean.")
    except Exception as e:
        st.error(f"Failed to clean vector database: {str(e)}")

def load_scan_results_from_db():
    with get_db_connection() as conn:
        query = "SELECT file_path, content, risks, analysis FROM scan_results"
        import pandas as pd
        df = pd.read_sql_query(query, conn)
        results = []
        for _, row in df.iterrows():
            results.append({
                "file_path": row['file_path'],
                "risks": eval(row['risks']),
                "analysis": row['analysis']
            })
        return results

def load_risk_count_from_db():
    with get_db_connection() as conn:
        query = "SELECT risks FROM scan_results"
        import pandas as pd
        df = pd.read_sql_query(query, conn)
        risk_count = {}
        for _, row in df.iterrows():
            detected_risks = eval(row['risks'])
            for risk in detected_risks:
                risk_name = risk["risk_name"]
                severity = risk["severity"]
                if risk_name not in risk_count:
                    risk_count[risk_name] = {"Low": 0, "Medium": 0, "High": 0}
                risk_count[risk_name][severity] += 1
        return risk_count