import re
from nltk.tokenize import word_tokenize
import nltk
import streamlit as st

nltk.download('punkt', quiet=True)

def preprocess_text(text):
    tokens = word_tokenize(text.lower())
    cleaned_tokens = [re.sub(r'[^a-z0-9\s]', '', token) for token in tokens]
    cleaned_text = ' '.join(token for token in cleaned_tokens if token)
    return cleaned_text

def load_file_content(file_path):
    encodings = ['utf-8', 'latin-1', 'gbk', 'utf-16']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
                return preprocess_text(content)
        except UnicodeDecodeError:
            continue
    try:
        with open(file_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='replace')
            return preprocess_text(content)
    except Exception as e:
        st.error(f"Cannot read file {file_path}: {str(e)}")
        return None

def chunk_text(text, chunk_size=1000, overlap=200):
    chunks = []
    start = 0
    text_length = len(text)
    while start < text_length:
        end = min(start + chunk_size, text_length)
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return chunks