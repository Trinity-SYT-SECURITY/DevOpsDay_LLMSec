from openai import OpenAI
import numpy as np
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings  # Add Embeddings to the import
import streamlit as st

class OllamaEmbeddingFunction(EmbeddingFunction):
    def __init__(self, model_name="nomic-embed-text"):
        self.client = OpenAI(
            base_url='http://localhost:11434/v1',
            api_key='ollama'
        )
        self.model_name = model_name

    def __call__(self, input: Documents) -> Embeddings:
        try:
            response = self.client.embeddings.create(
                model=self.model_name,
                input=input
            )
            embeddings = [item.embedding for item in response.data]
            embeddings = [self._normalize_embedding(emb) for emb in embeddings]
            return embeddings
        except Exception as e:
            st.error(f"Embedding generation failed: {str(e)}")
            return [[] for _ in input]

    def _normalize_embedding(self, embedding):
        embedding_array = np.array(embedding)
        norm = np.linalg.norm(embedding_array)
        if norm == 0:
            return embedding_array.tolist()
        return (embedding_array / norm).tolist()