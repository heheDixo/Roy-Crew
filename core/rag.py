# core/rag.py
import json
import numpy as np
from pathlib import Path
from openai import OpenAI
from config.settings import OLLAMA_BASE_URL, KNOWLEDGE_DIR

BASE_DIR = Path(__file__).resolve().parent.parent


class RAGPipeline:
    def __init__(self):
        self.embed_client = OpenAI(
            base_url=OLLAMA_BASE_URL,
            api_key="lm-studio"
        )
        self.embed_model = "text-embedding-nomic-embed-text-v1.5"
        self.store_path = BASE_DIR / "knowledge" / ".vector_store.json"
        self.docs = []
        self.embeddings = []
        self.metadata = []

        if self.store_path.exists():
            self._load()
        else:
            self._ingest()

    def _chunk_text(self, text: str, chunk_size: int = 400) -> list:
        words = text.split()
        chunks = []
        for i in range(0, len(words), chunk_size - 40):
            chunk = " ".join(words[i:i + chunk_size])
            if chunk.strip():
                chunks.append(chunk)
        return chunks

    def _embed(self, texts: list) -> list:
        response = self.embed_client.embeddings.create(
            model=self.embed_model,
            input=texts
        )
        return [item.embedding for item in response.data]

    def _ingest(self):
        knowledge_path = BASE_DIR / KNOWLEDGE_DIR
        if not knowledge_path.exists():
            print("[RAG] Knowledge directory not found.")
            return

        all_docs = []
        all_meta = []

        for filepath in knowledge_path.glob("*.txt"):
            try:
                text = filepath.read_text(encoding="utf-8")
                chunks = self._chunk_text(text)
                for chunk in chunks:
                    all_docs.append(chunk)
                    all_meta.append({"source": filepath.name})
                print(f"[RAG] Ingested: {filepath.name} ({len(chunks)} chunks)")
            except Exception as e:
                print(f"[RAG] Error reading {filepath}: {e}")

        if not all_docs:
            print("[RAG] No documents found.")
            return

        print(f"[RAG] Embedding {len(all_docs)} chunks...")
        embeddings = self._embed(all_docs)

        self.docs = all_docs
        self.embeddings = embeddings
        self.metadata = all_meta

        self._save()
        print(f"[RAG] Done. {len(all_docs)} chunks stored.")

    def _save(self):
        data = {
            "docs": self.docs,
            "embeddings": self.embeddings,
            "metadata": self.metadata
        }
        self.store_path.write_text(json.dumps(data), encoding="utf-8")

    def _load(self):
        data = json.loads(self.store_path.read_text(encoding="utf-8"))
        self.docs = data["docs"]
        self.embeddings = data["embeddings"]
        self.metadata = data["metadata"]
        print(f"[RAG] Loaded {len(self.docs)} chunks from store.")

    def _cosine_similarity(self, a: list, b: list) -> float:
        a = np.array(a)
        b = np.array(b)
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

    def retrieve(self, query: str, top_k: int = 3) -> str:
        if not self.docs:
            print("[RAG] WARNING: No docs loaded")
            return ""

        query_embedding = self._embed([query])[0]

        scores = [
            self._cosine_similarity(query_embedding, emb)
            for emb in self.embeddings
        ]

        top_indices = sorted(
            range(len(scores)),
            key=lambda i: scores[i],
            reverse=True
        )[:top_k]

        chunks = []
        for idx in top_indices:
            source = self.metadata[idx]["source"]
            chunks.append(f"[{source}]\n{self.docs[idx]}")

        return "\n\n---\n\n".join(chunks)