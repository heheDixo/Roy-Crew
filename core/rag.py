# core/rag.py
import os
from pathlib import Path
from openai import OpenAI
import chromadb
from chromadb.config import Settings
from config.settings import OLLAMA_BASE_URL, KNOWLEDGE_DIR

BASE_DIR = Path(__file__).resolve().parent.parent


class RAGPipeline:
    def __init__(self):
        self.embed_client = OpenAI(
            base_url=OLLAMA_BASE_URL,
            api_key="lm-studio"
        )
        self.embed_model = "text-embedding-nomic-embed-text-v1.5"

        db_path = str(BASE_DIR / "knowledge" / ".chromadb")
        self.chroma = chromadb.PersistentClient(path=db_path)
        self.collection = self.chroma.get_or_create_collection(
            name="ghostcrew_kb",
            metadata={"hnsw:space": "cosine"}
        )

        knowledge_path = BASE_DIR / KNOWLEDGE_DIR
        if self.collection.count() == 0:
            self._ingest(knowledge_path)

    def _chunk_text(self, text: str, chunk_size: int = 512) -> list:
        """Split text into overlapping chunks."""
        words = text.split()
        chunks = []
        for i in range(0, len(words), chunk_size - 50):  # 50 word overlap
            chunk = " ".join(words[i:i + chunk_size])
            if chunk:
                chunks.append(chunk)
        return chunks

    def _embed(self, texts: list) -> list:
        """Get embeddings from LM Studio."""
        response = self.embed_client.embeddings.create(
            model=self.embed_model,
            input=texts
        )
        return [item.embedding for item in response.data]

    def _ingest(self, knowledge_path: Path):
        """Read all .txt files and store in ChromaDB."""
        if not knowledge_path.exists():
            print("[RAG] Knowledge directory not found.")
            return

        docs = []
        ids = []
        metadatas = []
        doc_id = 0

        for filepath in knowledge_path.glob("*.txt"):
            try:
                text = filepath.read_text(encoding="utf-8")
                chunks = self._chunk_text(text)
                for chunk in chunks:
                    docs.append(chunk)
                    ids.append(f"doc_{doc_id}")
                    metadatas.append({"source": filepath.name})
                    doc_id += 1
                print(f"[RAG] Ingested: {filepath.name} ({len(chunks)} chunks)")
            except Exception as e:
                print(f"[RAG] Error reading {filepath}: {e}")

        if docs:
            embeddings = self._embed(docs)
            self.collection.add(
                documents=docs,
                embeddings=embeddings,
                ids=ids,
                metadatas=metadatas
            )
            print(f"[RAG] Total chunks stored: {len(docs)}")

    def retrieve(self, query: str, top_k: int = 3) -> str:
        """Retrieve top-k relevant chunks for a query."""
        if self.collection.count() == 0:
            return ""

        query_embedding = self._embed([query])[0]
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, self.collection.count())
        )

        chunks = results["documents"][0]
        sources = [m["source"] for m in results["metadatas"][0]]

        context = "\n\n---\n\n".join([
            f"[Source: {src}]\n{chunk}"
            for src, chunk in zip(sources, chunks)
        ])
        return context

    def add_document(self, text: str, source: str = "runtime"):
        """Add a document at runtime (e.g. tool output summary)."""
        chunks = self._chunk_text(text)
        embeddings = self._embed(chunks)
        start_id = self.collection.count()
        self.collection.add(
            documents=chunks,
            embeddings=embeddings,
            ids=[f"rt_{start_id + i}" for i in range(len(chunks))],
            metadatas=[{"source": source}] * len(chunks)
        )