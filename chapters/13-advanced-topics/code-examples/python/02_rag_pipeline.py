"""
Chapter 13: RAG Pipeline for Government Documents at IL5
=========================================================
Implements a production-ready Retrieval-Augmented Generation pipeline
for federal document corpora — contracts, policy memoranda, technical manuals.

Key design decisions:
- Document-type-aware chunking (not naive 512-token sliding window)
- Self-hosted embeddings via sentence-transformers (no external API calls at IL4+)
- FAISS for single-node deployments; ChromaDB for multi-user team access
- Citation enforcement to support hallucination detection
- Confidence scoring on retrieval results

Classification note: All processing happens within your accredited environment.
This pipeline does not call any external API by default.
"""

import os
import re
import json
import logging
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Section 1: Document-Type-Aware Chunking
# ---------------------------------------------------------------------------

@dataclass
class DocumentChunk:
    """A chunk of a government document with full provenance metadata."""
    text: str
    chunk_id: str                   # SHA256 hash of (doc_path + chunk_index)
    source_document: str            # Document filename or identifier
    doc_type: str                   # contract | policy | technical_manual | foia
    classification_marking: str     # UNCLASSIFIED, CUI, SECRET, etc.
    section_reference: str          # Clause number, paragraph number, section header
    page_number: Optional[int]
    chunk_index: int                # Position in the document (for reconstruction)
    parent_section: str             # Parent clause/section for context


def chunk_government_contract(
    text: str,
    source_doc: str,
    classification_marking: str = "UNCLASSIFIED//CUI",
    max_chunk_tokens: int = 800
) -> list[DocumentChunk]:
    """
    Chunk a federal contract document at clause boundaries.

    FAR/DFARS contracts have a predictable structure: clauses are numbered
    like 52.212-4, 252.204-7012, etc. We split at these boundaries first,
    then recursively split oversized clauses at paragraph boundaries.

    Args:
        text: Full text of the contract document
        source_doc: Document identifier (filename, contract number, etc.)
        classification_marking: Classification string to embed in metadata
        max_chunk_tokens: Approximate maximum tokens per chunk (1 token ≈ 4 chars)

    Returns:
        List of DocumentChunk objects with full provenance
    """
    max_chunk_chars = max_chunk_tokens * 4

    # FAR clause pattern: 52.XXX-X or 252.XXX-XXXX (DFARS)
    # Also catches agency-specific supplements like NMCARS, SOFARS, etc.
    far_clause_pattern = re.compile(
        r'(?:^|\n)(?=\s*(?:\d{2,4}\.\d{3}(?:-\d+)?|[A-Z]{2,5}\s+\d{3}(?:\.\d+)?)\s)',
        re.MULTILINE
    )

    # Split at clause boundaries
    clause_splits = far_clause_pattern.split(text)
    # Remove empty strings
    clause_splits = [s.strip() for s in clause_splits if s.strip()]

    chunks = []
    chunk_index = 0

    for clause_text in clause_splits:
        # Extract clause number from the start of this block
        clause_match = re.match(
            r'^(\d{2,4}\.\d{3}(?:-\d+)?|[A-Z]{2,5}\s+\d{3}(?:\.\d+)?)',
            clause_text
        )
        clause_ref = clause_match.group(1) if clause_match else "PREAMBLE"

        if len(clause_text) <= max_chunk_chars:
            # Clause fits in one chunk
            chunks.append(_make_chunk(
                text=clause_text,
                source_doc=source_doc,
                doc_type="contract",
                classification_marking=classification_marking,
                section_reference=clause_ref,
                page_number=None,
                chunk_index=chunk_index,
                parent_section=clause_ref
            ))
            chunk_index += 1
        else:
            # Clause is too long — split at paragraph boundaries
            paragraphs = re.split(r'\n{2,}', clause_text)
            current_chunk_text = ""

            for para in paragraphs:
                if len(current_chunk_text) + len(para) > max_chunk_chars and current_chunk_text:
                    chunks.append(_make_chunk(
                        text=current_chunk_text.strip(),
                        source_doc=source_doc,
                        doc_type="contract",
                        classification_marking=classification_marking,
                        section_reference=f"{clause_ref} (part {chunk_index})",
                        page_number=None,
                        chunk_index=chunk_index,
                        parent_section=clause_ref
                    ))
                    chunk_index += 1
                    current_chunk_text = para
                else:
                    current_chunk_text += "\n\n" + para

            if current_chunk_text.strip():
                chunks.append(_make_chunk(
                    text=current_chunk_text.strip(),
                    source_doc=source_doc,
                    doc_type="contract",
                    classification_marking=classification_marking,
                    section_reference=f"{clause_ref} (part {chunk_index})",
                    page_number=None,
                    chunk_index=chunk_index,
                    parent_section=clause_ref
                ))
                chunk_index += 1

    return chunks


def chunk_policy_document(
    text: str,
    source_doc: str,
    classification_marking: str = "UNCLASSIFIED",
    max_chunk_tokens: int = 600
) -> list[DocumentChunk]:
    """
    Chunk a DoD policy memorandum or directive at numbered paragraph boundaries.

    Policy documents typically have numbered paragraphs like:
    "1. PURPOSE", "2. APPLICABILITY", "3.a. Organizations shall..."
    Splitting at these boundaries keeps the policy context intact.
    """
    max_chunk_chars = max_chunk_tokens * 4

    # Match numbered paragraph headers: "1.", "1.a.", "2.1.", "SECTION 3:", etc.
    para_pattern = re.compile(
        r'(?:^|\n)(?=\s*(?:\d+(?:\.\d+)*[a-z]?\.|SECTION\s+\d+:|ENCLOSURE\s+\d+:))',
        re.MULTILINE | re.IGNORECASE
    )

    sections = para_pattern.split(text)
    sections = [s.strip() for s in sections if s.strip()]

    chunks = []
    for idx, section_text in enumerate(sections):
        # Extract paragraph number
        para_match = re.match(
            r'^(\d+(?:\.\d+)*[a-z]?\.?|SECTION\s+\d+|ENCLOSURE\s+\d+)',
            section_text, re.IGNORECASE
        )
        para_ref = para_match.group(1) if para_match else f"PARA-{idx}"

        # Extract section header (first line after the number)
        lines = section_text.split('\n', 2)
        section_title = lines[0].strip()

        if len(section_text) <= max_chunk_chars:
            chunks.append(_make_chunk(
                text=section_text,
                source_doc=source_doc,
                doc_type="policy",
                classification_marking=classification_marking,
                section_reference=para_ref,
                page_number=None,
                chunk_index=idx,
                parent_section=section_title[:100]
            ))
        else:
            # Long sections: split at sentence boundaries preserving 2-sentence overlap
            sentences = re.split(r'(?<=[.!?])\s+', section_text)
            current_chunk = []
            current_len = 0

            for sent in sentences:
                if current_len + len(sent) > max_chunk_chars and current_chunk:
                    chunk_text = " ".join(current_chunk)
                    chunks.append(_make_chunk(
                        text=chunk_text,
                        source_doc=source_doc,
                        doc_type="policy",
                        classification_marking=classification_marking,
                        section_reference=para_ref,
                        page_number=None,
                        chunk_index=len(chunks),
                        parent_section=section_title[:100]
                    ))
                    # 2-sentence overlap for context continuity
                    current_chunk = current_chunk[-2:] + [sent]
                    current_len = sum(len(s) for s in current_chunk)
                else:
                    current_chunk.append(sent)
                    current_len += len(sent)

            if current_chunk:
                chunks.append(_make_chunk(
                    text=" ".join(current_chunk),
                    source_doc=source_doc,
                    doc_type="policy",
                    classification_marking=classification_marking,
                    section_reference=para_ref,
                    page_number=None,
                    chunk_index=len(chunks),
                    parent_section=section_title[:100]
                ))

    return chunks


def _make_chunk(text, source_doc, doc_type, classification_marking,
                section_reference, page_number, chunk_index, parent_section) -> DocumentChunk:
    """Helper to create a DocumentChunk with a deterministic ID."""
    chunk_id = hashlib.sha256(
        f"{source_doc}:{chunk_index}:{text[:50]}".encode()
    ).hexdigest()[:16]

    return DocumentChunk(
        text=text,
        chunk_id=chunk_id,
        source_document=source_doc,
        doc_type=doc_type,
        classification_marking=classification_marking,
        section_reference=section_reference,
        page_number=page_number,
        chunk_index=chunk_index,
        parent_section=parent_section
    )


# ---------------------------------------------------------------------------
# Section 2: Self-Hosted Embedding Model
# ---------------------------------------------------------------------------
# At IL4+, you cannot call an external embedding API (OpenAI, Cohere, etc.)
# Use sentence-transformers running locally within your accredited environment.

class GovernmentEmbeddingModel:
    """
    Local embedding model for air-gapped / IL4+ environments.
    Uses sentence-transformers — no external API calls.

    Model selection guide:
    - all-MiniLM-L6-v2:  80MB, fastest, good for quick prototypes
    - all-mpnet-base-v2: 420MB, balanced accuracy/speed
    - e5-large-v2:       1.3GB, best retrieval accuracy, use in production
    - hkunlp/instructor-large: 1.3GB, best for instruction-following queries

    For government document retrieval, e5-large-v2 or instructor-large are
    recommended based on MTEB retrieval benchmark performance.
    """

    def __init__(self, model_name: str = "intfloat/e5-large-v2", device: str = "cpu"):
        """
        Args:
            model_name: HuggingFace model name (must be pre-downloaded in air-gapped env)
            device: "cpu" or "cuda" — use CUDA if a GPU cluster is available
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise ImportError(
                "sentence-transformers not installed. "
                "Run: pip install sentence-transformers"
            )

        logger.info(f"Loading embedding model: {model_name} on {device}")
        self.model = SentenceTransformer(model_name, device=device)
        self.model_name = model_name
        self.dimension = self.model.get_sentence_embedding_dimension()
        logger.info(f"Embedding dimension: {self.dimension}")

    def embed_chunks(
        self,
        chunks: list[DocumentChunk],
        batch_size: int = 32,
        show_progress: bool = True
    ) -> np.ndarray:
        """
        Embed a list of document chunks. Returns numpy array of shape (n_chunks, dim).

        For e5 models, prepend "passage: " to document text and "query: " to queries.
        This is required by the e5 training protocol for correct similarity scores.
        """
        texts = self._format_for_model(chunks)
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=show_progress,
            convert_to_numpy=True,
            normalize_embeddings=True  # Cosine similarity via dot product
        )
        return embeddings

    def embed_query(self, query: str) -> np.ndarray:
        """Embed a single user query for retrieval."""
        formatted = self._format_query(query)
        embedding = self.model.encode(
            [formatted],
            convert_to_numpy=True,
            normalize_embeddings=True
        )
        return embedding[0]

    def _format_for_model(self, chunks: list[DocumentChunk]) -> list[str]:
        """Add model-specific prefixes to document text."""
        if "e5" in self.model_name.lower():
            return [f"passage: {c.text}" for c in chunks]
        elif "instructor" in self.model_name.lower():
            return [
                f"Represent the {c.doc_type} document for retrieval: {c.text}"
                for c in chunks
            ]
        else:
            return [c.text for c in chunks]

    def _format_query(self, query: str) -> str:
        """Add model-specific prefix to query text."""
        if "e5" in self.model_name.lower():
            return f"query: {query}"
        elif "instructor" in self.model_name.lower():
            return f"Represent the question for retrieving relevant government documents: {query}"
        else:
            return query


# ---------------------------------------------------------------------------
# Section 3: Vector Store (FAISS + ChromaDB)
# ---------------------------------------------------------------------------

class FAISSVectorStore:
    """
    FAISS-backed vector store for single-node government RAG deployments.
    Best for: corpora up to ~500K chunks on a single server.
    Metadata and chunks stored in a parallel JSON file.

    For multi-user access with metadata filtering, use ChromaVectorStore instead.
    """

    def __init__(self, index_path: Optional[str] = None, dimension: int = 1024):
        """
        Args:
            index_path: Path to load an existing index (None for fresh index)
            dimension: Embedding dimension (must match your embedding model)
        """
        try:
            import faiss
        except ImportError:
            raise ImportError(
                "faiss-cpu not installed. Run: pip install faiss-cpu\n"
                "For GPU: pip install faiss-gpu"
            )
        import faiss as faiss_lib

        self.faiss = faiss_lib
        self.dimension = dimension
        self.chunks: list[DocumentChunk] = []

        if index_path and Path(index_path).exists():
            self._load(index_path)
        else:
            # IndexFlatIP: exact search with inner product (works with normalized vectors)
            # For large corpora (>1M chunks), use IndexIVFFlat for approximate search
            self.index = faiss_lib.IndexFlatIP(dimension)

    def add(self, chunks: list[DocumentChunk], embeddings: np.ndarray) -> None:
        """Add chunks and their embeddings to the index."""
        if len(chunks) != len(embeddings):
            raise ValueError(
                f"Chunk count ({len(chunks)}) must match embedding count ({len(embeddings)})"
            )
        self.index.add(embeddings.astype(np.float32))
        self.chunks.extend(chunks)
        logger.info(f"Added {len(chunks)} chunks. Total: {len(self.chunks)}")

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
        min_score: float = 0.3,
        filter_doc_type: Optional[str] = None,
        filter_classification: Optional[str] = None
    ) -> list[dict]:
        """
        Retrieve the top_k most relevant chunks for a query embedding.

        Args:
            query_embedding: Shape (dimension,) from embedding model
            top_k: Number of results to return
            min_score: Minimum cosine similarity threshold (0-1)
            filter_doc_type: If set, only return chunks of this doc_type
            filter_classification: If set, only return chunks with this marking

        Returns:
            List of dicts with keys: chunk, score, rank
        """
        # Retrieve more candidates if filtering, to ensure we get top_k after filter
        search_k = top_k * 5 if (filter_doc_type or filter_classification) else top_k

        scores, indices = self.index.search(
            query_embedding.reshape(1, -1).astype(np.float32),
            min(search_k, len(self.chunks))
        )

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:  # FAISS returns -1 for empty slots
                continue
            if score < min_score:
                continue

            chunk = self.chunks[idx]

            # Apply metadata filters
            if filter_doc_type and chunk.doc_type != filter_doc_type:
                continue
            if filter_classification and chunk.classification_marking != filter_classification:
                continue

            results.append({
                "chunk": chunk,
                "score": float(score),
                "rank": len(results) + 1
            })

            if len(results) >= top_k:
                break

        return results

    def save(self, index_path: str) -> None:
        """Persist index and metadata to disk."""
        self.faiss.write_index(self.index, index_path)
        meta_path = index_path.replace(".faiss", "_chunks.json")
        with open(meta_path, "w") as f:
            json.dump(
                [
                    {
                        "text": c.text,
                        "chunk_id": c.chunk_id,
                        "source_document": c.source_document,
                        "doc_type": c.doc_type,
                        "classification_marking": c.classification_marking,
                        "section_reference": c.section_reference,
                        "page_number": c.page_number,
                        "chunk_index": c.chunk_index,
                        "parent_section": c.parent_section
                    }
                    for c in self.chunks
                ],
                f
            )
        logger.info(f"Index saved to {index_path} ({len(self.chunks)} chunks)")

    def _load(self, index_path: str) -> None:
        """Load index and metadata from disk."""
        self.index = self.faiss.read_index(index_path)
        meta_path = index_path.replace(".faiss", "_chunks.json")
        with open(meta_path) as f:
            raw = json.load(f)
        self.chunks = [
            DocumentChunk(**{k: v for k, v in item.items()}) for item in raw
        ]
        logger.info(f"Loaded index from {index_path} ({len(self.chunks)} chunks)")


class ChromaVectorStore:
    """
    ChromaDB-backed vector store for multi-user team deployments.
    Supports metadata filtering, persistent storage, and server mode.
    Best for: teams of 2-20 analysts sharing a document corpus.
    """

    def __init__(
        self,
        persist_directory: str = "./chroma_db",
        collection_name: str = "government_documents"
    ):
        try:
            import chromadb
        except ImportError:
            raise ImportError("chromadb not installed. Run: pip install chromadb")
        import chromadb as chroma_lib

        self.client = chroma_lib.PersistentClient(path=persist_directory)
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )

    def add(self, chunks: list[DocumentChunk], embeddings: np.ndarray) -> None:
        """Add chunks and embeddings to the ChromaDB collection."""
        self.collection.add(
            ids=[c.chunk_id for c in chunks],
            embeddings=embeddings.tolist(),
            documents=[c.text for c in chunks],
            metadatas=[
                {
                    "source_document": c.source_document,
                    "doc_type": c.doc_type,
                    "classification_marking": c.classification_marking,
                    "section_reference": c.section_reference,
                    "chunk_index": c.chunk_index,
                    "parent_section": c.parent_section
                }
                for c in chunks
            ]
        )
        logger.info(f"Added {len(chunks)} chunks to ChromaDB. "
                    f"Collection size: {self.collection.count()}")

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
        filter_doc_type: Optional[str] = None,
        filter_classification: Optional[str] = None
    ) -> list[dict]:
        """Retrieve top_k chunks with optional metadata filtering."""
        where_clause = {}
        if filter_doc_type:
            where_clause["doc_type"] = {"$eq": filter_doc_type}
        if filter_classification:
            where_clause["classification_marking"] = {"$eq": filter_classification}

        query_kwargs = {
            "query_embeddings": [query_embedding.tolist()],
            "n_results": top_k,
            "include": ["documents", "metadatas", "distances"]
        }
        if where_clause:
            query_kwargs["where"] = where_clause

        results = self.collection.query(**query_kwargs)

        formatted = []
        for i, (doc, meta, dist) in enumerate(
            zip(results["documents"][0], results["metadatas"][0], results["distances"][0])
        ):
            # ChromaDB returns cosine distance (0=identical, 2=opposite)
            # Convert to similarity score (1=identical, 0=no similarity)
            similarity = 1 - (dist / 2)
            formatted.append({
                "chunk": DocumentChunk(
                    text=doc,
                    chunk_id=results["ids"][0][i],
                    source_document=meta["source_document"],
                    doc_type=meta["doc_type"],
                    classification_marking=meta["classification_marking"],
                    section_reference=meta["section_reference"],
                    page_number=None,
                    chunk_index=meta["chunk_index"],
                    parent_section=meta["parent_section"]
                ),
                "score": similarity,
                "rank": i + 1
            })

        return formatted


# ---------------------------------------------------------------------------
# Section 4: RAG Query Engine with Hallucination Detection
# ---------------------------------------------------------------------------

@dataclass
class RAGResponse:
    """Complete response from the RAG pipeline with full audit trail."""
    answer: str
    citations: list[dict]              # List of {section_ref, source_doc, excerpt, score}
    retrieved_chunks: list[dict]       # All retrieved chunks with scores
    query: str
    hallucination_flags: list[str]     # Any claims that couldn't be grounded
    confidence: float                  # 0.0 - 1.0, based on retrieval scores


class GovernmentRAGPipeline:
    """
    End-to-end RAG pipeline for government document Q&A.
    Combines chunking, embedding, retrieval, and LLM response generation
    with citation enforcement and basic hallucination detection.
    """

    def __init__(
        self,
        embedding_model: GovernmentEmbeddingModel,
        vector_store,  # FAISSVectorStore or ChromaVectorStore
        llm_client,    # FederalLLMClient from 01_llm_integration.py
        top_k: int = 5,
        min_retrieval_score: float = 0.25
    ):
        self.embedder = embedding_model
        self.store = vector_store
        self.llm = llm_client
        self.top_k = top_k
        self.min_score = min_retrieval_score

    def index_documents(
        self,
        documents: list[dict],
        batch_size: int = 64
    ) -> int:
        """
        Chunk and index a list of documents.

        Args:
            documents: List of dicts with keys:
                - text (str): Full document text
                - source (str): Document identifier
                - doc_type (str): contract | policy | technical_manual
                - classification (str): Classification marking
            batch_size: Embedding batch size

        Returns:
            Total number of chunks indexed
        """
        all_chunks = []
        for doc in documents:
            if doc["doc_type"] == "contract":
                chunks = chunk_government_contract(
                    text=doc["text"],
                    source_doc=doc["source"],
                    classification_marking=doc.get("classification", "UNCLASSIFIED//CUI")
                )
            elif doc["doc_type"] in ("policy", "memo"):
                chunks = chunk_policy_document(
                    text=doc["text"],
                    source_doc=doc["source"],
                    classification_marking=doc.get("classification", "UNCLASSIFIED")
                )
            else:
                # Generic chunking for other document types
                chunks = chunk_policy_document(
                    text=doc["text"],
                    source_doc=doc["source"],
                    classification_marking=doc.get("classification", "UNCLASSIFIED")
                )
                for c in chunks:
                    c.doc_type = doc["doc_type"]

            all_chunks.extend(chunks)

        logger.info(f"Chunked {len(documents)} documents into {len(all_chunks)} chunks")

        # Embed in batches
        for i in range(0, len(all_chunks), batch_size):
            batch = all_chunks[i:i + batch_size]
            embeddings = self.embedder.embed_chunks(batch, show_progress=False)
            self.store.add(batch, embeddings)
            logger.info(f"Indexed {min(i + batch_size, len(all_chunks))} / {len(all_chunks)} chunks")

        return len(all_chunks)

    def query(
        self,
        question: str,
        filter_doc_type: Optional[str] = None,
        require_citations: bool = True
    ) -> RAGResponse:
        """
        Answer a natural language question using the indexed document corpus.

        Args:
            question: The analyst's question in plain English
            filter_doc_type: Limit search to a specific document type
            require_citations: If True, the LLM is instructed to cite sources inline

        Returns:
            RAGResponse with answer, citations, and audit trail
        """
        # Step 1: Embed the query
        query_embedding = self.embedder.embed_query(question)

        # Step 2: Retrieve relevant chunks
        search_results = self.store.search(
            query_embedding=query_embedding,
            top_k=self.top_k,
            min_score=self.min_score,
            filter_doc_type=filter_doc_type
        )

        if not search_results:
            return RAGResponse(
                answer="No relevant documents found for this query. "
                       "The answer may not be in the indexed corpus, or "
                       "try broadening the query.",
                citations=[],
                retrieved_chunks=[],
                query=question,
                hallucination_flags=["No retrieval results — answer is not grounded"],
                confidence=0.0
            )

        # Step 3: Build context from retrieved chunks
        context_parts = []
        for result in search_results:
            chunk = result["chunk"]
            context_parts.append(
                f"[SOURCE: {chunk.source_document} | {chunk.section_reference} | "
                f"score: {result['score']:.3f}]\n{chunk.text}"
            )
        context = "\n\n---\n\n".join(context_parts)

        # Step 4: Build the RAG prompt
        citation_instruction = ""
        if require_citations:
            citation_instruction = (
                "\n\nCITATION REQUIREMENT: Every factual claim in your answer MUST be "
                "followed by an inline citation in this format: [SOURCE: document_name | section]. "
                "If a claim cannot be cited from the provided sources, do NOT make that claim. "
                "Explicitly state what the sources do not cover."
            )

        system_prompt = f"""You are a federal government document analyst. Answer questions using
ONLY the provided source documents. Do not use any outside knowledge.
If the answer is not in the provided sources, say so explicitly.{citation_instruction}"""

        user_message = f"""Question: {question}

Provided Source Documents:
{context}

Answer the question based solely on the provided sources. Include inline citations."""

        # Step 5: Generate response
        response = self.llm.complete(
            system_prompt=system_prompt,
            user_message=user_message,
            max_tokens=2048,
            temperature=0.0  # Deterministic for auditable responses
        )

        # Step 6: Extract citations from response
        citations = self._extract_citations(response.content, search_results)

        # Step 7: Check for hallucination signals
        hallucination_flags = self._check_grounding(response.content, search_results)

        # Step 8: Compute overall confidence
        avg_retrieval_score = np.mean([r["score"] for r in search_results])
        citation_coverage = len(citations) / max(1, response.content.count("[SOURCE:"))
        confidence = float(avg_retrieval_score * 0.6 + citation_coverage * 0.4)

        return RAGResponse(
            answer=response.content,
            citations=citations,
            retrieved_chunks=[
                {
                    "source": r["chunk"].source_document,
                    "section": r["chunk"].section_reference,
                    "score": r["score"],
                    "excerpt": r["chunk"].text[:200] + "..."
                }
                for r in search_results
            ],
            query=question,
            hallucination_flags=hallucination_flags,
            confidence=confidence
        )

    def _extract_citations(
        self, response_text: str, search_results: list[dict]
    ) -> list[dict]:
        """Extract inline citations from the response and match to chunks."""
        citation_pattern = re.compile(r'\[SOURCE:\s*([^\|]+)\|\s*([^\]]+)\]')
        matches = citation_pattern.findall(response_text)

        citations = []
        for doc_name, section_ref in matches:
            doc_name = doc_name.strip()
            section_ref = section_ref.strip()

            # Find the matching chunk
            for result in search_results:
                chunk = result["chunk"]
                if (doc_name.lower() in chunk.source_document.lower() or
                        chunk.source_document.lower() in doc_name.lower()):
                    citations.append({
                        "document": chunk.source_document,
                        "section": section_ref,
                        "classification": chunk.classification_marking,
                        "retrieval_score": result["score"],
                        "excerpt": chunk.text[:300]
                    })
                    break

        return citations

    def _check_grounding(
        self, response_text: str, search_results: list[dict]
    ) -> list[str]:
        """
        Basic hallucination check: look for specific claims that don't
        appear to be grounded in the retrieved context.

        This is a heuristic check, not a guarantee. For high-stakes decisions,
        use a dedicated entailment model.
        """
        flags = []

        # Check 1: Are there uncited specific numbers or dates?
        # Numbers in the response that don't appear in any retrieved chunk
        number_pattern = re.compile(r'\$[\d,]+|\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s*(?:million|billion|thousand))?|\d{4}-\d{2}-\d{2}')
        response_numbers = set(number_pattern.findall(response_text))

        all_context_text = " ".join(r["chunk"].text for r in search_results)
        for number in response_numbers:
            if number not in all_context_text:
                flags.append(
                    f"Claim '{number}' not found in retrieved context — verify manually"
                )

        # Check 2: Are there citation markers that don't match our sources?
        cited_pattern = re.compile(r'\[SOURCE:\s*([^\|]+)\|')
        cited_docs = {m.strip() for m in cited_pattern.findall(response_text)}
        indexed_docs = {r["chunk"].source_document for r in search_results}

        for cited_doc in cited_docs:
            if not any(cited_doc.lower() in d.lower() for d in indexed_docs):
                flags.append(
                    f"Citation references '{cited_doc}' which is not in retrieved context"
                )

        return flags


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Demo: Build and query a RAG pipeline over synthetic government documents.
    Uses CPU-only embedding (no GPU required) and FAISS for storage.
    No external API calls for embedding (sentence-transformers runs locally).
    You will need an LLM client from 01_llm_integration.py for generation.
    """
    import sys

    print("=== Chapter 13: RAG Pipeline Demo ===\n")

    # Synthetic policy document
    sample_policy = """MEMORANDUM FOR DISTRIBUTION

    SUBJECT: Updated Cybersecurity Requirements for AI Systems

    1. PURPOSE. This memorandum establishes cybersecurity requirements for
    artificial intelligence systems deployed on DoD networks.

    2. APPLICABILITY. This memorandum applies to all DoD components acquiring
    or deploying AI systems that process Controlled Unclassified Information (CUI)
    or higher classification levels.

    3. REQUIREMENTS.
    3.a. All AI systems shall undergo a cybersecurity review prior to Authority to Operate (ATO).
    3.b. LLM inference endpoints must be deployed within FedRAMP High authorized environments.
    3.c. Model weights for systems processing IL4 or higher data shall not be hosted
    on commercial cloud infrastructure without explicit waiver approval.
    3.d. All AI-generated outputs used in operational decisions shall be logged with
    the model version, prompt hash, and timestamp for audit purposes.

    4. COMPLIANCE DEADLINE. Components shall achieve compliance with paragraph 3.b and 3.c
    requirements no later than 1 October 2026.

    5. WAIVERS. Requests for waivers shall be submitted to the CDAO no later than
    90 days before the compliance deadline. Waiver approvals are valid for one year.

    6. POINT OF CONTACT. Questions shall be directed to the CDAO AI Policy Division.
    """

    # Test chunking
    print("Testing policy document chunking...")
    chunks = chunk_policy_document(
        text=sample_policy,
        source_doc="AI_Cybersecurity_Memo_2025.pdf",
        classification_marking="UNCLASSIFIED"
    )
    print(f"Created {len(chunks)} chunks from policy document")
    for chunk in chunks:
        print(f"  [{chunk.section_reference}]: {chunk.text[:80]}...")

    print("\n--- Chunking complete ---")
    print("\nTo run full RAG query demo, initialize with:")
    print("  embedding_model = GovernmentEmbeddingModel('intfloat/e5-large-v2')")
    print("  vector_store = FAISSVectorStore(dimension=1024)")
    print("  llm_client = FederalLLMClient(provider='azure_openai')  # from 01_llm_integration.py")
    print("  pipeline = GovernmentRAGPipeline(embedding_model, vector_store, llm_client)")
    print("  pipeline.index_documents([{'text': ..., 'source': ..., 'doc_type': 'policy'}])")
    print("  result = pipeline.query('What is the compliance deadline for LLM endpoints?')")
