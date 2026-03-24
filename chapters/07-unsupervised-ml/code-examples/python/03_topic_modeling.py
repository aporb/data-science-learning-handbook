"""
Chapter 07: Unsupervised ML - Topic Modeling
=============================================
LDA and BERTopic on federal contract text, FOIA responses,
and program office documents. Includes government-specific
text preprocessing and the LLM-labeling pattern via Palantir AIP.

Requirements:
    pip install scikit-learn pandas numpy gensim
    pip install bertopic sentence-transformers  # For BERTopic
    pip install requests  # For AIP labeling
"""

import re
import warnings
from typing import Optional
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.decomposition import LatentDirichletAllocation

warnings.filterwarnings("ignore")


# ---------------------------------------------------------------------------
# 1. Government text preprocessing
# ---------------------------------------------------------------------------

# Words that appear in nearly every federal contract and carry no
# discriminating information for topic modeling. These swamp the model
# when left in.
GOVERNMENT_STOPWORDS = {
    # Contract boilerplate
    "shall", "contractor", "government", "period", "performance", "requirement",
    "requirements", "provide", "service", "services", "support", "work",
    "contract", "contracts", "agreement", "agreements", "accordance",
    "including", "pursuant", "applicable", "necessary", "ensure",
    "within", "section", "clause", "statement", "attached", "herein",
    "thereof", "therefore", "whereas", "hereby",
    # Solicitation boilerplate
    "offeror", "proposal", "solicitation", "award", "base", "option",
    "year", "years", "period", "ordering",
    # FAR references
    "far", "dfars", "nmcars",
    # Common but uninformative
    "also", "may", "must", "will", "would", "could", "should",
    "use", "used", "using", "time", "new", "total",
}

# Patterns to preserve as single tokens
PRESERVE_PHRASES = [
    (r"earned value management", "earned_value_management"),
    (r"cost plus fixed fee", "cost_plus_fixed_fee"),
    (r"cost\s*-?\s*plus\s*-?\s*fixed\s*-?\s*fee", "cost_plus_fixed_fee"),
    (r"firm fixed price", "firm_fixed_price"),
    (r"indefinite delivery indefinite quantity", "idiq"),
    (r"sole source", "sole_source"),
    (r"small business", "small_business"),
    (r"8\(a\)", "8a_program"),
    (r"service disabled veteran", "sdvosb"),
    (r"women owned", "wosb"),
    (r"other transaction authority", "other_transaction_authority"),
    (r"base and all options", "base_and_options"),
    (r"period of performance", "period_of_performance"),
    (r"naval information warfare", "nifw"),
    (r"program executive office", "peo"),
    (r"program management office", "pmo"),
    (r"technical data package", "technical_data_package"),
    (r"condition based maintenance", "condition_based_maintenance"),
    (r"predictive maintenance", "predictive_maintenance"),
]


def preprocess_government_text(
    texts: list[str],
    preserve_phrases: bool = True,
    min_token_length: int = 3,
) -> list[str]:
    """
    Preprocess federal government text for topic modeling.

    Args:
        texts: List of raw text strings (contract descriptions, FOIA docs, etc.)
        preserve_phrases: If True, multi-word government terms become single tokens
        min_token_length: Discard tokens shorter than this

    Returns:
        List of preprocessed text strings
    """
    processed = []

    for text in texts:
        if not isinstance(text, str) or not text.strip():
            processed.append("")
            continue

        doc = text.lower()

        # Preserve meaningful multi-word phrases before tokenization
        if preserve_phrases:
            for pattern, replacement in PRESERVE_PHRASES:
                doc = re.sub(pattern, replacement, doc, flags=re.IGNORECASE)

        # Remove special characters but keep underscores (from preserved phrases)
        doc = re.sub(r"[^a-z0-9_\s]", " ", doc)

        # Tokenize and filter
        tokens = doc.split()
        tokens = [
            t for t in tokens
            if len(t) >= min_token_length
            and t not in GOVERNMENT_STOPWORDS
            and not t.isdigit()
        ]

        processed.append(" ".join(tokens))

    return processed


# ---------------------------------------------------------------------------
# 2. LDA topic modeling
# ---------------------------------------------------------------------------

def run_lda(
    texts: list[str],
    n_topics: int = 10,
    n_top_words: int = 10,
    max_features: int = 5_000,
    min_df: int = 5,
    max_df: float = 0.85,
    random_state: int = 42,
) -> tuple[LatentDirichletAllocation, CountVectorizer, np.ndarray]:
    """
    Run LDA topic modeling on preprocessed government documents.

    Args:
        texts: Preprocessed text strings (output of preprocess_government_text)
        n_topics: Number of topics to extract
        n_top_words: Number of top words to display per topic
        max_features: Maximum vocabulary size
        min_df: Minimum document frequency for vocabulary inclusion
        max_df: Maximum document frequency (0.85 = ignore words in >85% of docs)
        random_state: For reproducibility

    Returns:
        (model, vectorizer, document_topic_matrix)
        document_topic_matrix shape: (n_documents, n_topics)
    """
    # Remove empty documents
    non_empty = [t for t in texts if t.strip()]
    if len(non_empty) < len(texts):
        print(f"  Warning: {len(texts) - len(non_empty)} empty documents removed")

    vectorizer = CountVectorizer(
        max_features=max_features,
        min_df=min_df,
        max_df=max_df,
        ngram_range=(1, 2),  # Unigrams and bigrams
        strip_accents="unicode",
    )
    X = vectorizer.fit_transform(non_empty)
    print(f"  Vocabulary size: {len(vectorizer.vocabulary_):,}")
    print(f"  Document-term matrix: {X.shape[0]:,} docs x {X.shape[1]:,} terms")

    model = LatentDirichletAllocation(
        n_components=n_topics,
        random_state=random_state,
        learning_method="online",   # Better for large corpora
        max_iter=20,
        batch_size=128,
        n_jobs=-1,
    )
    doc_topic_matrix = model.fit_transform(X)

    # Print top words per topic
    feature_names = vectorizer.get_feature_names_out()
    print(f"\nLDA Topics (top {n_top_words} words each):")
    for topic_idx, topic in enumerate(model.components_):
        top_indices = topic.argsort()[-n_top_words:][::-1]
        top_words = [feature_names[i] for i in top_indices]
        print(f"  Topic {topic_idx:2d}: {', '.join(top_words)}")

    return model, vectorizer, doc_topic_matrix


def assign_dominant_topic(
    doc_topic_matrix: np.ndarray,
    texts: list[str],
    min_confidence: float = 0.3,
) -> pd.DataFrame:
    """
    Assign the dominant topic to each document.

    Documents where no single topic exceeds min_confidence are marked as
    'mixed' — common for long documents that genuinely cover multiple topics.

    Args:
        doc_topic_matrix: Output from run_lda, shape (n_docs, n_topics)
        texts: Original text strings (for preview)
        min_confidence: Minimum topic probability to assign a dominant topic

    Returns:
        DataFrame with dominant_topic, topic_confidence, and text_preview columns
    """
    dominant_topic = np.argmax(doc_topic_matrix, axis=1)
    topic_confidence = np.max(doc_topic_matrix, axis=1)

    result = pd.DataFrame({
        "dominant_topic": dominant_topic,
        "topic_confidence": topic_confidence,
        "is_mixed": topic_confidence < min_confidence,
        "text_preview": [t[:150] + "..." if len(t) > 150 else t for t in texts],
    })

    topic_counts = result["dominant_topic"].value_counts().sort_index()
    print("\nDocuments per topic:")
    for topic_id, count in topic_counts.items():
        pct = count / len(result) * 100
        print(f"  Topic {topic_id}: {count:,} documents ({pct:.1f}%)")

    mixed_count = result["is_mixed"].sum()
    print(f"  Mixed (confidence < {min_confidence}): {mixed_count:,} documents")

    return result


# ---------------------------------------------------------------------------
# 3. BERTopic
# ---------------------------------------------------------------------------

def run_bertopic(
    texts: list[str],
    n_topics: int = 20,
    min_topic_size: int = 10,
    nr_repr_docs: int = 5,
    embedding_model_name: str = "all-MiniLM-L6-v2",
) -> tuple[object, list[int], list[float]]:
    """
    Run BERTopic on government contract or document text.

    BERTopic outperforms LDA on:
    - Short texts (< 200 words per document)
    - Technically specialized vocabulary
    - Corpora where the same concept appears with varying terminology

    Uses sentence-transformers for embeddings — runs locally, no API needed.
    On CPU, embedding ~50K documents with all-MiniLM-L6-v2 takes ~15 minutes.
    On a Databricks GPU cluster, the same job runs in under 2 minutes.

    Args:
        texts: Raw or lightly preprocessed text strings
        n_topics: Approximate number of topics (BERTopic auto-adjusts)
        min_topic_size: Minimum documents per topic
        nr_repr_docs: Number of representative documents shown per topic
        embedding_model_name: Sentence transformer model to use

    Returns:
        (model, topic_assignments, probabilities)

    Requires: pip install bertopic sentence-transformers
    """
    try:
        from bertopic import BERTopic
        from sentence_transformers import SentenceTransformer
    except ImportError:
        raise ImportError("pip install bertopic sentence-transformers")

    non_empty_texts = [t if isinstance(t, str) and t.strip() else "unknown" for t in texts]

    embedding_model = SentenceTransformer(embedding_model_name)
    print(f"  Embedding model: {embedding_model_name}")

    topic_model = BERTopic(
        embedding_model=embedding_model,
        nr_topics=n_topics,
        min_topic_size=min_topic_size,
        verbose=True,
        calculate_probabilities=False,  # Faster; set True for soft assignments
    )

    topics, probs = topic_model.fit_transform(non_empty_texts)

    n_actual_topics = len(set(topics)) - (1 if -1 in topics else 0)
    n_outliers = topics.count(-1)
    print(f"\n  Topics found: {n_actual_topics}")
    print(f"  Outlier documents (topic -1): {n_outliers:,} ({n_outliers/len(topics)*100:.1f}%)")

    print(f"\nTop topics (top 7 words each):")
    for topic_id in sorted(set(topics)):
        if topic_id == -1:
            continue
        topic_words = topic_model.get_topic(topic_id)
        if not topic_words:
            continue
        top_words = [word for word, _ in topic_words[:7]]
        doc_count = topics.count(topic_id)
        print(f"  Topic {topic_id:3d} ({doc_count:4d} docs): {', '.join(top_words)}")

    return topic_model, topics, probs


def label_topics_with_llm(
    topic_model: object,
    foundry_url: str,
    bearer_token: str,
    ontology_rid: str,
    n_sample_docs: int = 10,
) -> dict[int, str]:
    """
    Use Palantir AIP Logic to generate human-readable topic labels.

    After BERTopic produces topics, this function:
    1. Assembles representative documents + top words for each topic
    2. Calls an LLM via the Foundry AIP REST API
    3. Returns a dict mapping topic_id -> label

    The LLM-generated labels replace "Topic 0, Topic 1..." with
    plain-language names like "Ship Propulsion Maintenance",
    "Software License Procurement", etc.

    This requires AIP to be enabled on your Foundry enrollment.
    Foundry API docs: https://www.palantir.com/docs/foundry/api/

    Args:
        topic_model: Fitted BERTopic model
        foundry_url: Base Foundry URL
        bearer_token: Foundry bearer token
        ontology_rid: Ontology RID for AIP Logic calls
        n_sample_docs: Representative docs to include per topic

    Returns:
        Dict mapping topic_id to LLM-generated label string
    """
    import requests

    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
    }

    topic_ids = [t for t in topic_model.get_topics() if t != -1]
    labels = {}

    for topic_id in topic_ids:
        topic_words = topic_model.get_topic(topic_id)
        if not topic_words:
            labels[topic_id] = f"Topic {topic_id}"
            continue

        top_words = [word for word, _ in topic_words[:10]]

        # Build the AIP Logic prompt
        prompt = (
            f"Top words from a topic cluster: {', '.join(top_words)}\n\n"
            "Based only on these words, what is the most likely subject matter "
            "of these government documents? Answer in 5 words or fewer."
        )

        # AIP Logic completion endpoint
        url = f"{foundry_url}/api/v2/aipAgents/agents/completions"
        payload = {
            "prompt": prompt,
            "maxTokens": 30,
            "temperature": 0.1,
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=15)
            response.raise_for_status()
            label = response.json().get("completion", "").strip()
            labels[topic_id] = label if label else f"Topic {topic_id}"
        except Exception as e:
            print(f"  LLM labeling failed for topic {topic_id}: {e}")
            labels[topic_id] = f"Topic {topic_id}"

    return labels


# ---------------------------------------------------------------------------
# 4. TF-IDF based document characterization
# ---------------------------------------------------------------------------

def tfidf_cluster_keywords(
    texts: list[str],
    cluster_assignments: list[int],
    n_keywords: int = 15,
    max_features: int = 10_000,
) -> dict[int, list[str]]:
    """
    Extract the most distinctive keywords for each cluster using TF-IDF.
    This is the same approach BERTopic uses internally (c-TF-IDF).

    Useful as a lightweight alternative to BERTopic when you already have
    cluster assignments from another source (e.g., Palantir Ontology
    clustering or K-means on embeddings).

    Args:
        texts: Raw document texts
        cluster_assignments: Cluster label per document
        n_keywords: Top keywords to return per cluster
        max_features: Maximum vocabulary size

    Returns:
        Dict mapping cluster_id -> list of top keywords
    """
    cluster_ids = sorted(set(c for c in cluster_assignments if c != -1))

    # Build one "super-document" per cluster (concatenate all member docs)
    cluster_docs = {}
    for cid in cluster_ids:
        members = [texts[i] for i, c in enumerate(cluster_assignments) if c == cid]
        cluster_docs[cid] = " ".join(members)

    doc_list = [cluster_docs[cid] for cid in cluster_ids]

    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 2),
        min_df=1,
        sublinear_tf=True,
    )
    tfidf_matrix = vectorizer.fit_transform(doc_list)
    feature_names = vectorizer.get_feature_names_out()

    keywords = {}
    for i, cid in enumerate(cluster_ids):
        row = tfidf_matrix[i].toarray().flatten()
        top_indices = row.argsort()[-n_keywords:][::-1]
        keywords[cid] = [feature_names[j] for j in top_indices]

    return keywords


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Synthetic contract description corpus
    sample_contracts = [
        "Provide cybersecurity services including penetration testing, vulnerability assessments, and incident response for Navy networks.",
        "Systems engineering and technical assistance for ship systems integration, including propulsion and combat systems.",
        "Software development and maintenance for financial management systems supporting audit readiness.",
        "Provide logistics and supply chain management services for aircraft parts and components.",
        "Information technology modernization including cloud migration and enterprise architecture services.",
        "Naval architecture and marine engineering services for ship design and maintenance.",
        "Cybersecurity operations center services for continuous monitoring and threat detection.",
        "Aircraft maintenance and repair services for rotary wing aircraft systems.",
        "Data analytics and business intelligence services supporting financial audit compliance.",
        "Systems integration and test services for combat management systems.",
    ] * 20  # Repeat to simulate a realistic corpus size

    print("=== Government Text Preprocessing ===")
    processed = preprocess_government_text(sample_contracts[:5])
    for i, (raw, proc) in enumerate(zip(sample_contracts[:3], processed[:3])):
        print(f"\nRaw: {raw[:80]}...")
        print(f"Processed: {proc[:80]}...")

    print("\n=== LDA Topic Modeling ===")
    processed_all = preprocess_government_text(sample_contracts)
    lda_model, vectorizer, doc_topics = run_lda(
        processed_all,
        n_topics=5,
        n_top_words=8,
        min_df=2,
    )

    assignments = assign_dominant_topic(doc_topics, sample_contracts)
    print(f"\nTopic assignment sample:")
    print(assignments.head(5)[["dominant_topic", "topic_confidence", "text_preview"]]
          .to_string(index=False))

    print("\n=== TF-IDF Cluster Keywords ===")
    keywords = tfidf_cluster_keywords(
        sample_contracts,
        cluster_assignments=assignments["dominant_topic"].tolist(),
        n_keywords=5,
    )
    for cid, kws in keywords.items():
        print(f"  Cluster {cid}: {', '.join(kws)}")
