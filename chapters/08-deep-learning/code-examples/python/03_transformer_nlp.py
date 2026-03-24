"""
Chapter 08 — Deep Learning and Neural Networks
Example 03: Transformer fine-tuning for government document NLP

Use case: Classify contract description text into procurement categories
Platform: Databricks ML Runtime (A10g GPU), Advana, Navy Jupiter

Key concepts:
    - BERT fine-tuning via HuggingFace Transformers + Trainer API
    - Handling long documents beyond BERT's 512-token limit (chunking strategy)
    - MLflow integration via report_to="mlflow" in TrainingArguments
    - Model registration in Unity Catalog (Databricks)
    - Handling class imbalance in government procurement data

Dependencies: transformers, torch, scikit-learn, numpy, pandas, mlflow
"""

import logging
import re
from typing import Optional

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset
from transformers import (
    BertTokenizer,
    BertForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.utils.class_weight import compute_class_weight
import mlflow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONTRACT_CATEGORIES = [
    "IT Services",
    "Professional Services",
    "Construction",
    "Equipment and Supplies",
    "Research and Development",
    "Other",
]
N_LABELS = len(CONTRACT_CATEGORIES)
LABEL2ID = {c: i for i, c in enumerate(CONTRACT_CATEGORIES)}
ID2LABEL = {i: c for i, c in enumerate(CONTRACT_CATEGORIES)}

BERT_MAX_TOKENS = 512        # Hard limit for BERT-base
LONG_DOC_CHUNK_SIZE = 480    # Tokens per chunk (leave room for [CLS] and [SEP])
LONG_DOC_STRIDE = 128        # Overlap between chunks (avoids missing context at boundaries)

# ---------------------------------------------------------------------------
# Synthetic data generator
# ---------------------------------------------------------------------------

def generate_contract_dataset(n_samples: int = 5_000, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic contract description text for each procurement category.
    Mimics the language and structure of real FPDS/USASpending contract descriptions.
    """
    rng = np.random.RandomState(seed)

    templates = {
        "IT Services": [
            "Cloud infrastructure modernization and migration support services for {agency} data center consolidation initiative",
            "Software development and maintenance for {agency} enterprise resource planning system",
            "Cybersecurity operations and monitoring for {agency} network perimeter defense",
            "IT helpdesk and end-user support services for {agency} distributed workforce",
            "Data analytics platform development and integration services for {agency}",
            "DevSecOps support for {agency} cloud-native application development program",
        ],
        "Professional Services": [
            "Management consulting and organizational change management support for {agency}",
            "Financial management advisory services for {agency} budget formulation",
            "Program management support for {agency} major acquisition program",
            "Strategic communications and outreach support for {agency} public affairs office",
            "Acquisition support and contract administration services for {agency} contracting office",
        ],
        "Construction": [
            "Renovation and repair of {agency} administrative building HVAC systems",
            "Construction of new warehouse facility at {agency} logistics support area",
            "Pavement repair and maintenance for {agency} airfield taxiway and runway surfaces",
            "Installation of security fencing and access control at {agency} installation",
            "Demolition of condemned structures at {agency} former industrial complex",
        ],
        "Equipment and Supplies": [
            "Procurement of commercial off-the-shelf server hardware for {agency} data center refresh",
            "Vehicular parts and components for {agency} fleet maintenance program",
            "Medical supplies and consumables for {agency} healthcare facility",
            "Personal protective equipment and safety gear for {agency} hazmat response teams",
            "Office furniture and workstation equipment for {agency} space consolidation",
        ],
        "Research and Development": [
            "Basic research in advanced materials for next-generation {agency} system applications",
            "Applied research and technology demonstration for autonomous unmanned system navigation",
            "Prototype development and testing of directed energy weapon component for {agency}",
            "Human factors research supporting {agency} operator interface design standards",
            "Science and technology investment in quantum computing for cryptographic applications",
        ],
        "Other": [
            "Janitorial and custodial services for {agency} administrative facilities",
            "Food service and dining facility operations at {agency} installation",
            "Vehicle and equipment maintenance and repair for {agency} fleet",
            "Training and education services for {agency} workforce development program",
            "Translation and interpretation services for {agency} international operations",
        ],
    }

    agencies = ["DoD", "Navy", "Army", "Air Force", "DHS", "VA", "HHS", "DOJ", "DLA", "USACE"]

    texts, labels = [], []
    per_category = n_samples // len(CONTRACT_CATEGORIES)

    for category, tmpl_list in templates.items():
        for _ in range(per_category):
            tmpl = tmpl_list[rng.randint(0, len(tmpl_list))]
            agency = agencies[rng.randint(0, len(agencies))]
            text = tmpl.format(agency=agency)

            # Add noise: sometimes descriptions are longer with boilerplate
            if rng.random() > 0.6:
                boilerplate = (
                    " The contractor shall provide qualified personnel and all materials, "
                    "equipment, tools, and other items necessary for the performance of this work. "
                    "Services shall be performed in accordance with applicable federal regulations "
                    "and agency-specific requirements."
                )
                text += boilerplate

            texts.append(text)
            labels.append(LABEL2ID[category])

    # Shuffle
    idx = rng.permutation(len(texts))
    return pd.DataFrame({
        "description": [texts[i] for i in idx],
        "label": [labels[i] for i in idx],
        "category": [CONTRACT_CATEGORIES[labels[i]] for i in idx],
    })


# ---------------------------------------------------------------------------
# Dataset class
# ---------------------------------------------------------------------------

class ContractTextDataset(Dataset):
    """
    HuggingFace-compatible dataset for contract text classification.
    Handles tokenization at construction time for efficiency.
    """

    def __init__(
        self,
        texts: list,
        labels: list,
        tokenizer: BertTokenizer,
        max_length: int = BERT_MAX_TOKENS,
    ):
        log.info("Tokenizing %s examples (max_length=%s)...", f"{len(texts):,}", max_length)
        self.encodings = tokenizer(
            texts,
            truncation=True,
            padding="max_length",
            max_length=max_length,
            return_tensors="pt",
        )
        self.labels = torch.tensor(labels, dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return {
            "input_ids":      self.encodings["input_ids"][idx],
            "attention_mask": self.encodings["attention_mask"][idx],
            "labels":         self.labels[idx],
        }


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(eval_pred) -> dict:
    """Metrics function for HuggingFace Trainer."""
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy":    accuracy_score(labels, preds),
        "f1_macro":    f1_score(labels, preds, average="macro"),
        "f1_weighted": f1_score(labels, preds, average="weighted"),
    }


# ---------------------------------------------------------------------------
# Fine-tuning pipeline
# ---------------------------------------------------------------------------

def fine_tune_contract_classifier(
    df: pd.DataFrame,
    output_dir: str = "./contract_bert",
    n_epochs: int = 4,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
    warmup_ratio: float = 0.1,
    mlflow_experiment: str = "contract_classification",
) -> BertForSequenceClassification:
    """
    Fine-tune BERT-base for contract description classification.

    Learning rate 2e-5 is the standard recommendation for BERT fine-tuning.
    Too high (>5e-5) causes catastrophic forgetting of pre-trained representations.
    Too low (<1e-5) results in slow convergence and underfitting.

    The Trainer API handles:
        - Gradient accumulation
        - Mixed precision (fp16=True on GPU)
        - MLflow logging (report_to="mlflow")
        - Best model loading from checkpoint
    """
    mlflow.set_experiment(mlflow_experiment)

    texts  = df["description"].tolist()
    labels = df["label"].tolist()

    # Stratified split preserves class distribution across train/val
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.15, stratify=labels, random_state=42
    )

    log.info("Train: %s | Val: %s", f"{len(train_texts):,}", f"{len(val_texts):,}")

    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
    train_ds = ContractTextDataset(train_texts, train_labels, tokenizer)
    val_ds   = ContractTextDataset(val_texts,   val_labels,   tokenizer)

    model = BertForSequenceClassification.from_pretrained(
        "bert-base-uncased",
        num_labels=N_LABELS,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        hidden_dropout_prob=0.1,
        attention_probs_dropout_prob=0.1,
    )

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=n_epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size * 2,
        learning_rate=learning_rate,
        warmup_ratio=warmup_ratio,
        weight_decay=0.01,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1_weighted",
        greater_is_better=True,
        logging_steps=50,
        report_to="mlflow",         # Automatic MLflow tracking on Databricks
        fp16=torch.cuda.is_available(),
        dataloader_num_workers=0,   # Use 0 for compatibility in notebooks
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    trainer.train()

    # Final evaluation with detailed per-class report
    predictions = trainer.predict(val_ds)
    preds = np.argmax(predictions.predictions, axis=-1)
    report = classification_report(
        val_labels, preds,
        target_names=CONTRACT_CATEGORIES,
        output_dict=True
    )

    log.info("Final validation metrics:")
    log.info("  Accuracy:    %.4f", report["accuracy"])
    log.info("  Macro F1:    %.4f", report["macro avg"]["f1-score"])
    log.info("  Weighted F1: %.4f", report["weighted avg"]["f1-score"])

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

    # On Databricks: register in Unity Catalog Model Registry
    # mlflow.transformers.log_model(
    #     transformers_model={"model": model, "tokenizer": tokenizer},
    #     artifact_path="model",
    #     registered_model_name="procurement_catalog.models.contract_classifier",
    # )

    return model


# ---------------------------------------------------------------------------
# Long document handling: chunking strategy for FAR clauses / IG reports
# ---------------------------------------------------------------------------

def classify_long_document(
    text: str,
    model: BertForSequenceClassification,
    tokenizer: BertTokenizer,
    chunk_size: int = LONG_DOC_CHUNK_SIZE,
    stride: int = LONG_DOC_STRIDE,
    device: str = "cpu",
) -> dict:
    """
    Classify a document that exceeds BERT's 512-token limit.

    Strategy: sliding window chunking with overlap.
    - Split document into overlapping chunks of `chunk_size` tokens
    - Classify each chunk independently
    - Aggregate by averaging softmax probabilities across all chunks

    This is more reliable than truncation (which loses document tail)
    and simpler than hierarchical models (which require more code and training).

    When to use a different strategy:
    - If document structure matters (beginning vs. end carry different signals),
      weight the first and last chunks more heavily
    - If processing > 10,000 documents, use a long-context model (Longformer)
      to avoid the overhead of multiple BERT forward passes per document
    """
    # Tokenize without truncation to get full token sequence
    tokens = tokenizer(
        text,
        truncation=False,
        return_tensors="pt",
        add_special_tokens=False,  # We'll add them per-chunk
    )
    input_ids = tokens["input_ids"][0]  # Shape: (full_token_length,)
    n_tokens = len(input_ids)

    if n_tokens <= chunk_size:
        # Short enough for single pass
        encoding = tokenizer(
            text, truncation=True, max_length=BERT_MAX_TOKENS,
            padding="max_length", return_tensors="pt"
        )
        encoding = {k: v.to(device) for k, v in encoding.items()}
        model.train(False)
        with torch.no_grad():
            logits = model(**encoding).logits
        probs = torch.softmax(logits, dim=-1)[0].cpu().numpy()
        return _format_prediction(probs)

    # Chunking: stride through the token sequence
    chunk_probs_list = []
    start = 0
    while start < n_tokens:
        end = min(start + chunk_size, n_tokens)
        chunk_ids = input_ids[start:end]

        # Add [CLS] and [SEP] tokens
        cls_id = tokenizer.cls_token_id
        sep_id = tokenizer.sep_token_id
        chunk_with_special = torch.cat([
            torch.tensor([cls_id]),
            chunk_ids,
            torch.tensor([sep_id])
        ])

        # Pad to max_length
        pad_length = BERT_MAX_TOKENS - len(chunk_with_special)
        if pad_length > 0:
            pad_ids = torch.full((pad_length,), tokenizer.pad_token_id)
            chunk_with_special = torch.cat([chunk_with_special, pad_ids])

        attention_mask = (chunk_with_special != tokenizer.pad_token_id).long()

        input_dict = {
            "input_ids":      chunk_with_special.unsqueeze(0).to(device),
            "attention_mask": attention_mask.unsqueeze(0).to(device),
        }

        model.train(False)
        with torch.no_grad():
            logits = model(**input_dict).logits
        probs = torch.softmax(logits, dim=-1)[0].cpu().numpy()
        chunk_probs_list.append(probs)

        if end == n_tokens:
            break
        start += chunk_size - stride

    # Average across chunks
    avg_probs = np.mean(chunk_probs_list, axis=0)
    return _format_prediction(avg_probs, n_chunks=len(chunk_probs_list))


def _format_prediction(probs: np.ndarray, n_chunks: int = 1) -> dict:
    pred_idx = int(probs.argmax())
    return {
        "predicted_category": CONTRACT_CATEGORIES[pred_idx],
        "confidence": float(probs[pred_idx]),
        "class_probabilities": {CONTRACT_CATEGORIES[i]: float(p) for i, p in enumerate(probs)},
        "n_chunks_processed": n_chunks,
        "requires_human_review": float(probs[pred_idx]) < 0.70,
    }


# ---------------------------------------------------------------------------
# Batch inference for production use
# ---------------------------------------------------------------------------

def classify_contract_batch(
    texts: list,
    model: BertForSequenceClassification,
    tokenizer: BertTokenizer,
    batch_size: int = 64,
    device: str = "cpu",
    confidence_threshold: float = 0.70,
) -> pd.DataFrame:
    """
    Classify a batch of contract descriptions.
    Automatically routes long documents through the chunking strategy.
    Returns a DataFrame with predictions, confidence scores, and review flags.
    """
    model = model.to(device)
    results = []

    for i in range(0, len(texts), batch_size):
        batch_texts = texts[i:i + batch_size]
        for text in batch_texts:
            # Quick token length check
            n_tokens = len(tokenizer.encode(text, add_special_tokens=False))
            if n_tokens > LONG_DOC_CHUNK_SIZE:
                result = classify_long_document(text, model, tokenizer, device=device)
            else:
                encoding = tokenizer(
                    text, truncation=True, max_length=BERT_MAX_TOKENS,
                    padding="max_length", return_tensors="pt"
                )
                encoding = {k: v.to(device) for k, v in encoding.items()}
                model.train(False)
                with torch.no_grad():
                    logits = model(**encoding).logits
                probs = torch.softmax(logits, dim=-1)[0].cpu().numpy()
                result = _format_prediction(probs)

            result["text_preview"] = text[:80] + "..." if len(text) > 80 else text
            result["requires_human_review"] = result["confidence"] < confidence_threshold
            results.append(result)

        log.info("Classified %s / %s contracts", min(i + batch_size, len(texts)), len(texts))

    return pd.DataFrame(results)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("Generating synthetic contract dataset...")
    df = generate_contract_dataset(n_samples=3_000)

    log.info("Dataset: %s samples | Class distribution:", len(df))
    print(df["category"].value_counts().to_string())

    log.info("\nStarting BERT fine-tuning...")
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmpdir:
        model = fine_tune_contract_classifier(
            df,
            output_dir=os.path.join(tmpdir, "contract_bert"),
            n_epochs=2,        # Small for demo; use 4 in production
            batch_size=8,
        )

        tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

        # Test on a few examples
        test_texts = [
            "Cloud hosting and DevSecOps pipeline support for Navy data lake modernization",
            "Construction of maintenance facility and vehicle inspection bay at Fort Bragg",
            "Prototype development for hypersonic glide vehicle thermal protection system",
            (
                "The contractor shall provide all labor, materials, equipment, and supervision "
                "necessary for professional accounting and financial audit support services. "
                "Services include reviewing internal controls, conducting compliance assessments, "
                "and providing recommendations to improve financial management practices. "
                "The contractor shall have access to all relevant financial records and systems "
                "as authorized by the Contracting Officer. All work shall comply with generally "
                "accepted government auditing standards (GAGAS) and agency-specific requirements."
            )
        ]

        predictions = classify_contract_batch(
            test_texts, model, tokenizer, device="cpu", confidence_threshold=0.70
        )

        print("\n=== Predictions ===")
        for _, row in predictions.iterrows():
            review_flag = " ← REVIEW" if row["requires_human_review"] else ""
            print(f"  '{row['text_preview']}'")
            print(f"    → {row['predicted_category']} ({row['confidence']:.1%})"
                  f"  chunks={row['n_chunks_processed']}{review_flag}\n")
