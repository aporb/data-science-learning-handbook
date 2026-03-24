# Chapter 08 Exercises: Deep Learning and Neural Networks

These exercises are structured around realistic DoD and federal agency scenarios. They build progressively — Exercise 1 establishes the foundations, Exercise 4 is the integration challenge that brings everything together.

---

## Exercise 1: Build a Neural Network from Scratch

**Context:** You're on a contract with the Defense Logistics Agency (DLA). Your team has 80,000 records of supply item demand history and needs to predict whether each item will experience a critical shortage in the next 90 days. The dataset is tabular: item category (300 categories), supply class (20 classes), days-of-supply remaining (continuous), average monthly demand (continuous), lead time in days (continuous), and number of active requisitions (count).

A DLA analyst tried logistic regression and got 71% accuracy. Your baseline XGBoost got 76%. The program office wants to see if a neural network can do better.

**Tasks:**

**1a.** Write a PyTorch `nn.Module` for this problem. Requirements:
- Learned embeddings for `item_category` (300 categories → 24-dim) and `supply_class` (20 categories → 6-dim)
- 3 hidden layers: 128 → 64 → 32 neurons
- BatchNorm1d and Dropout (rate=0.3) after each hidden layer
- Sigmoid output for binary classification

Print the model architecture and total trainable parameter count.

**1b.** Write a training loop (no Trainer API — manual PyTorch). Use:
- AdamW optimizer, learning rate 1e-3, weight_decay 1e-4
- BCELoss
- Time-based train/val split: last 15% of records chronologically → validation

Run 20 epochs. Print train loss and val loss every 5 epochs.

**1c.** Implement early stopping: stop training if validation loss doesn't improve for 5 consecutive epochs. Save the best model weights.

**1d.** Evaluate your best model against the XGBoost baseline. Does the neural network beat 76% accuracy? If not, what does that tell you about whether deep learning is the right tool for this problem?

**Setup:**
```python
import numpy as np
import pandas as pd
import torch

np.random.seed(42)
torch.manual_seed(42)
n = 80_000

# Simulate DLA supply item dataset
df = pd.DataFrame({
    "item_category": np.random.randint(0, 300, size=n),
    "supply_class": np.random.randint(0, 20, size=n),
    "days_of_supply": np.random.exponential(scale=45, size=n).clip(0, 365).astype(np.float32),
    "avg_monthly_demand": np.random.gamma(2, 50, size=n).astype(np.float32),
    "lead_time_days": np.random.exponential(scale=30, size=n).clip(1, 180).astype(np.float32),
    "active_requisitions": np.random.poisson(3, size=n).astype(np.float32),
    "record_date": pd.date_range("2022-01-01", periods=n, freq="1H"),
})
# Label: shortage if days_of_supply < 14 AND avg_monthly_demand > lead_time_days
shortage_risk = (df["days_of_supply"] < 14) & (df["avg_monthly_demand"] / 30 > df["lead_time_days"] / 60)
df["shortage_flag"] = shortage_risk.astype(int)
print(f"Shortage rate: {df['shortage_flag'].mean():.1%}")
```

---

## Exercise 2: CNN Transfer Learning for Equipment Anomaly Detection

**Context:** The Naval Aviation Systems Command (NAVAIR) has given your team 2,400 labeled photographs of aircraft engine components — 800 from "nominal" inspections, 800 from "minor defect" inspections, and 800 from "major defect" inspections requiring immediate maintenance. The goal: build an automated visual inspection classifier to prioritize maintenance queues.

2,400 images is not enough to train a CNN from scratch. Transfer learning is required.

**Tasks:**

**2a.** Set up a ResNet-18 (smaller than ResNet-50 — appropriate for a 3-class problem with limited data) with:
- Frozen backbone (all layers except the final classification head)
- A custom head: Dropout(0.5) → Linear(512, 128) → ReLU → Linear(128, 3)
- How many parameters are trainable in this configuration?

**2b.** Define appropriate train and validation transforms. Your images are close-up photographs of engine components under controlled lighting. Unlike satellite imagery, these do NOT benefit from RandomVerticalFlip. What augmentations are appropriate? Justify your choices.

**2c.** Write the training loop. Use:
- CrossEntropyLoss with label_smoothing=0.1
- SGD with momentum=0.9, lr=1e-2 for the head
- Run for 15 epochs

**2d.** After 15 epochs, unfreeze the last two convolutional blocks of ResNet-18 (`layer3` and `layer4`) and fine-tune for 10 more epochs with a lower learning rate (1e-4 for backbone, 1e-3 for head). Compare validation accuracy before and after unfreezing.

**2e.** For the "major defect" class — the safety-critical category — compute the false positive rate at your model's current performance. Is it acceptable for an automated maintenance prioritization system? What would you change if it isn't?

**Setup:**
```python
# Use torchvision's FakeData for structure testing (no real imagery required)
import torchvision
from torchvision.datasets import FakeData
import torchvision.transforms as transforms

# FakeData generates random tensors in the shape of real image datasets
# In a real NAVAIR deployment, images come from the depot's inspection camera system
# stored in a Unity Catalog managed volume

CLASSES = ["nominal", "minor_defect", "major_defect"]
N_CLASSES = 3

# Simulate class-imbalanced dataset (more nominal than defective)
# This mimics real inspection data where defects are relatively rare
```

---

## Exercise 3: BERT Fine-Tuning for Regulatory Document Classification

**Context:** The DoD IG (Inspector General) office produces hundreds of audit reports per year. Each report covers one or more oversight areas: financial management, contract management, cybersecurity, personnel, facilities, or acquisitions. The IG office wants to automatically tag incoming reports by oversight area to route them to the correct analyst team.

You have 1,200 labeled report excerpts (200 per category).

**Tasks:**

**3a.** Fine-tune `distilbert-base-uncased` (a smaller, faster BERT variant — appropriate for a resource-constrained environment or when latency matters) for 6-class classification. Use the HuggingFace Trainer API with `report_to="none"` (local testing without MLflow).

**3b.** Government documents often contain dense regulatory language that fills the 512-token limit. Write a function `check_token_lengths(texts, tokenizer)` that takes a list of texts and returns:
- The percentage of texts that exceed 256, 384, and 512 tokens
- The mean and 95th percentile token length
- A recommendation: should you truncate, chunk, or use a long-context model?

**3c.** Implement the chunking strategy from `03_transformer_nlp.py` and classify a synthetic "long document" — a 1,500-token text constructed by repeating a short excerpt. Verify that the chunking function produces the same predicted category as direct truncation on a sample of short documents.

**3d.** The IG office asks: "For the cybersecurity oversight category specifically, what is the model's false discovery rate?" (False discovery rate = false positives / total positive predictions.) Compute this from your validation set. If it's above 15%, what are two architectural or data changes you could try?

**Setup:**
```python
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification

IG_CATEGORIES = [
    "financial_management",
    "contract_management",
    "cybersecurity",
    "personnel",
    "facilities",
    "acquisitions",
]

# Generate synthetic IG report excerpts
category_keywords = {
    "financial_management": ["audit", "financial statement", "obligation", "disbursement", "internal control"],
    "contract_management": ["contractor", "performance", "statement of work", "deliverable", "CLIN"],
    "cybersecurity": ["FISMA", "vulnerability", "incident", "access control", "network"],
    "personnel": ["security clearance", "background investigation", "conduct", "personnel action"],
    "facilities": ["building", "maintenance", "infrastructure", "real property", "renovation"],
    "acquisitions": ["solicitation", "award", "competition", "FAR", "source selection"],
}
```

---

## Exercise 4: Integration Challenge — Operational AI Pipeline with Audit Trail

**Context:** You're deploying a contract anomaly detection system for the DoD IG. The system classifies contracts into three risk tiers: low risk, medium risk, and high risk (requires immediate investigative review). High-risk misclassification — specifically, classifying a high-risk contract as low-risk — is the dangerous failure mode. The program office has specified a false negative rate on the high-risk class of no more than 2%.

**Tasks:**

**4a.** Build a simple feedforward classifier for 3-class contract risk using the tabular features below. The exact architecture is your choice — justify it briefly in a comment.

```python
import numpy as np
import pandas as pd
import torch

np.random.seed(99)
n = 10_000

df_contracts = pd.DataFrame({
    "contract_value_log": np.log1p(np.random.exponential(500_000, size=n)).astype(np.float32),
    "n_modifications": np.random.poisson(2.5, size=n).astype(np.float32),
    "days_to_award": np.random.exponential(45, size=n).clip(1, 365).astype(np.float32),
    "vendor_past_violations": np.random.poisson(0.3, size=n).astype(np.float32),
    "sole_source_flag": np.random.binomial(1, 0.15, size=n).astype(np.float32),
    "naics_sector": np.random.randint(0, 23, size=n),
})
# Label: high risk if multiple red flags
high_risk = (
    (df_contracts["vendor_past_violations"] > 1) |
    ((df_contracts["sole_source_flag"] == 1) & (df_contracts["contract_value_log"] > np.log(5_000_000)))
)
low_risk = ~high_risk & (df_contracts["n_modifications"] <= 2)
df_contracts["risk_tier"] = 0  # low
df_contracts.loc[~low_risk & ~high_risk, "risk_tier"] = 1  # medium
df_contracts.loc[high_risk, "risk_tier"] = 2  # high
```

**4b.** Wrap your trained model in the `OperationalInferencePipeline` from `04_operational_inference_pipeline.py`. Set the confidence threshold to 0.80.

**4c.** Run inference on a held-out test set of 1,000 contracts. Capture the full audit log. From the audit log, report:
- Total inferences run
- Percentage routed to human review (confidence < 0.80)
- Predicted class distribution across auto-classified records only

**4d.** Run the full `evaluate_operational_model()` evaluation. The safety-critical class is `high_risk` (index 2). Does your model meet the 2% false negative rate requirement on the high-risk class? (Note: false negative rate = 1 - recall for the high-risk class.)

**4e.** If your model does NOT meet the 2% false negative requirement, identify one concrete change that would likely help: changing the confidence threshold, rebalancing training data, adjusting the classification threshold independently (using a lower decision boundary for the high-risk class), or modifying the architecture. Implement whichever change you choose and re-evaluate.

---

## Submission Format

For each exercise, provide:
1. Working Python code with brief comments on non-obvious decisions
2. Printed output demonstrating the results (accuracy, AUC, FPR, etc.)
3. A 2-3 sentence written answer for any qualitative question (e.g., 1d, 2b, 2e, 3d)

See [solutions/solutions.md](./solutions/solutions.md) for reference implementations.
