# Chapter 08 Exercise Solutions

Reference implementations for all exercises. These show one correct path — architecture choices, hyperparameters, and evaluation thresholds can legitimately vary. What matters is the reasoning behind each decision.

---

## Exercise 1 Solutions: Feedforward Network from Scratch

### 1a — Model architecture

```python
import torch
import torch.nn as nn

class DLAShortagePredictor(nn.Module):
    def __init__(self):
        super().__init__()
        # Embedding sizes: rule of thumb min(50, (n_categories + 1) // 2)
        self.item_cat_emb = nn.Embedding(300, 24)   # 300 categories → 24-dim
        self.supply_cls_emb = nn.Embedding(20, 6)    # 20 classes → 6-dim

        # Input: 24 + 6 + 4 continuous = 34
        self.network = nn.Sequential(
            nn.Linear(34, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, item_cat, supply_cls, continuous):
        ic = self.item_cat_emb(item_cat)
        sc = self.supply_cls_emb(supply_cls)
        x = torch.cat([ic, sc, continuous], dim=1)
        return self.network(x).squeeze(1)

model = DLAShortagePredictor()
total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
print(f"Trainable parameters: {total_params:,}")
# Output: ~45,000 parameters — small enough for fast training, sufficient for this problem
```

---

### 1b, 1c — Training loop with early stopping

```python
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler

np.random.seed(42)
torch.manual_seed(42)
n = 80_000

df = pd.DataFrame({
    "item_category": np.random.randint(0, 300, size=n),
    "supply_class": np.random.randint(0, 20, size=n),
    "days_of_supply": np.random.exponential(scale=45, size=n).clip(0, 365).astype(np.float32),
    "avg_monthly_demand": np.random.gamma(2, 50, size=n).astype(np.float32),
    "lead_time_days": np.random.exponential(scale=30, size=n).clip(1, 180).astype(np.float32),
    "active_requisitions": np.random.poisson(3, size=n).astype(np.float32),
    "record_date": pd.date_range("2022-01-01", periods=n, freq="1H"),
})
shortage_risk = (df["days_of_supply"] < 14) & (df["avg_monthly_demand"] / 30 > df["lead_time_days"] / 60)
df["shortage_flag"] = shortage_risk.astype(int)

# Time-based split
df_sorted = df.sort_values("record_date").reset_index(drop=True)
split_idx = int(len(df_sorted) * 0.85)
df_train = df_sorted.iloc[:split_idx]
df_val   = df_sorted.iloc[split_idx:]

cont_cols = ["days_of_supply", "avg_monthly_demand", "lead_time_days", "active_requisitions"]
scaler = StandardScaler()
X_train_cont = scaler.fit_transform(df_train[cont_cols].values).astype(np.float32)
X_val_cont   = scaler.transform(df_val[cont_cols].values).astype(np.float32)

def make_loader(df_split, X_cont, batch_size, shuffle):
    ds = TensorDataset(
        torch.tensor(df_split["item_category"].values, dtype=torch.long),
        torch.tensor(df_split["supply_class"].values, dtype=torch.long),
        torch.tensor(X_cont, dtype=torch.float32),
        torch.tensor(df_split["shortage_flag"].values, dtype=torch.float32),
    )
    return DataLoader(ds, batch_size=batch_size, shuffle=shuffle)

train_loader = make_loader(df_train, X_train_cont, 512, shuffle=True)
val_loader   = make_loader(df_val, X_val_cont, 512, shuffle=False)

model = DLAShortagePredictor()
optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
criterion = nn.BCELoss()

best_val_loss = float("inf")
patience_counter = 0
patience = 5

for epoch in range(1, 21):
    model.train()
    train_losses = []
    for ic, sc, cont, labels in train_loader:
        optimizer.zero_grad()
        preds = model(ic, sc, cont)
        loss = criterion(preds, labels)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        train_losses.append(loss.item())

    model.train(False)
    val_losses = []
    with torch.no_grad():
        for ic, sc, cont, labels in val_loader:
            preds = model(ic, sc, cont)
            val_losses.append(criterion(preds, labels).item())

    train_loss = np.mean(train_losses)
    val_loss = np.mean(val_losses)

    if epoch % 5 == 0 or epoch == 1:
        print(f"Epoch {epoch:3d}: train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")

    if val_loss < best_val_loss:
        best_val_loss = val_loss
        patience_counter = 0
        torch.save(model.state_dict(), "best_dla_model.pt")
    else:
        patience_counter += 1
        if patience_counter >= patience:
            print(f"Early stopping at epoch {epoch}")
            break
```

---

### 1d — Does the neural network beat XGBoost?

```python
from sklearn.metrics import accuracy_score
from sklearn.ensemble import GradientBoostingClassifier

# XGBoost-style baseline (using sklearn GBT for compatibility)
X_train_feat = np.hstack([
    df_train[["item_category", "supply_class"]].values,
    X_train_cont
])
X_val_feat = np.hstack([
    df_val[["item_category", "supply_class"]].values,
    X_val_cont
])

baseline = GradientBoostingClassifier(n_estimators=100, max_depth=4, random_state=42)
baseline.fit(X_train_feat, df_train["shortage_flag"])
baseline_acc = accuracy_score(df_val["shortage_flag"], baseline.predict(X_val_feat))
print(f"GBT baseline accuracy: {baseline_acc:.1%}")

# Neural network accuracy
model.load_state_dict(torch.load("best_dla_model.pt"))
model.train(False)
all_preds = []
with torch.no_grad():
    for ic, sc, cont, _ in val_loader:
        preds = model(ic, sc, cont)
        all_preds.extend((preds.numpy() > 0.5).astype(int))
nn_acc = accuracy_score(df_val["shortage_flag"], all_preds)
print(f"Neural network accuracy: {nn_acc:.1%}")
```

**Written answer for 1d:** On a tabular dataset of 80,000 records with 6 features (2 categorical, 4 continuous), gradient boosted trees and neural networks typically perform comparably. If the neural network does not meaningfully beat the GBT (less than ~2 percentage point improvement), the right call is to ship the GBT — it's faster to train, easier to explain feature importance on, and a DoD auditor can understand a decision tree path. The neural network's advantage here would primarily come from the learned embeddings capturing latent structure in the 300-category item code space that the GBT treats as a flat categorical feature.

---

## Exercise 2 Solutions: CNN Transfer Learning

### 2a — ResNet-18 with frozen backbone

```python
import torchvision.models as models

def build_inspection_classifier(n_classes=3):
    model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)

    # Freeze all backbone layers
    for param in model.parameters():
        param.requires_grad = False

    # Replace final layer. ResNet-18 fc input: 512 features
    model.fc = nn.Sequential(
        nn.Dropout(0.5),
        nn.Linear(512, 128),
        nn.ReLU(inplace=True),
        nn.Linear(128, n_classes),
    )

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"Trainable: {trainable:,} / Total: {total:,} ({trainable/total*100:.1f}%)")
    # Expected: ~66K trainable out of ~11.2M total — only the head is trained
    return model
```

### 2b — Augmentation justification

```python
# For close-up equipment inspection photography (NOT satellite/overhead imagery):
train_transforms = transforms.Compose([
    transforms.Resize((256, 256)),
    transforms.RandomCrop(224),
    transforms.RandomHorizontalFlip(p=0.5),
    # No RandomVerticalFlip: engine components have a "right way up" —
    # an upside-down compressor blade is not a valid inspection image
    transforms.ColorJitter(brightness=0.3, contrast=0.2),
    # Lighting varies between depot inspection stations
    transforms.RandomAffine(degrees=10, translate=(0.05, 0.05)),
    # Small rotation/translation mimics positioning variance on the inspection bench
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])
# Justification: depot inspection photographs are taken under controlled conditions
# (fixed camera, controlled lighting) with the component positioned right-side up.
# Horizontal flip is acceptable (left/right symmetry for some components).
# Vertical flip would create physically impossible orientations and confuse the model.
```

### 2e — False positive rate analysis

```python
from sklearn.metrics import confusion_matrix

# After training, compute FPR for "major_defect" class (index 2)
# FPR = false positives / (false positives + true negatives)
# In inspection context: a false positive means flagging a good component as major defect
# This is costly (unnecessary maintenance) but not safety-critical
# A false negative (missing a major defect) IS safety-critical

cm = confusion_matrix(y_true, y_pred)  # From your validation predictions
tn = cm.sum() - cm[2, :].sum() - cm[:, 2].sum() + cm[2, 2]
fp = cm[:, 2].sum() - cm[2, 2]
fpr = fp / (fp + tn)
fnr = 1.0 - (cm[2, 2] / cm[2, :].sum())  # False negative rate (missed defects)

print(f"FPR (false alarm rate): {fpr:.3f}")
print(f"FNR (missed detection rate): {fnr:.3f}")
```

**Written answer for 2e:** For a maintenance prioritization system, the false *negative* rate (missed major defects) is more dangerous than the false positive rate (unnecessary maintenance flags). If FNR > 5%, the model should not be deployed without a low-confidence safety net — any prediction below 90% confidence on this class should route to mandatory human inspection. The FPR determines operational cost (analyst time), not safety risk.

---

## Exercise 3 Solutions: BERT Fine-Tuning

### 3b — Token length analysis

```python
from transformers import DistilBertTokenizer

tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")

def check_token_lengths(texts: list, tokenizer) -> dict:
    lengths = [
        len(tokenizer.encode(t, add_special_tokens=False))
        for t in texts
    ]
    lengths = np.array(lengths)
    over_256 = (lengths > 256).mean() * 100
    over_384 = (lengths > 384).mean() * 100
    over_512 = (lengths > 512).mean() * 100

    print(f"Mean token length:      {lengths.mean():.0f}")
    print(f"95th percentile length: {np.percentile(lengths, 95):.0f}")
    print(f"Over 256 tokens:        {over_256:.1f}%")
    print(f"Over 384 tokens:        {over_384:.1f}%")
    print(f"Over 512 tokens (BERT limit): {over_512:.1f}%")

    if over_512 < 5:
        recommendation = "TRUNCATE: < 5% of documents exceed 512 tokens. Simple truncation is acceptable."
    elif over_512 < 20:
        recommendation = "CHUNK: 5-20% over limit. Use sliding window chunking (Example 03)."
    else:
        recommendation = "LONG-CONTEXT MODEL: > 20% exceed limit. Use Longformer or Llama-based model."

    print(f"\nRecommendation: {recommendation}")
    return {"mean_length": lengths.mean(), "p95_length": np.percentile(lengths, 95),
            "pct_over_512": over_512, "recommendation": recommendation}
```

### 3d — False discovery rate analysis

```python
from sklearn.metrics import confusion_matrix

# cybersecurity class index: 2
cm = confusion_matrix(y_true, y_pred)
cybersec_idx = 2

# False discovery rate (FDR) = FP / (FP + TP) = 1 - Precision
tp = cm[cybersec_idx, cybersec_idx]
fp = cm[:, cybersec_idx].sum() - tp
fdr = fp / (fp + tp) if (fp + tp) > 0 else 0.0
print(f"FDR for cybersecurity class: {fdr:.3f}")
```

**Written answer for 3d:** If FDR > 15% for the cybersecurity category, two likely improvements:

1. **More training data:** With only 200 examples per class, BERT fine-tuning is at the edge of what's reliable for 6-class classification. Adding 200-300 more cybersecurity examples (real or synthetically generated) will improve precision. Cybersecurity language in IG reports is relatively distinctive; the model should separate it from other categories given sufficient examples.

2. **Threshold adjustment per class:** Instead of using argmax across all classes, set a lower decision threshold for the cybersecurity class — only predict it when P(cybersecurity) > 0.60 rather than just being the highest probability. This increases recall at the cost of some precision, which is the right tradeoff when routing to analysts who can handle false positives but who might miss real cybersecurity findings.

---

## Exercise 4 Solutions: Operational Pipeline

### 4a — Contract risk classifier

```python
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler

np.random.seed(99)
torch.manual_seed(99)
n = 10_000

df_contracts = pd.DataFrame({
    "contract_value_log": np.log1p(np.random.exponential(500_000, size=n)).astype(np.float32),
    "n_modifications": np.random.poisson(2.5, size=n).astype(np.float32),
    "days_to_award": np.random.exponential(45, size=n).clip(1, 365).astype(np.float32),
    "vendor_past_violations": np.random.poisson(0.3, size=n).astype(np.float32),
    "sole_source_flag": np.random.binomial(1, 0.15, size=n).astype(np.float32),
    "naics_sector": np.random.randint(0, 23, size=n),
})
high_risk = (
    (df_contracts["vendor_past_violations"] > 1) |
    ((df_contracts["sole_source_flag"] == 1) & (df_contracts["contract_value_log"] > np.log(5_000_000)))
)
low_risk = ~high_risk & (df_contracts["n_modifications"] <= 2)
df_contracts["risk_tier"] = 0
df_contracts.loc[~low_risk & ~high_risk, "risk_tier"] = 1
df_contracts.loc[high_risk, "risk_tier"] = 2

# Architecture choice: simple 3-layer network with embedding for naics_sector
# Justification: 10,000 records, 6 features. A deep network would overfit.
# 3 layers with strong dropout is the right tradeoff here.
class ContractRiskNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.naics_emb = nn.Embedding(23, 6)
        # 5 continuous + 6 embedding = 11 features
        self.net = nn.Sequential(
            nn.Linear(11, 64), nn.BatchNorm1d(64), nn.ReLU(), nn.Dropout(0.4),
            nn.Linear(64, 32), nn.BatchNorm1d(32), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(32, 3),  # 3 risk tiers, no activation (CrossEntropyLoss needs logits)
        )

    def forward(self, naics, continuous):
        ne = self.naics_emb(naics)
        x = torch.cat([ne, continuous], dim=1)
        return self.net(x)

# Train (abbreviated — full loop mirrors Exercise 1)
cont_cols = ["contract_value_log", "n_modifications", "days_to_award",
             "vendor_past_violations", "sole_source_flag"]
split = int(n * 0.80)
df_train, df_val = df_contracts.iloc[:split], df_contracts.iloc[split:]
scaler = StandardScaler()
X_train = scaler.fit_transform(df_train[cont_cols].values).astype(np.float32)
X_val = scaler.transform(df_val[cont_cols].values).astype(np.float32)

model = ContractRiskNet()
# ... (training loop using CrossEntropyLoss, AdamW, 30 epochs with early stopping)
```

### 4c — Audit log analysis

```python
# After wrapping model in OperationalInferencePipeline and running on test set:
stats = pipeline.review_statistics()
print(f"Total inferences: {stats['total_inferences']:,}")
print(f"Routed to human review: {stats['pct_requiring_human_review']:.1f}%")

df_log = pipeline.audit_logger.get_all()
auto_classified = df_log[~df_log["requires_human_review"]]
print("\nPredicted class distribution (auto-classified only):")
print(auto_classified["predicted_class"].value_counts())
```

### 4d — Meeting the 2% false negative requirement

```python
import numpy as np
from sklearn.metrics import confusion_matrix

# After running evaluate_operational_model():
cm = np.array(metrics["confusion_matrix"])

# False negative rate for high_risk (class 2) = missed high-risk contracts
# FNR = FN / (FN + TP) = 1 - Recall(high_risk)
tp_high = cm[2, 2]
fn_high = cm[2, :].sum() - tp_high
fnr_high = fn_high / cm[2, :].sum() if cm[2, :].sum() > 0 else 0.0

print(f"False negative rate on high-risk class: {fnr_high:.3f}")
print(f"Requirement met: {'YES' if fnr_high <= 0.02 else 'NO — model must be revised'}")
```

### 4e — Fixing the FNR requirement

If FNR > 2% on high-risk contracts, the most direct fix is **adjusting the classification threshold independently for the high-risk class**. Instead of using argmax, predict "high risk" whenever P(high_risk) > T for some threshold T < 0.5.

```python
import numpy as np

def predict_with_class_threshold(
    y_prob: np.ndarray,
    high_risk_threshold: float = 0.30,  # Lower threshold = higher recall for high-risk
) -> np.ndarray:
    """
    Custom thresholding: flag high-risk whenever P(high_risk) exceeds threshold,
    regardless of whether it is the highest probability class.
    This trades some low-risk false positives for reduced high-risk false negatives.
    """
    preds = y_prob.argmax(axis=1).copy()
    # Override: classify as high-risk if P(class=2) > threshold
    high_risk_mask = y_prob[:, 2] > high_risk_threshold
    preds[high_risk_mask] = 2
    return preds

# Sweep thresholds to find one that meets the 2% FNR requirement
for threshold in [0.20, 0.25, 0.30, 0.35, 0.40]:
    preds_adjusted = predict_with_class_threshold(y_prob_test, high_risk_threshold=threshold)
    cm = confusion_matrix(y_true_test, preds_adjusted)
    fnr = (cm[2, :].sum() - cm[2, 2]) / cm[2, :].sum()
    fpr_low = (cm[:, 0].sum() - cm[0, 0]) / (cm.sum() - cm[0, :].sum())  # False alarms
    print(f"Threshold={threshold:.2f}: FNR={fnr:.3f}, low-risk FPR={fpr_low:.3f}")

# Select the lowest threshold that meets FNR <= 0.02
# Document this threshold in the model card and system specification
```

**Key lessons from Exercise 4:**
- FNR and FPR are in tension — lowering the classification threshold for the high-risk class reduces FNR (fewer missed high-risk cases) but increases FPR (more low-risk contracts flagged incorrectly)
- The 2% FNR requirement is a policy decision that must be documented in the system specification before deployment
- The confidence threshold (0.80) and the classification threshold (P(high_risk) > T) are separate concepts that can be tuned independently
- Log both thresholds in the model card and the audit record so that any future model update knows what targets it must match or exceed
