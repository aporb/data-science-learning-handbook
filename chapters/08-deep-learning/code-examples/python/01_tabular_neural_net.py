"""
Chapter 08 — Deep Learning and Neural Networks
Example 01: Feedforward neural network for tabular government data

Use case: Predicting equipment readiness priority score for DoD maintenance scheduling
Dataset: Simulated equipment maintenance records (tabular)
Platform: Any Python environment — local, Databricks ML Runtime, Advana, Jupiter

Key concepts:
    - Learned embeddings for high-cardinality categorical fields (unit codes, NSNs)
    - Batch normalization for distribution shift resilience
    - AdamW optimizer with OneCycleLR schedule
    - Early stopping with validation set from most recent time period
    - MLflow integration for experiment tracking (Databricks-native)

Dependencies: torch, numpy, pandas, scikit-learn, mlflow
"""

import os
import math
import logging
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, random_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score
import mlflow
import mlflow.pytorch

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data generation — simulates DoD equipment maintenance records
# ---------------------------------------------------------------------------

def generate_maintenance_dataset(n_records: int = 50_000, seed: int = 42) -> pd.DataFrame:
    """
    Generate a synthetic equipment readiness dataset that mimics
    the structure of DoD logistics data (GCSS-Army, DPAS, Navy NALCOMIS).

    Features:
        unit_code: Unit Identification Code (UIC) — high cardinality categorical
        nsn: National Stock Number — high cardinality categorical
        equipment_type: broad equipment category — lower cardinality categorical
        days_since_maintenance: continuous
        operational_hours_ytd: continuous
        failure_count_90d: count variable
        mission_capable_pct_30d: continuous, 0-100

    Label:
        priority_flag: 1 if equipment needs priority maintenance in next 30 days
    """
    rng = np.random.RandomState(seed)

    n_uics = 500          # 500 distinct unit codes
    n_nsns = 2000         # 2000 distinct NSNs
    n_equip_types = 12    # Broad equipment categories

    n = n_records
    unit_codes = rng.randint(0, n_uics, size=n)
    nsns = rng.randint(0, n_nsns, size=n)
    equipment_types = rng.randint(0, n_equip_types, size=n)

    days_since_maint = rng.exponential(scale=60, size=n).clip(0, 365)
    op_hours_ytd = rng.gamma(shape=3, scale=200, size=n)
    failure_count_90d = rng.poisson(lam=0.8, size=n)
    mission_capable_pct = (100 - rng.exponential(scale=15, size=n)).clip(40, 100)

    # Label: priority if days_since_maint > 90 OR failure_count > 2 OR mc_pct < 65
    # Add noise: 10% label flip
    hard_label = (
        (days_since_maint > 90) |
        (failure_count_90d > 2) |
        (mission_capable_pct < 65)
    ).astype(float)
    noise = rng.binomial(1, 0.10, size=n)
    priority_flag = ((hard_label + noise) > 0).astype(int)

    # Simulate temporal structure: records span 2 years
    base_date = datetime(2023, 1, 1)
    action_dates = [base_date + timedelta(days=int(d)) for d in rng.randint(0, 730, size=n)]

    return pd.DataFrame({
        "unit_code": unit_codes,
        "nsn": nsns,
        "equipment_type": equipment_types,
        "days_since_maintenance": days_since_maint.astype(np.float32),
        "operational_hours_ytd": op_hours_ytd.astype(np.float32),
        "failure_count_90d": failure_count_90d.astype(np.float32),
        "mission_capable_pct": mission_capable_pct.astype(np.float32),
        "action_date": action_dates,
        "priority_flag": priority_flag,
    })


# ---------------------------------------------------------------------------
# Dataset class
# ---------------------------------------------------------------------------

class ReadinessDataset(Dataset):
    """
    PyTorch Dataset wrapping the readiness DataFrame.
    Handles encoding of categorical fields and scaling of continuous fields.
    """

    def __init__(
        self,
        df: pd.DataFrame,
        scaler: StandardScaler = None,
        fit_scaler: bool = False,
    ):
        self.unit_codes = torch.tensor(df["unit_code"].values, dtype=torch.long)
        self.nsns = torch.tensor(df["nsn"].values, dtype=torch.long)
        self.equip_types = torch.tensor(df["equipment_type"].values, dtype=torch.long)

        continuous_cols = [
            "days_since_maintenance",
            "operational_hours_ytd",
            "failure_count_90d",
            "mission_capable_pct",
        ]
        continuous_data = df[continuous_cols].values.astype(np.float32)

        if fit_scaler:
            self.scaler = StandardScaler()
            continuous_data = self.scaler.fit_transform(continuous_data)
        elif scaler is not None:
            self.scaler = scaler
            continuous_data = scaler.transform(continuous_data)
        else:
            self.scaler = None

        self.continuous = torch.tensor(continuous_data, dtype=torch.float32)
        self.labels = torch.tensor(df["priority_flag"].values, dtype=torch.float32)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return (
            self.unit_codes[idx],
            self.nsns[idx],
            self.equip_types[idx],
            self.continuous[idx],
            self.labels[idx],
        )


# ---------------------------------------------------------------------------
# Model architecture
# ---------------------------------------------------------------------------

class ReadinessPriorityNet(nn.Module):
    """
    Embedding-based feedforward network for equipment readiness priority prediction.

    Architecture:
        - Learned embeddings for unit_code (high-cardinality) and NSN (high-cardinality)
        - Direct input for equipment_type (lower cardinality, still embedded)
        - Batch normalization + dropout on each hidden layer
        - Sigmoid output for binary priority prediction
    """

    def __init__(
        self,
        n_unit_codes: int,
        n_nsns: int,
        n_equip_types: int,
        unit_embed_dim: int = 16,
        nsn_embed_dim: int = 24,
        equip_embed_dim: int = 6,
        n_continuous: int = 4,
        hidden_sizes: list = None,
        dropout_rate: float = 0.3,
    ):
        super().__init__()
        hidden_sizes = hidden_sizes or [128, 64, 32]

        # Embedding rule of thumb: min(50, (n_categories + 1) // 2)
        self.unit_embedding  = nn.Embedding(n_unit_codes,  unit_embed_dim)
        self.nsn_embedding   = nn.Embedding(n_nsns,        nsn_embed_dim)
        self.equip_embedding = nn.Embedding(n_equip_types, equip_embed_dim)

        input_dim = unit_embed_dim + nsn_embed_dim + equip_embed_dim + n_continuous

        layers = []
        prev = input_dim
        for h in hidden_sizes:
            layers += [
                nn.Linear(prev, h),
                nn.BatchNorm1d(h),
                nn.ReLU(inplace=True),
                nn.Dropout(dropout_rate),
            ]
            prev = h

        layers += [nn.Linear(prev, 1), nn.Sigmoid()]
        self.network = nn.Sequential(*layers)

        self._init_weights()

    def _init_weights(self):
        """He initialization for ReLU networks."""
        for module in self.network:
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, nonlinearity="relu")
                nn.init.zeros_(module.bias)

    def forward(self, unit_codes, nsns, equip_types, continuous):
        u = self.unit_embedding(unit_codes)
        n = self.nsn_embedding(nsns)
        e = self.equip_embedding(equip_types)
        x = torch.cat([u, n, e, continuous], dim=1)
        return self.network(x).squeeze(1)


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------

def train_epoch(model, loader, optimizer, criterion, scheduler, device, clip_norm=1.0):
    model.train()
    total_loss = 0.0
    for unit_c, nsn_c, equip_c, cont, labels in loader:
        unit_c, nsn_c, equip_c, cont, labels = (
            unit_c.to(device), nsn_c.to(device), equip_c.to(device),
            cont.to(device), labels.to(device)
        )
        optimizer.zero_grad()
        preds = model(unit_c, nsn_c, equip_c, cont)
        loss = criterion(preds, labels)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), clip_norm)
        optimizer.step()
        scheduler.step()
        total_loss += loss.item() * len(labels)
    return total_loss / len(loader.dataset)


def evaluate(model, loader, criterion, device):
    """Run inference mode evaluation, collect predictions for AUC computation."""
    model.train(False)   # Sets to inference mode (disables dropout, uses running stats in BN)
    total_loss = 0.0
    all_preds, all_labels = [], []
    with torch.no_grad():
        for unit_c, nsn_c, equip_c, cont, labels in loader:
            unit_c, nsn_c, equip_c, cont, labels = (
                unit_c.to(device), nsn_c.to(device), equip_c.to(device),
                cont.to(device), labels.to(device)
            )
            preds = model(unit_c, nsn_c, equip_c, cont)
            loss = criterion(preds, labels)
            total_loss += loss.item() * len(labels)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    avg_loss = total_loss / len(loader.dataset)
    auc = roc_auc_score(all_labels, all_preds) if len(set(all_labels)) > 1 else 0.0
    ap = average_precision_score(all_labels, all_preds) if len(set(all_labels)) > 1 else 0.0
    return avg_loss, auc, ap


def train_readiness_model(
    df: pd.DataFrame,
    n_epochs: int = 50,
    batch_size: int = 512,
    lr: float = 1e-3,
    hidden_sizes: list = None,
    dropout_rate: float = 0.3,
    patience: int = 8,
    device: str = None,
    mlflow_experiment: str = "readiness_priority",
) -> tuple:
    """
    Full training pipeline with time-based train/val split, early stopping,
    and MLflow experiment tracking.

    Time-based split: most recent 20% of records → validation set.
    This tests whether the model generalizes to future data, not just
    withheld records from the same time period.

    Returns: (trained_model, scaler, metrics_dict)
    """
    hidden_sizes = hidden_sizes or [128, 64, 32]
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    log.info("Training on device: %s", device)

    # Time-based split: sort by date, last 20% is validation
    df_sorted = df.sort_values("action_date").reset_index(drop=True)
    split_idx = int(len(df_sorted) * 0.80)
    df_train = df_sorted.iloc[:split_idx]
    df_val   = df_sorted.iloc[split_idx:]

    log.info("Train: %s records | Val: %s records", f"{len(df_train):,}", f"{len(df_val):,}")

    train_ds = ReadinessDataset(df_train, fit_scaler=True)
    val_ds   = ReadinessDataset(df_val,   scaler=train_ds.scaler)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True,  pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False, pin_memory=True)

    # Vocabulary sizes from data (add 1 for safety against unseen values)
    n_unit_codes = int(df["unit_code"].max()) + 1
    n_nsns       = int(df["nsn"].max()) + 1
    n_equip_types = int(df["equipment_type"].max()) + 1

    model = ReadinessPriorityNet(
        n_unit_codes=n_unit_codes,
        n_nsns=n_nsns,
        n_equip_types=n_equip_types,
        hidden_sizes=hidden_sizes,
        dropout_rate=dropout_rate,
    ).to(device)

    # Compute positive class weight to handle class imbalance
    pos_weight_val = (df_train["priority_flag"] == 0).sum() / max(
        (df_train["priority_flag"] == 1).sum(), 1
    )
    criterion = nn.BCELoss(
        # Weight positive examples more heavily if imbalanced
        # Note: BCELoss doesn't accept pos_weight directly — use BCEWithLogitsLoss for that
        # Here we use a simpler approach: the model's Sigmoid handles calibration
    )

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    total_steps = n_epochs * len(train_loader)
    scheduler = optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=lr, total_steps=total_steps, pct_start=0.1
    )

    best_val_auc = 0.0
    best_epoch = 0
    patience_counter = 0
    history = []

    mlflow.set_experiment(mlflow_experiment)
    with mlflow.start_run(run_name=f"readiness_net_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
        mlflow.log_params({
            "n_epochs": n_epochs,
            "batch_size": batch_size,
            "lr": lr,
            "hidden_sizes": str(hidden_sizes),
            "dropout_rate": dropout_rate,
            "n_train": len(df_train),
            "n_val": len(df_val),
            "device": device,
        })

        for epoch in range(1, n_epochs + 1):
            train_loss = train_epoch(model, train_loader, optimizer, criterion, scheduler, device)
            val_loss, val_auc, val_ap = evaluate(model, val_loader, criterion, device)

            history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss,
                            "val_auc": val_auc, "val_ap": val_ap})

            mlflow.log_metrics({
                "train_loss": train_loss,
                "val_loss": val_loss,
                "val_auc": val_auc,
                "val_ap": val_ap,
            }, step=epoch)

            if epoch % 5 == 0 or epoch == 1:
                log.info(
                    "Epoch %3d: train_loss=%.4f  val_loss=%.4f  val_auc=%.4f  val_ap=%.4f",
                    epoch, train_loss, val_loss, val_auc, val_ap
                )

            if val_auc > best_val_auc:
                best_val_auc = val_auc
                best_epoch = epoch
                patience_counter = 0
                torch.save(model.state_dict(), "best_readiness_model.pt")
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    log.info("Early stopping at epoch %d (best epoch: %d)", epoch, best_epoch)
                    break

        # Load best weights and log final model
        model.load_state_dict(torch.load("best_readiness_model.pt", map_location=device))
        mlflow.pytorch.log_model(model, "model")
        mlflow.log_metrics({
            "best_val_auc": best_val_auc,
            "best_epoch": best_epoch,
        })

    log.info("Training complete. Best val AUC: %.4f at epoch %d", best_val_auc, best_epoch)
    return model, train_ds.scaler, {"best_val_auc": best_val_auc, "best_epoch": best_epoch}


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def predict_batch(
    model: ReadinessPriorityNet,
    df: pd.DataFrame,
    scaler: StandardScaler,
    device: str = "cpu",
    threshold: float = 0.5,
) -> pd.DataFrame:
    """
    Run inference on a new batch of equipment records.
    Returns df with added columns: priority_score, priority_flag_predicted.
    """
    ds = ReadinessDataset(df, scaler=scaler)
    loader = DataLoader(ds, batch_size=1024, shuffle=False)

    model = model.to(device)
    model.train(False)   # Inference mode

    all_scores = []
    with torch.no_grad():
        for unit_c, nsn_c, equip_c, cont, _ in loader:
            unit_c, nsn_c, equip_c, cont = (
                unit_c.to(device), nsn_c.to(device), equip_c.to(device), cont.to(device)
            )
            scores = model(unit_c, nsn_c, equip_c, cont)
            all_scores.extend(scores.cpu().numpy())

    result = df.copy()
    result["priority_score"] = all_scores
    result["priority_flag_predicted"] = (result["priority_score"] >= threshold).astype(int)
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("Generating synthetic maintenance dataset...")
    df = generate_maintenance_dataset(n_records=50_000)

    log.info("Dataset shape: %s | Priority rate: %.1f%%",
             df.shape, df["priority_flag"].mean() * 100)

    model, scaler, metrics = train_readiness_model(
        df,
        n_epochs=30,
        batch_size=512,
        lr=1e-3,
        hidden_sizes=[128, 64, 32],
        dropout_rate=0.3,
        patience=8,
    )

    print(f"\nFinal metrics: {metrics}")

    # Run inference on a small sample
    sample = df.sample(100, random_state=7)
    results = predict_batch(model, sample, scaler, threshold=0.5)
    print(f"\nSample predictions:")
    print(results[["unit_code", "nsn", "priority_score", "priority_flag_predicted",
                   "priority_flag"]].head(10).to_string(index=False))

    match_rate = (results["priority_flag_predicted"] == results["priority_flag"]).mean()
    print(f"\nSample accuracy: {match_rate:.1%}")
