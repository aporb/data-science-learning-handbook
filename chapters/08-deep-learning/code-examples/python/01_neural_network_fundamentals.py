"""
Chapter 08 — Deep Learning and Neural Networks
Example 01: Neural network fundamentals and tabular government data

Use cases covered:
  1. Core PyTorch concepts: tensors, autograd, forward pass, training loop
  2. Feedforward network with learned embeddings for high-cardinality categoricals
  3. LSTM for sequential maintenance data indexed by operational cycles
  4. Training utilities: time-based split, gradient clipping, early stopping

Platform: Any Python environment — local, Databricks ML Runtime, Advana, Jupiter
Framework: PyTorch (not TensorFlow — see README for rationale)

Dependencies: torch, numpy, pandas, scikit-learn, mlflow
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import mlflow
import mlflow.pytorch
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, Dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# =============================================================================
# PART 1: Core PyTorch Concepts
# =============================================================================

def demonstrate_autograd():
    """
    PyTorch's automatic differentiation (autograd) is the engine behind training.
    This function demonstrates the key concepts before we build anything.
    """
    # Every computation in PyTorch happens on tensors — n-dimensional arrays
    # with a data type and a device (CPU or CUDA GPU).

    # requires_grad=True tells PyTorch to track operations for backprop
    x = torch.tensor([[1.0, 2.0, 3.0]], requires_grad=True)
    W = torch.randn(3, 2, requires_grad=True)  # weight matrix
    b = torch.zeros(2, requires_grad=True)     # bias vector

    # Forward pass: matrix multiply + bias
    z = x @ W + b

    # Activation function: sigmoid squashes to (0, 1)
    output = torch.sigmoid(z)

    # Simulate a binary cross-entropy loss against a target label
    target = torch.tensor([[1.0, 0.0]])
    loss = -torch.mean(target * torch.log(output) + (1 - target) * torch.log(1 - output))

    # Backward pass: PyTorch computes d(loss)/d(W), d(loss)/d(b), d(loss)/d(x)
    loss.backward()

    logger.info(f"Loss: {loss.item():.4f}")
    logger.info(f"Gradient w.r.t. W shape: {W.grad.shape}")  # same as W: (3, 2)

    # After computing gradients, an optimizer would update W and b:
    # W.data -= learning_rate * W.grad
    # W.grad.zero_()  # Always zero gradients after update — they accumulate


def demonstrate_train_eval_modes():
    """
    PyTorch models have two modes that affect behavior during training vs. inference.

    model.train()       — activates dropout (random neuron dropout)
                        — BatchNorm uses batch statistics
    model.train(False)  — disables dropout (all neurons active)
                        — BatchNorm uses running statistics from training
                        — Equivalent to model.eval()

    ALWAYS switch to inference mode before making predictions. Forgetting this
    is a common source of slightly inconsistent results that are hard to diagnose.
    """
    model = nn.Sequential(
        nn.Linear(10, 32),
        nn.BatchNorm1d(32),
        nn.ReLU(),
        nn.Dropout(p=0.3),
        nn.Linear(32, 1),
        nn.Sigmoid(),
    )

    # Training mode — dropout active, BatchNorm uses batch stats
    model.train()
    x = torch.randn(16, 10)  # batch of 16 samples
    out_train_1 = model(x)
    out_train_2 = model(x)
    # These two outputs will differ because dropout randomly zeros neurons
    assert not torch.allclose(out_train_1, out_train_2, atol=1e-6), \
        "Expected variation between two forward passes in train mode"

    # Inference mode — dropout disabled, consistent outputs
    model.train(False)
    with torch.no_grad():  # also disable gradient tracking for efficiency
        out_eval_1 = model(x)
        out_eval_2 = model(x)
    # These will be identical
    assert torch.allclose(out_eval_1, out_eval_2), \
        "Expected identical outputs in inference mode"

    logger.info("Train vs. inference mode demonstration passed.")


# =============================================================================
# PART 2: Feedforward Network with Embeddings for Tabular Government Data
# =============================================================================

def generate_readiness_dataset(n_samples: int = 50_000) -> pd.DataFrame:
    """
    Generate synthetic equipment readiness records for DoD maintenance scheduling.

    In a real program, this data would come from GCSS-Army, NALCOMIS (Navy aviation),
    or the Army's SAMS-E maintenance management system, accessed via Advana or Jupiter.
    """
    rng = np.random.RandomState(42)
    n_units = 500
    n_equip_types = 200
    n_nsns = 2000

    base_date = datetime(2022, 1, 1)
    dates = [base_date + timedelta(days=int(d)) for d in rng.randint(0, 730, n_samples)]

    df = pd.DataFrame({
        "asset_id": [f"ASSET-{i:05d}" for i in range(n_samples)],
        "unit_code": rng.randint(0, n_units, n_samples),           # UIC — 0 to 499
        "equipment_type": rng.randint(0, n_equip_types, n_samples), # TMDE category
        "nsn": rng.randint(0, n_nsns, n_samples),                   # National Stock Number
        "days_since_maintenance": rng.exponential(45, n_samples).clip(0, 365),
        "operational_hours": rng.exponential(200, n_samples).clip(0, 3000),
        "failure_count_90d": rng.poisson(0.5, n_samples).clip(0, 10),
        "age_years": rng.uniform(0, 30, n_samples),
        "maintenance_backlog_count": rng.poisson(2, n_samples).clip(0, 20),
        "record_date": dates,
    })

    # Target: readiness priority score (0 = low priority, 1 = needs immediate maintenance)
    # Constructed from domain logic: age, failure history, and backlog matter most
    score = (
        0.3 * (df["days_since_maintenance"] / 365)
        + 0.3 * np.minimum(df["failure_count_90d"] / 5, 1.0)
        + 0.2 * (df["maintenance_backlog_count"] / 20)
        + 0.2 * (df["age_years"] / 30)
        + rng.normal(0, 0.05, n_samples)
    ).clip(0, 1)
    df["readiness_priority"] = score.astype(np.float32)

    return df


class ReadinessDataset(Dataset):
    """
    PyTorch Dataset for equipment readiness tabular data.
    Categorical fields are integer-encoded for embedding lookup.
    """

    def __init__(self, df: pd.DataFrame, scaler: Optional[StandardScaler] = None):
        # Categorical fields: integer codes for embedding lookup
        self.unit_codes = torch.tensor(df["unit_code"].values, dtype=torch.long)
        self.equip_types = torch.tensor(df["equipment_type"].values, dtype=torch.long)
        self.nsns = torch.tensor(df["nsn"].values, dtype=torch.long)

        # Continuous fields: scale to zero mean, unit variance
        cont_features = df[[
            "days_since_maintenance",
            "operational_hours",
            "failure_count_90d",
            "age_years",
            "maintenance_backlog_count",
        ]].values.astype(np.float32)

        if scaler is None:
            self.scaler = StandardScaler()
            cont_features = self.scaler.fit_transform(cont_features)
        else:
            self.scaler = scaler
            cont_features = scaler.transform(cont_features)

        self.continuous = torch.tensor(cont_features, dtype=torch.float32)
        self.labels = torch.tensor(df["readiness_priority"].values, dtype=torch.float32)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int):
        return {
            "unit_code": self.unit_codes[idx],
            "equip_type": self.equip_types[idx],
            "nsn": self.nsns[idx],
            "continuous": self.continuous[idx],
            "label": self.labels[idx],
        }


class ReadinessPriorityNet(nn.Module):
    """
    Feedforward neural network for equipment readiness scoring.

    Architecture:
    - Learned embeddings for high-cardinality categorical fields (UICs, NSNs)
    - Batch normalization for distribution-shift resilience across deployment cycles
    - Dropout for regularization
    - Single output: priority score in [0, 1]

    Why embeddings instead of one-hot encoding?
    A one-hot vector for 2,000 NSN categories has 1,999 zeros per row — mostly
    empty space. A 16-dimensional embedding is dense, learns semantic relationships
    (NSNs that co-fail end up nearby in embedding space), and uses ~30x fewer
    parameters per input sample.
    """

    def __init__(
        self,
        n_unit_codes: int,
        n_equip_types: int,
        n_nsns: int,
        n_continuous_features: int = 5,
        hidden_dims: Tuple[int, ...] = (128, 64, 32),
        dropout_rate: float = 0.3,
    ):
        super().__init__()

        # Embedding dimensions: rule of thumb is min(50, cardinality // 2 + 1)
        unit_embed_dim = min(50, n_unit_codes // 2 + 1)
        equip_embed_dim = min(20, n_equip_types // 2 + 1)
        nsn_embed_dim = min(30, n_nsns // 2 + 1)

        self.unit_embedding = nn.Embedding(n_unit_codes, unit_embed_dim)
        self.equip_embedding = nn.Embedding(n_equip_types, equip_embed_dim)
        self.nsn_embedding = nn.Embedding(n_nsns, nsn_embed_dim)

        input_dim = unit_embed_dim + equip_embed_dim + nsn_embed_dim + n_continuous_features

        # Build hidden layers programmatically from hidden_dims tuple
        layers = []
        prev_dim = input_dim
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout_rate),
            ])
            prev_dim = hidden_dim

        self.hidden = nn.Sequential(*layers)
        self.output = nn.Linear(prev_dim, 1)

    def forward(self, batch: Dict[str, torch.Tensor]) -> torch.Tensor:
        # Look up embeddings for each categorical field
        unit_emb = self.unit_embedding(batch["unit_code"])
        equip_emb = self.equip_embedding(batch["equip_type"])
        nsn_emb = self.nsn_embedding(batch["nsn"])

        # Concatenate embeddings with continuous features
        x = torch.cat([unit_emb, equip_emb, nsn_emb, batch["continuous"]], dim=-1)

        x = self.hidden(x)
        # Sigmoid constrains output to [0, 1] — interpretable as priority score
        return torch.sigmoid(self.output(x)).squeeze(-1)


def time_based_train_val_split(
    df: pd.DataFrame,
    date_col: str = "record_date",
    val_fraction: float = 0.15,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split a dataset by time, reserving the most recent fraction for validation.

    Random splits are wrong for time series data. If you randomly assign 15% of rows
    to validation, you will have future data in training and past data in validation.
    The model appears well-calibrated on the validation set because it has already
    seen what the future looks like. In production, it fails.
    """
    df = df.sort_values(date_col)
    split_idx = int(len(df) * (1 - val_fraction))
    return df.iloc[:split_idx].copy(), df.iloc[split_idx:].copy()


def train_readiness_model(
    n_epochs: int = 30,
    batch_size: int = 256,
    learning_rate: float = 1e-3,
    patience: int = 5,
    mlflow_experiment: str = "readiness-prediction",
) -> ReadinessPriorityNet:
    """
    Train the readiness priority network with early stopping.
    Logs parameters, metrics, and the final model to MLflow.
    """
    df = generate_readiness_dataset(n_samples=50_000)

    train_df, val_df = time_based_train_val_split(df)
    logger.info(f"Train: {len(train_df):,} rows | Val: {len(val_df):,} rows")
    logger.info(
        f"Train date range: {train_df['record_date'].min().date()} — "
        f"{train_df['record_date'].max().date()}"
    )
    logger.info(
        f"Val date range: {val_df['record_date'].min().date()} — "
        f"{val_df['record_date'].max().date()}"
    )

    train_ds = ReadinessDataset(train_df)
    val_ds = ReadinessDataset(val_df, scaler=train_ds.scaler)  # reuse training scaler

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=batch_size * 2, shuffle=False, num_workers=0)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Training on: {device}")

    model = ReadinessPriorityNet(
        n_unit_codes=500,
        n_equip_types=200,
        n_nsns=2000,
    ).to(device)

    optimizer = optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    criterion = nn.MSELoss()
    scheduler = optim.lr_scheduler.OneCycleLR(
        optimizer,
        max_lr=learning_rate,
        steps_per_epoch=len(train_loader),
        epochs=n_epochs,
    )

    mlflow.set_experiment(mlflow_experiment)
    with mlflow.start_run(run_name=f"readiness-ffn-{datetime.now():%Y%m%d-%H%M}"):
        mlflow.log_params({
            "n_epochs": n_epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "architecture": "embedding-ffn",
            "hidden_dims": "128-64-32",
            "dropout": 0.3,
        })

        best_val_loss = float("inf")
        best_state = None
        epochs_without_improvement = 0

        for epoch in range(n_epochs):
            # --- Training phase ---
            model.train()
            train_loss = 0.0

            for batch in train_loader:
                batch = {k: v.to(device) for k, v in batch.items()}
                predictions = model(batch)
                loss = criterion(predictions, batch["label"])

                optimizer.zero_grad()
                loss.backward()
                # Gradient clipping: prevents exploding gradients (critical for deep nets)
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()

                train_loss += loss.item() * len(batch["label"])

            train_loss /= len(train_ds)

            # --- Validation phase ---
            model.train(False)  # inference mode: disable dropout, use running BatchNorm stats
            val_loss = 0.0
            with torch.no_grad():
                for batch in val_loader:
                    batch = {k: v.to(device) for k, v in batch.items()}
                    predictions = model(batch)
                    val_loss += criterion(predictions, batch["label"]).item() * len(batch["label"])
            val_loss /= len(val_ds)

            mlflow.log_metrics({"train_loss": train_loss, "val_loss": val_loss}, step=epoch)

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                epochs_without_improvement = 0
            else:
                epochs_without_improvement += 1

            if epoch % 5 == 0:
                logger.info(f"Epoch {epoch:3d}: train={train_loss:.4f}, val={val_loss:.4f}")

            if epochs_without_improvement >= patience:
                logger.info(f"Early stopping at epoch {epoch} (no improvement for {patience} epochs)")
                break

        # Restore best weights
        model.load_state_dict(best_state)
        mlflow.log_metric("best_val_loss", best_val_loss)
        mlflow.pytorch.log_model(model, artifact_path="readiness_model")
        logger.info(f"Best validation MSE: {best_val_loss:.4f}")

    return model


# =============================================================================
# PART 3: LSTM for Sequential Maintenance Data
# =============================================================================

class MaintenanceLSTM(nn.Module):
    """
    LSTM for predicting equipment failure risk from sequential sensor readings.

    The key design decision: sequences are indexed by operational cycles (flight hours,
    engine starts, etc.) NOT by calendar time. Two assets at the same calendar date
    can be at very different points in their maintenance cycle. The LSTM needs to
    see where you are in the cycle, not what month it is.
    """

    def __init__(
        self,
        n_sensor_features: int,
        hidden_size: int = 64,
        n_layers: int = 2,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=n_sensor_features,
            hidden_size=hidden_size,
            num_layers=n_layers,
            batch_first=True,  # input shape: (batch, seq_len, features)
            dropout=dropout if n_layers > 1 else 0.0,
        )
        self.dropout = nn.Dropout(dropout)
        self.head = nn.Linear(hidden_size, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch_size, sequence_length, n_sensor_features)
        lstm_out, (h_n, _) = self.lstm(x)

        # h_n: (n_layers, batch_size, hidden_size)
        # Use the final layer's last hidden state as the sequence summary
        final_hidden = h_n[-1]  # (batch_size, hidden_size)
        out = self.dropout(final_hidden)
        return torch.sigmoid(self.head(out)).squeeze(-1)


def generate_maintenance_sequences(
    n_assets: int = 200,
    sequence_length: int = 30,
    n_sensor_features: int = 8,
    rng: Optional[np.random.RandomState] = None,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic asset sensor sequences indexed by operational cycle position.

    Each asset has a history of sensor readings. Windows of `sequence_length`
    readings are sliced, and the label is whether the asset failed within the
    next 10 cycles after the window.

    In production data (e.g., from NALCOMIS for P-8 Poseidon aircraft), you would:
    1. Query Bronze Delta table: raw sensor readings with flight hours and tail number
    2. Group by tail number, sort by cumulative flight hours
    3. Create rolling windows with this function's logic
    4. Train the LSTM on the resulting (n_windows, seq_len, n_features) array
    """
    if rng is None:
        rng = np.random.RandomState(2024)

    X_windows, y_labels = [], []

    for asset_idx in range(n_assets):
        # Each asset has 100-200 cycle readings
        n_cycles = rng.randint(100, 200)

        # Sensor degradation trend: slight upward drift toward failure
        degradation = np.linspace(0, rng.uniform(0.3, 0.8), n_cycles)
        noise = rng.normal(0, 0.05, (n_cycles, n_sensor_features))
        base_readings = rng.normal(0.5, 0.15, (n_cycles, n_sensor_features)).clip(0, 1)

        # Apply degradation to first half of sensors (simulate wear indicators)
        base_readings[:, :4] += degradation[:, np.newaxis]
        readings = (base_readings + noise).clip(0, 1).astype(np.float32)

        # Label: asset fails if degradation at end of window is above 0.7
        for start in range(n_cycles - sequence_length):
            window = readings[start : start + sequence_length]
            end_degradation = degradation[start + sequence_length]
            label = float(end_degradation > 0.7)

            X_windows.append(window)
            y_labels.append(label)

    return np.array(X_windows), np.array(y_labels, dtype=np.float32)


def train_lstm_model(
    n_epochs: int = 20,
    batch_size: int = 64,
    learning_rate: float = 5e-4,
) -> MaintenanceLSTM:
    """Train the maintenance LSTM with gradient clipping."""
    from torch.utils.data import TensorDataset

    X, y = generate_maintenance_sequences()
    logger.info(f"Generated {len(X):,} sequence windows from {200} synthetic assets")
    logger.info(f"Positive rate (failure events): {y.mean():.1%}")

    # Time-based split: last 15% of windows are validation
    split_idx = int(len(X) * 0.85)
    X_train, X_val = X[:split_idx], X[split_idx:]
    y_train, y_val = y[:split_idx], y[split_idx:]

    train_ds = TensorDataset(
        torch.tensor(X_train),
        torch.tensor(y_train),
    )
    val_ds = TensorDataset(
        torch.tensor(X_val),
        torch.tensor(y_val),
    )

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size * 2, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = MaintenanceLSTM(n_sensor_features=8, hidden_size=64, n_layers=2).to(device)

    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    # Positive class weight: failures are ~30% of data — upweight to compensate
    pos_weight = torch.tensor([(1 - y_train.mean()) / y_train.mean()]).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_val_loss = float("inf")

    for epoch in range(n_epochs):
        model.train()
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            logits = model(X_batch)

            # Use raw logits with BCEWithLogitsLoss (numerically more stable than BCE + sigmoid)
            loss = criterion(logits, y_batch)
            optimizer.zero_grad()
            loss.backward()

            # Gradient clipping: essential for LSTMs on long sequences
            # Without this, gradients can explode and produce NaN losses
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

        model.train(False)
        val_losses = []
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                logits = model(X_batch)
                val_losses.append(criterion(logits, y_batch).item())

        val_loss = np.mean(val_losses)
        if val_loss < best_val_loss:
            best_val_loss = val_loss

        if epoch % 5 == 0:
            logger.info(f"Epoch {epoch:3d}: val_loss={val_loss:.4f}")

    logger.info(f"Best validation loss: {best_val_loss:.4f}")
    return model


if __name__ == "__main__":
    logger.info("=== Core PyTorch Concepts ===")
    demonstrate_autograd()
    demonstrate_train_eval_modes()

    logger.info("\n=== Feedforward Network: Equipment Readiness ===")
    readiness_model = train_readiness_model(n_epochs=10)  # reduce for quick demo

    logger.info("\n=== LSTM: Sequential Maintenance Prediction ===")
    lstm_model = train_lstm_model(n_epochs=10)
    logger.info("Training complete.")
