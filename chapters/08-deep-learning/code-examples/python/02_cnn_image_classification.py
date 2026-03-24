"""
Chapter 08 — Deep Learning and Neural Networks
Example 02: CNN image classification for government computer vision tasks

Use cases covered:
  1. Transfer learning: fine-tuning ResNet-50 (ImageNet) on facility imagery
  2. Data augmentation strategy for satellite/overhead imagery
  3. Dual learning rates: low LR for backbone, high LR for head
  4. Grad-CAM saliency maps for model explainability
  5. Multi-GPU training via Databricks TorchDistributor (annotated)
  6. Air-gapped model loading: local path patterns for IL5 environments

Platform targets:
  - Databricks (FedRAMP High, AWS GovCloud, IL5) — primary training platform
  - Local / Advana / Jupiter — single-GPU or CPU for development

Dependencies: torch, torchvision, numpy, pillow, mlflow
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import mlflow
import mlflow.pytorch
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from PIL import Image
from torch.utils.data import DataLoader, Dataset
from torchvision import models, transforms

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# =============================================================================
# Facility classes for the classification task
# =============================================================================

FACILITY_CLASSES = [
    "airfield",          # runways, taxiways, hardened aircraft shelters
    "port_facility",     # piers, cranes, naval vessel berths
    "logistics_depot",   # warehouse complexes, marshalling yards
    "command_center",    # hardened structures, antenna arrays
    "training_range",    # impact areas, range control structures
]


# =============================================================================
# Dataset
# =============================================================================

class FacilityImageDataset(Dataset):
    """
    Dataset for overhead/satellite facility imagery classification.

    Directory structure expected:
        data_dir/
            airfield/
                img_001.jpg
                img_002.jpg
            port_facility/
                img_001.jpg
            ...

    In a real Advana/Databricks program:
    - Raw imagery is stored in Delta Lake Bronze tier (binary files or DBFS paths)
    - Labeled tiles are in Silver tier with metadata (class, coordinates, collection date)
    - This Dataset reads from a local copy exported to DBFS or a mounted NFS share
    """

    def __init__(self, data_dir: str, transform=None, class_names: Optional[List[str]] = None):
        self.data_dir = Path(data_dir)
        self.transform = transform
        self.class_names = class_names or FACILITY_CLASSES
        self.class_to_idx = {cls: idx for idx, cls in enumerate(self.class_names)}

        self.samples: List[Tuple[Path, int]] = []
        for class_name in self.class_names:
            class_dir = self.data_dir / class_name
            if class_dir.exists():
                for img_path in class_dir.glob("*.jpg"):
                    self.samples.append((img_path, self.class_to_idx[class_name]))
                for img_path in class_dir.glob("*.png"):
                    self.samples.append((img_path, self.class_to_idx[class_name]))

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, int]:
        img_path, label = self.samples[idx]
        image = Image.open(img_path).convert("RGB")
        if self.transform:
            image = self.transform(image)
        return image, label


def get_transforms(mode: str = "train") -> transforms.Compose:
    """
    Return transforms appropriate for satellite/overhead imagery.

    Key difference from standard ImageNet augmentation:
    - RandomVerticalFlip is included (satellite imagery has no canonical up-orientation)
    - ColorJitter accounts for sensor calibration variance and atmospheric conditions
    - No RandomRotation at 45/90 — use dedicated overhead imagery augmentation
      libraries (e.g., albumentations with CoarseDropout for cloud occlusion) if available
    """
    normalize = transforms.Normalize(
        mean=[0.485, 0.456, 0.406],  # ImageNet statistics — fine for overhead RGB imagery
        std=[0.229, 0.224, 0.225],
    )

    if mode == "train":
        return transforms.Compose([
            transforms.Resize((256, 256)),
            transforms.RandomCrop(224),
            transforms.RandomHorizontalFlip(),
            transforms.RandomVerticalFlip(),   # Valid for overhead imagery
            transforms.ColorJitter(
                brightness=0.2,
                contrast=0.2,
                saturation=0.1,
                hue=0.05,
            ),
            transforms.ToTensor(),
            normalize,
        ])
    else:  # val / test
        return transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            normalize,
        ])


# =============================================================================
# Model: ResNet-50 with transfer learning
# =============================================================================

def build_facility_classifier(
    n_classes: int = 5,
    freeze_backbone: bool = True,
    pretrained_weights_path: Optional[str] = None,
) -> nn.Module:
    """
    Build a ResNet-50 fine-tuned for facility classification.

    Two loading modes:
    1. Standard (internet available): loads from PyTorch Hub cache or downloads
    2. Air-gapped (IL5 classified network): loads from local path

    For air-gapped environments, set pretrained_weights_path to the local path
    where ResNet-50 weights were imported after media transfer.

    The air-gapped weight file is obtained by:
        import torch
        from torchvision.models import resnet50, ResNet50_Weights
        m = resnet50(weights=ResNet50_Weights.IMAGENET1K_V2)
        torch.save(m.state_dict(), "resnet50_imagenet1k_v2.pth")
    Then transfer this .pth file via DD-1149 media transfer to the secure environment.
    """
    if pretrained_weights_path and os.path.exists(pretrained_weights_path):
        # Air-gapped environment: load pre-downloaded weights from local path
        logger.info(f"Loading ResNet-50 weights from local path: {pretrained_weights_path}")
        model = models.resnet50(weights=None)  # initialize architecture without downloading
        state_dict = torch.load(pretrained_weights_path, map_location="cpu")
        model.load_state_dict(state_dict)
    else:
        # Standard environment: download from PyTorch Hub if not cached
        logger.info("Loading ResNet-50 with ImageNet1K-V2 weights")
        model = models.resnet50(weights=models.ResNet50_Weights.IMAGENET1K_V2)

    if freeze_backbone:
        # Freeze all parameters in the backbone — only the new head will train
        for param in model.parameters():
            param.requires_grad = False

    # Replace the final fully connected layer with a task-specific head
    # ResNet-50's final layer has 2048 input features
    in_features = model.fc.in_features
    model.fc = nn.Sequential(
        nn.Dropout(p=0.4),           # regularization for small government datasets
        nn.Linear(in_features, 256),
        nn.ReLU(),
        nn.Dropout(p=0.2),
        nn.Linear(256, n_classes),
    )

    return model


def fine_tune_facility_classifier(
    model: nn.Module,
    train_loader: DataLoader,
    val_loader: DataLoader,
    n_epochs: int = 15,
    backbone_lr: float = 1e-5,   # low LR for pretrained backbone
    head_lr: float = 1e-3,       # higher LR for new classification head
    device: Optional[torch.device] = None,
    mlflow_experiment: str = "facility-classification",
) -> nn.Module:
    """
    Fine-tune with separate learning rates for backbone and head.

    Why two learning rates?
    The backbone (ResNet-50 layers 1 through layer4) contains ImageNet representations
    that still transfer — edge detectors, texture sensors, object shape detectors.
    These need to adapt, but slowly. Set backbone LR to 1/10th of head LR.

    If you set one LR for everything:
    - High LR: backbone catastrophically forgets ImageNet representations
    - Low LR: head learns too slowly and underperforms for the available data
    """
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = model.to(device)

    # Separate parameter groups with different learning rates
    backbone_params = [
        p for name, p in model.named_parameters()
        if "fc" not in name and p.requires_grad
    ]
    head_params = list(model.fc.parameters())

    optimizer = optim.AdamW([
        {"params": backbone_params, "lr": backbone_lr},
        {"params": head_params, "lr": head_lr},
    ], weight_decay=1e-4)

    # Label smoothing: prevents overconfidence on ambiguous facility types
    criterion = nn.CrossEntropyLoss(label_smoothing=0.1)

    scheduler = optim.lr_scheduler.CosineAnnealingLR(
        optimizer,
        T_max=n_epochs,
        eta_min=backbone_lr * 0.01,
    )

    mlflow.set_experiment(mlflow_experiment)
    with mlflow.start_run(run_name="resnet50-facility-finetune"):
        mlflow.log_params({
            "architecture": "resnet50",
            "backbone_lr": backbone_lr,
            "head_lr": head_lr,
            "n_epochs": n_epochs,
            "label_smoothing": 0.1,
            "dropout_head": 0.4,
        })

        best_val_acc = 0.0
        best_state = None

        for epoch in range(n_epochs):
            # --- Training ---
            model.train()
            total, correct, running_loss = 0, 0, 0.0

            for images, labels in train_loader:
                images, labels = images.to(device), labels.to(device)
                logits = model(images)
                loss = criterion(logits, labels)

                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
                optimizer.step()

                running_loss += loss.item() * len(labels)
                correct += (logits.argmax(dim=1) == labels).sum().item()
                total += len(labels)

            train_acc = correct / total
            train_loss = running_loss / total
            scheduler.step()

            # --- Validation ---
            model.train(False)
            val_total, val_correct = 0, 0
            with torch.no_grad():
                for images, labels in val_loader:
                    images, labels = images.to(device), labels.to(device)
                    preds = model(images).argmax(dim=1)
                    val_correct += (preds == labels).sum().item()
                    val_total += len(labels)

            val_acc = val_correct / val_total
            mlflow.log_metrics({
                "train_accuracy": train_acc,
                "train_loss": train_loss,
                "val_accuracy": val_acc,
            }, step=epoch)

            if val_acc > best_val_acc:
                best_val_acc = val_acc
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

            if epoch % 3 == 0:
                logger.info(
                    f"Epoch {epoch:3d}: "
                    f"train_loss={train_loss:.4f}, train_acc={train_acc:.3f}, "
                    f"val_acc={val_acc:.3f}"
                )

        model.load_state_dict(best_state)
        mlflow.log_metric("best_val_accuracy", best_val_acc)
        mlflow.pytorch.log_model(model, artifact_path="facility_classifier")
        logger.info(f"Best validation accuracy: {best_val_acc:.3f}")

    return model


# =============================================================================
# Grad-CAM: Explainability for Classification Decisions
# =============================================================================

class GradCAM:
    """
    Gradient-weighted Class Activation Mapping (Grad-CAM).

    Grad-CAM produces a heatmap showing which regions of the input image most
    influenced the model's classification decision. For government computer vision,
    this is the explainability mechanism: when a contracting officer or program manager
    asks "why did the model classify this as an airfield?", you show the heatmap
    highlighting the runway and taxiway areas.

    Works on any CNN with spatial feature maps — ResNet, VGG, EfficientNet, etc.
    """

    def __init__(self, model: nn.Module, target_layer: nn.Module):
        self.model = model
        self.target_layer = target_layer
        self.gradients: Optional[torch.Tensor] = None
        self.activations: Optional[torch.Tensor] = None

        # Register hooks to capture gradients and activations during forward/backward
        target_layer.register_forward_hook(self._save_activation)
        target_layer.register_full_backward_hook(self._save_gradient)

    def _save_activation(self, module, input, output):
        self.activations = output.detach()

    def _save_gradient(self, module, grad_input, grad_output):
        self.gradients = grad_output[0].detach()

    def generate_heatmap(
        self,
        image_tensor: torch.Tensor,
        class_idx: Optional[int] = None,
        device: Optional[torch.device] = None,
    ) -> np.ndarray:
        """
        Generate a Grad-CAM heatmap for the given image.

        Returns a numpy array of shape (H, W) with values in [0, 1],
        where higher values indicate regions more important for the prediction.
        """
        if device is None:
            device = next(self.model.parameters()).device

        image_tensor = image_tensor.unsqueeze(0).to(device)  # add batch dim

        # Forward pass with gradient tracking enabled
        self.model.train(False)
        logits = self.model(image_tensor)

        if class_idx is None:
            class_idx = logits.argmax(dim=1).item()

        # Backward pass to get gradients for the target class
        self.model.zero_grad()
        logits[0, class_idx].backward()

        # Global average pooling of gradients to get channel importance weights
        # Shape: (n_channels,)
        weights = self.gradients.mean(dim=(2, 3))[0]

        # Weighted combination of activation maps
        # activations shape: (1, n_channels, h, w)
        cam = torch.zeros(
            self.activations.shape[2],
            self.activations.shape[3],
            device=device,
        )
        for i, w in enumerate(weights):
            cam += w * self.activations[0, i]

        # ReLU: only keep positive contributions
        cam = torch.relu(cam)

        # Normalize to [0, 1]
        if cam.max() > 0:
            cam = cam / cam.max()

        return cam.cpu().numpy()


def explain_prediction(
    model: nn.Module,
    image_tensor: torch.Tensor,
    class_names: List[str] = FACILITY_CLASSES,
) -> Dict:
    """
    Run inference and generate a Grad-CAM explanation.

    Returns predicted class, confidence scores, and heatmap array.
    The heatmap can be overlaid on the original image using matplotlib
    or exported as a Foundry Workshop visualization artifact.
    """
    # For ResNet-50, the last convolutional block is model.layer4[-1].conv3
    # This is the layer with the richest semantic feature maps
    target_layer = model.layer4[-1].conv3
    gradcam = GradCAM(model, target_layer)

    device = next(model.parameters()).device
    image_batch = image_tensor.unsqueeze(0).to(device)

    model.train(False)
    with torch.no_grad():
        logits = model(image_batch)
    probabilities = torch.softmax(logits, dim=1)[0].cpu().numpy()

    predicted_class_idx = int(probabilities.argmax())
    predicted_class = class_names[predicted_class_idx]
    confidence = float(probabilities[predicted_class_idx])

    # Generate heatmap for the predicted class
    heatmap = gradcam.generate_heatmap(
        image_tensor,
        class_idx=predicted_class_idx,
        device=device,
    )

    return {
        "predicted_class": predicted_class,
        "confidence": confidence,
        "class_probabilities": {
            cls: float(p) for cls, p in zip(class_names, probabilities)
        },
        "heatmap": heatmap,  # numpy array (H, W), overlay on original for visualization
    }


# =============================================================================
# Multi-GPU training stub: Databricks TorchDistributor
# =============================================================================

def train_distributed_databricks(n_gpus: int = 4, data_dir: str = "/dbfs/imagery/facilities"):
    """
    Multi-GPU training via Databricks TorchDistributor.

    Run this from a Databricks notebook cell on a GPU ML cluster.
    The `spark` session and SparkContext are already available in that environment.

    Each GPU worker gets an exclusive, non-overlapping data shard via DistributedSampler.
    Gradients are synchronized across workers after each backward pass via NCCL.

    Cost guidance: an 8xA10g cluster runs ~7x faster than 1xA10g for large datasets,
    but has 8x the per-GPU cost. For datasets under 50K images and training runs
    under 2 hours, a single A10g is more cost-effective.
    """
    # This block runs only in a Databricks notebook environment
    try:
        from pyspark.ml.torch.distributor import TorchDistributor
    except ImportError:
        logger.warning("TorchDistributor not available outside Databricks — skipping distributed demo")
        return

    def train_worker_fn():
        import os
        import torch
        import torch.distributed as dist
        from torch.nn.parallel import DistributedDataParallel as DDP
        from torch.utils.data import DistributedSampler

        local_rank = int(os.environ["LOCAL_RANK"])
        device = torch.device(f"cuda:{local_rank}")
        dist.init_process_group(backend="nccl")

        model = build_facility_classifier(freeze_backbone=False)
        model = model.to(device)
        model = DDP(model, device_ids=[local_rank])

        train_transforms = get_transforms("train")
        train_ds = FacilityImageDataset(data_dir, transform=train_transforms)
        sampler = DistributedSampler(train_ds)
        train_loader = DataLoader(
            train_ds,
            batch_size=32,
            sampler=sampler,
            num_workers=4,
            pin_memory=True,
        )

        optimizer = optim.AdamW(model.parameters(), lr=1e-4)
        criterion = nn.CrossEntropyLoss(label_smoothing=0.1)

        for epoch in range(15):
            sampler.set_epoch(epoch)  # ensures different shuffle per epoch across workers
            model.train()
            for images, labels in train_loader:
                images, labels = images.to(device), labels.to(device)
                loss = criterion(model(images), labels)
                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
                optimizer.step()

        dist.destroy_process_group()

    distributor = TorchDistributor(
        num_processes=n_gpus,
        local_mode=False,
        use_gpu=True,
    )
    distributor.run(train_worker_fn)


# =============================================================================
# Synthetic dataset creation for testing without real imagery
# =============================================================================

def create_synthetic_dataset(
    output_dir: str = "/tmp/synthetic_facility_data",
    n_per_class: int = 50,
    image_size: int = 256,
) -> str:
    """
    Create a synthetic image dataset for testing the pipeline without real imagery.
    Each class gets images with distinct color patterns to test that the model
    can differentiate classes at all.

    NOT a realistic benchmark — use this only to verify the training pipeline runs
    before investing time in real labeled data.
    """
    output_path = Path(output_dir)

    class_colors = {
        "airfield": (180, 180, 120),       # grey-tan for concrete runways
        "port_facility": (60, 90, 140),    # blue-grey for water/metal
        "logistics_depot": (130, 110, 80), # brown for earth/warehouse
        "command_center": (80, 80, 80),    # dark grey for hardened structures
        "training_range": (100, 150, 80),  # green for terrain
    }

    rng = np.random.RandomState(42)

    for class_name, base_color in class_colors.items():
        class_dir = output_path / class_name
        class_dir.mkdir(parents=True, exist_ok=True)

        for i in range(n_per_class):
            # Add noise to base color to simulate sensor variance
            noise = rng.randint(-30, 30, (image_size, image_size, 3))
            pixel_values = (np.array(base_color) + noise).clip(0, 255).astype(np.uint8)

            img = Image.fromarray(pixel_values, mode="RGB")
            img.save(class_dir / f"synthetic_{i:04d}.jpg")

    total_images = len(FACILITY_CLASSES) * n_per_class
    logger.info(f"Created {total_images} synthetic images in {output_dir}")
    return output_dir


if __name__ == "__main__":
    # Create synthetic data and run a quick training demonstration
    data_dir = create_synthetic_dataset(n_per_class=40)

    train_transforms = get_transforms("train")
    val_transforms = get_transforms("val")

    # For demo: use first 32 samples as train, rest as val
    # In production: use a proper time-based or stratified split
    full_ds = FacilityImageDataset(data_dir, transform=train_transforms)
    train_size = int(0.8 * len(full_ds))
    val_size = len(full_ds) - train_size

    from torch.utils.data import random_split
    train_ds, val_ds = random_split(
        full_ds,
        [train_size, val_size],
        generator=torch.Generator().manual_seed(42),
    )

    # Override val transform (random_split doesn't support separate transforms;
    # in production use two separate Dataset instances with appropriate transforms)
    train_loader = DataLoader(train_ds, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=16, shuffle=False)

    logger.info(f"Dataset: {train_size} train, {val_size} val")

    # Build model — local weights path set to None (will use internet if available)
    # On an air-gapped IL5 network, set this to the transferred .pth file path
    AIRGAPPED_WEIGHTS_PATH = os.environ.get("RESNET50_WEIGHTS_PATH", None)

    model = build_facility_classifier(
        n_classes=len(FACILITY_CLASSES),
        freeze_backbone=True,
        pretrained_weights_path=AIRGAPPED_WEIGHTS_PATH,
    )

    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    logger.info(
        f"Trainable parameters: "
        f"{sum(p.numel() for p in model.parameters() if p.requires_grad):,}"
    )

    # Quick demo: 3 epochs to verify the pipeline runs
    fine_tune_facility_classifier(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        n_epochs=3,
    )

    # Test explainability on one sample
    sample_image, sample_label = full_ds[0]
    result = explain_prediction(model, sample_image)
    logger.info(f"Prediction: {result['predicted_class']} ({result['confidence']:.1%} confidence)")
    logger.info(f"Heatmap shape: {result['heatmap'].shape}")
    logger.info("Pipeline verification complete.")
