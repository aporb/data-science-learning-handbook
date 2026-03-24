"""
Chapter 08 — Deep Learning and Neural Networks
Example 02: CNN transfer learning for satellite imagery classification

Use case: Classify overhead imagery into facility types for ISR analysis
Classes: airfield, naval_base, logistics_depot, command_facility, other
Platform: Databricks ML Runtime (GPU cluster), Advana, Navy Jupiter

Key concepts:
    - Transfer learning from ImageNet pre-trained ResNet-50
    - Separate learning rates: backbone (10x lower) vs. classification head
    - Domain-appropriate augmentation for satellite/overhead imagery
    - Grad-CAM saliency maps for explainability (required for operational AI review)
    - MLflow experiment tracking and model registration

Dependencies: torch, torchvision, Pillow, numpy, mlflow
"""

import os
import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import torchvision.models as models
import torchvision.transforms as transforms
from torch.utils.data import Dataset, DataLoader
from PIL import Image
import mlflow
import mlflow.pytorch

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FACILITY_CLASSES = ["airfield", "naval_base", "logistics_depot", "command_facility", "other"]
N_CLASSES = len(FACILITY_CLASSES)
CLASS_TO_IDX = {c: i for i, c in enumerate(FACILITY_CLASSES)}
IDX_TO_CLASS = {i: c for i, c in enumerate(FACILITY_CLASSES)}

# ImageNet normalization — required when using pretrained weights
IMAGENET_MEAN = [0.485, 0.456, 0.406]
IMAGENET_STD  = [0.229, 0.224, 0.225]

# ---------------------------------------------------------------------------
# Transforms
# ---------------------------------------------------------------------------

# Training: aggressive augmentation because satellite imagery varies by sensor,
# altitude, time of day, and season. RandomVerticalFlip because overhead images
# have no canonical "up" direction.
train_transforms = transforms.Compose([
    transforms.Resize((256, 256)),
    transforms.RandomCrop(224),
    transforms.RandomHorizontalFlip(p=0.5),
    transforms.RandomVerticalFlip(p=0.5),            # Unique to overhead imagery
    transforms.RandomRotation(degrees=15),
    transforms.ColorJitter(brightness=0.2, contrast=0.2, saturation=0.1),
    transforms.ToTensor(),
    transforms.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
])

# Validation/test: deterministic, center-cropped
val_transforms = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
])


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class SatelliteImageDataset(Dataset):
    """
    Dataset for overhead imagery classification.
    Directory structure: root/class_name/image_file.jpg

    In a Databricks + Unity Catalog environment, images are stored in a
    managed volume and accessed via mounted paths (e.g., /Volumes/catalog/schema/vol/).
    The path handling below works for both local and Databricks volume paths.
    """

    def __init__(self, root_dir: str, transform=None, class_names: list = None):
        self.transform = transform
        self.class_names = class_names or FACILITY_CLASSES
        self.class_to_idx = {c: i for i, c in enumerate(self.class_names)}
        self.samples = []

        root = Path(root_dir)
        for class_name in self.class_names:
            class_dir = root / class_name
            if not class_dir.exists():
                log.warning("Class directory not found: %s", class_dir)
                continue
            for fpath in class_dir.iterdir():
                if fpath.suffix.lower() in (".jpg", ".jpeg", ".png", ".tif", ".tiff"):
                    self.samples.append((str(fpath), self.class_to_idx[class_name]))

        log.info("Dataset: %s samples in %s | Root: %s",
                 f"{len(self.samples):,}", root_dir, root)

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        img_path, label = self.samples[idx]
        image = Image.open(img_path).convert("RGB")
        if self.transform:
            image = self.transform(image)
        return image, label, img_path  # Return path for audit/debugging


# ---------------------------------------------------------------------------
# Model: ResNet-50 with custom classification head
# ---------------------------------------------------------------------------

def build_facility_classifier(
    n_classes: int = N_CLASSES,
    freeze_backbone: bool = True,
    dropout_rate: float = 0.5,
) -> nn.Module:
    """
    Build a ResNet-50 fine-tuned for facility classification.

    freeze_backbone=True:
        Only train the classification head.
        Use when labeled dataset < 5,000 images.
        Prevents overfitting. Training is fast (< 10 min on single GPU).

    freeze_backbone=False:
        Train all layers. Lower LR on backbone, higher on head.
        Use when labeled dataset >= 5,000-10,000 images.
        Maximum performance but requires careful regularization.
    """
    model = models.resnet50(weights=models.ResNet50_Weights.IMAGENET1K_V2)

    if freeze_backbone:
        for param in model.parameters():
            param.requires_grad = False

    # ResNet-50's final layer: Linear(2048, 1000)
    # Replace with a deeper head for better fine-tuning
    model.fc = nn.Sequential(
        nn.Dropout(dropout_rate),
        nn.Linear(2048, 512),
        nn.BatchNorm1d(512),
        nn.ReLU(inplace=True),
        nn.Dropout(dropout_rate * 0.6),
        nn.Linear(512, n_classes),
    )

    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    log.info("Trainable parameters: %s (backbone frozen: %s)",
             f"{n_params:,}", freeze_backbone)

    return model


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def fine_tune_facility_classifier(
    train_dir: str,
    val_dir: str,
    output_dir: str = "./facility_classifier",
    n_epochs: int = 30,
    batch_size: int = 32,
    head_lr: float = 1e-3,
    backbone_lr: float = 1e-4,       # 10x lower than head — backbone adapts slowly
    freeze_backbone: bool = True,
    device: str = None,
    mlflow_experiment: str = "facility_classification",
) -> nn.Module:
    """
    Fine-tune ResNet-50 on overhead facility imagery.
    Logs all runs to MLflow (auto-configured on Databricks).
    """
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    os.makedirs(output_dir, exist_ok=True)

    train_ds = SatelliteImageDataset(train_dir, transform=train_transforms)
    val_ds   = SatelliteImageDataset(val_dir,   transform=val_transforms)

    if len(train_ds) == 0:
        raise ValueError(f"No training images found in {train_dir}")

    train_loader = DataLoader(
        train_ds, batch_size=batch_size, shuffle=True,
        num_workers=min(4, os.cpu_count() or 1), pin_memory=(device == "cuda")
    )
    val_loader = DataLoader(
        val_ds, batch_size=batch_size * 2, shuffle=False,
        num_workers=min(4, os.cpu_count() or 1), pin_memory=(device == "cuda")
    )

    model = build_facility_classifier(freeze_backbone=freeze_backbone).to(device)

    # Separate parameter groups with different learning rates
    backbone_params = [p for n, p in model.named_parameters()
                       if "fc" not in n and p.requires_grad]
    head_params = list(model.fc.parameters())

    optimizer = optim.AdamW([
        {"params": backbone_params, "lr": backbone_lr},
        {"params": head_params,     "lr": head_lr},
    ], weight_decay=1e-4)

    # Label smoothing: prevents overconfidence on ambiguous facility types
    criterion = nn.CrossEntropyLoss(label_smoothing=0.1)

    # Cosine annealing: smoothly reduces LR over training
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=n_epochs)

    best_val_acc = 0.0
    best_model_path = os.path.join(output_dir, "best_model.pt")

    mlflow.set_experiment(mlflow_experiment)
    with mlflow.start_run(run_name=f"resnet50_facility_{batch_size}bs"):
        mlflow.log_params({
            "architecture": "resnet50",
            "n_classes": N_CLASSES,
            "freeze_backbone": freeze_backbone,
            "n_epochs": n_epochs,
            "batch_size": batch_size,
            "head_lr": head_lr,
            "backbone_lr": backbone_lr,
            "n_train": len(train_ds),
            "n_val": len(val_ds),
        })

        for epoch in range(1, n_epochs + 1):
            # ---- Training ----
            model.train()
            train_correct = train_total = 0
            train_loss_sum = 0.0

            for images, labels, _ in train_loader:
                images, labels = images.to(device), labels.to(device)
                optimizer.zero_grad()
                outputs = model(images)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()

                _, predicted = outputs.max(1)
                train_total   += labels.size(0)
                train_correct += predicted.eq(labels).sum().item()
                train_loss_sum += loss.item() * labels.size(0)

            train_acc  = train_correct / train_total * 100
            train_loss = train_loss_sum / train_total

            # ---- Validation ----
            model.train(False)
            val_correct = val_total = 0
            val_loss_sum = 0.0

            with torch.no_grad():
                for images, labels, _ in val_loader:
                    images, labels = images.to(device), labels.to(device)
                    outputs = model(images)
                    loss = criterion(outputs, labels)
                    _, predicted = outputs.max(1)
                    val_total   += labels.size(0)
                    val_correct += predicted.eq(labels).sum().item()
                    val_loss_sum += loss.item() * labels.size(0)

            val_acc  = val_correct / val_total * 100
            val_loss = val_loss_sum / val_total

            scheduler.step()

            mlflow.log_metrics({
                "train_acc": train_acc,
                "train_loss": train_loss,
                "val_acc": val_acc,
                "val_loss": val_loss,
                "lr_head": optimizer.param_groups[1]["lr"],
            }, step=epoch)

            log.info("Epoch %3d: train=%.1f%%  val=%.1f%%  train_loss=%.4f  val_loss=%.4f",
                     epoch, train_acc, val_acc, train_loss, val_loss)

            if val_acc > best_val_acc:
                best_val_acc = val_acc
                torch.save(model.state_dict(), best_model_path)
                log.info("  → New best: %.1f%%", best_val_acc)

        # Load and log best model
        model.load_state_dict(torch.load(best_model_path, map_location=device))
        mlflow.pytorch.log_model(model, "model", registered_model_name="facility_classifier_v1")
        mlflow.log_metric("best_val_acc", best_val_acc)

    log.info("Fine-tuning complete. Best val accuracy: %.1f%%", best_val_acc)
    return model


# ---------------------------------------------------------------------------
# Grad-CAM: saliency maps for explainability
# ---------------------------------------------------------------------------

class GradCAM:
    """
    Gradient-weighted Class Activation Maps (Grad-CAM) for CNN explainability.

    Required for DoD AI system reviews: provides visual evidence of what
    spatial regions the model uses to make its classification.
    Attach the output visualization to model card and review documentation.

    Reference: Selvaraju et al., "Grad-CAM: Visual Explanations from Deep
    Networks via Gradient-based Localization," ICCV 2017.
    """

    def __init__(self, model: nn.Module, target_layer: nn.Module):
        self.model = model
        self.target_layer = target_layer
        self.gradients = None
        self.activations = None

        # Register hooks to capture gradients and activations at target layer
        self._register_hooks()

    def _register_hooks(self):
        def forward_hook(module, input, output):
            self.activations = output.detach()

        def backward_hook(module, grad_in, grad_out):
            self.gradients = grad_out[0].detach()

        self.target_layer.register_forward_hook(forward_hook)
        self.target_layer.register_full_backward_hook(backward_hook)

    def generate(self, image_tensor: torch.Tensor, class_idx: int = None) -> np.ndarray:
        """
        Generate Grad-CAM heatmap for a single image.

        Args:
            image_tensor: Shape (1, 3, H, W), normalized, on correct device
            class_idx: Target class (None = predicted class)

        Returns:
            heatmap: numpy array shape (H, W), values in [0, 1]
        """
        self.model.train(False)
        self.model.zero_grad()

        output = self.model(image_tensor)

        if class_idx is None:
            class_idx = output.argmax(dim=1).item()

        # Backpropagate with respect to the target class score
        one_hot = torch.zeros_like(output)
        one_hot[0, class_idx] = 1.0
        output.backward(gradient=one_hot)

        # Pool gradients across spatial dimensions
        pooled_grads = self.gradients.mean(dim=[2, 3], keepdim=True)

        # Weight activations by pooled gradients
        cam = (pooled_grads * self.activations).sum(dim=1, keepdim=True)
        cam = torch.relu(cam)  # Keep only positive contributions

        # Normalize to [0, 1]
        cam = cam.squeeze().cpu().numpy()
        cam = (cam - cam.min()) / (cam.max() - cam.min() + 1e-8)

        return cam

    @staticmethod
    def overlay_on_image(
        original_img: np.ndarray,
        heatmap: np.ndarray,
        alpha: float = 0.4,
    ) -> np.ndarray:
        """
        Overlay Grad-CAM heatmap on the original image.
        Returns an RGB numpy array suitable for display or saving.
        """
        import cv2  # opencv-python — available in Databricks ML Runtime

        heatmap_resized = cv2.resize(heatmap, (original_img.shape[1], original_img.shape[0]))
        heatmap_colored = cv2.applyColorMap(
            (heatmap_resized * 255).astype(np.uint8), cv2.COLORMAP_JET
        )
        heatmap_rgb = cv2.cvtColor(heatmap_colored, cv2.COLOR_BGR2RGB)
        overlay = (alpha * heatmap_rgb + (1 - alpha) * original_img).astype(np.uint8)
        return overlay


def explain_prediction(
    model: nn.Module,
    image_path: str,
    device: str = "cpu",
) -> dict:
    """
    Generate a Grad-CAM explanation for a single image prediction.
    Returns prediction, confidence, and the heatmap array.
    """
    image_raw = Image.open(image_path).convert("RGB")
    image_tensor = val_transforms(image_raw).unsqueeze(0).to(device)

    # Target layer: last convolutional block of ResNet-50
    target_layer = model.layer4[-1].conv3

    cam = GradCAM(model, target_layer)
    heatmap = cam.generate(image_tensor)

    model.train(False)
    with torch.no_grad():
        logits = model(image_tensor)
        probs = torch.softmax(logits, dim=-1)[0].cpu().numpy()

    pred_idx = int(probs.argmax())
    return {
        "predicted_class": IDX_TO_CLASS[pred_idx],
        "confidence": float(probs[pred_idx]),
        "class_probabilities": {IDX_TO_CLASS[i]: float(p) for i, p in enumerate(probs)},
        "gradcam_heatmap": heatmap,
    }


# ---------------------------------------------------------------------------
# Synthetic data generator for testing without real imagery
# ---------------------------------------------------------------------------

def create_synthetic_dataset(base_dir: str, n_per_class: int = 20, img_size: int = 64):
    """
    Create a small synthetic dataset of random color-pattern images per class.
    Useful for testing the training pipeline without real imagery.
    Each class gets a distinctive color pattern to make the problem learnable.
    """
    import random
    rng = np.random.RandomState(42)
    base = Path(base_dir)
    colors = {
        "airfield": ([200, 200, 200], [100, 100, 100]),    # Gray tones (concrete)
        "naval_base": ([30, 100, 180], [20, 60, 120]),     # Blue tones (water)
        "logistics_depot": ([140, 110, 70], [80, 60, 40]), # Brown/tan (warehouse)
        "command_facility": ([60, 140, 60], [40, 90, 40]), # Green (landscaped)
        "other": ([180, 60, 60], [120, 40, 40]),           # Red tones (misc)
    }
    for split in ["train", "val"]:
        for class_name in FACILITY_CLASSES:
            class_dir = base / split / class_name
            class_dir.mkdir(parents=True, exist_ok=True)
            mean_color, var_color = colors[class_name]
            n = n_per_class if split == "train" else max(5, n_per_class // 4)
            for i in range(n):
                img_array = np.clip(
                    np.array(mean_color) + rng.randint(-30, 30, size=(img_size, img_size, 3)),
                    0, 255
                ).astype(np.uint8)
                img = Image.fromarray(img_array)
                img.save(str(class_dir / f"{class_name}_{split}_{i:04d}.png"))

    log.info("Synthetic dataset created at %s", base_dir)
    return str(base / "train"), str(base / "val")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    log.info("Creating synthetic test dataset...")
    with tempfile.TemporaryDirectory() as tmpdir:
        train_dir, val_dir = create_synthetic_dataset(tmpdir, n_per_class=40)

        log.info("Starting fine-tuning on synthetic data...")
        model = fine_tune_facility_classifier(
            train_dir=train_dir,
            val_dir=val_dir,
            output_dir=os.path.join(tmpdir, "output"),
            n_epochs=5,          # Small for demo
            batch_size=8,
            freeze_backbone=True,
        )

        log.info("Testing Grad-CAM explanation on a sample image...")
        # Find a sample image
        sample_image = next(Path(val_dir).rglob("*.png"), None)
        if sample_image:
            explanation = explain_prediction(model, str(sample_image), device="cpu")
            print(f"\nPrediction for {sample_image.name}:")
            print(f"  Predicted: {explanation['predicted_class']}")
            print(f"  Confidence: {explanation['confidence']:.1%}")
            print(f"  All probabilities:")
            for cls, prob in explanation['class_probabilities'].items():
                bar = "█" * int(prob * 20)
                print(f"    {cls:20s}: {prob:.3f} {bar}")
            print(f"  Grad-CAM heatmap shape: {explanation['gradcam_heatmap'].shape}")
        else:
            log.warning("No sample image found for Grad-CAM demo")
