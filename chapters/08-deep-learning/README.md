# Chapter 08: Deep Learning and Neural Networks

The video feed was coming in at 30 frames per second from four separate drone platforms. Each frame was 1920x1080. The model had 400 milliseconds to decide — per frame, per camera — whether the object in the bounding box was a civilian vehicle, a military vehicle, or a known threat category. Not 400 milliseconds total. 400 milliseconds per inference, with all four feeds running simultaneously.

Kevin Okafor had trained object detection models before. He'd done it at a computer vision startup, on AWS SageMaker, using open-source weights and public benchmark datasets. That was fine work. But it had never mattered the way this mattered.

The program office had approved the use of a YOLOv8 architecture fine-tuned on DoD-classified imagery. The production environment was Palantir Foundry running on Azure Government at IL5. The training had happened on Databricks with A10g GPU clusters. Kevin had four weeks to validate that the model's latency profile was within spec, that its false positive rate on civilian vehicles was below 0.3%, and that the entire inference pipeline could be audited — every prediction logged, every confidence score recorded, every human override captured.

He had built a YOLO model before. He had never built one that needed to be auditable at IL5 classification levels with a documented kill chain review process.

This chapter is about what that kind of engineering actually requires.

Deep learning is not magic. It is differentiable function composition — stacking layers of learned transformations until the composition approximates whatever mapping you need. That framing sounds reductive, but it is actually clarifying. When you treat neural networks as learned function approximators, you can reason about them: what they can do well, where they fail systematically, what architectural choices serve which problems, and why the training process produces a model that generalizes or doesn't. In government contexts specifically, where the cost of a wrong prediction can be enormous, understanding the mechanics is not optional.

## What You'll Build

By the end of this chapter you will be able to:

- Build and train feedforward neural networks in PyTorch for tabular government data (readiness, financial, personnel)
- Apply convolutional neural networks to DoD computer vision tasks: satellite imagery classification, equipment inspection
- Use transformer architectures for NLP tasks on government document corpora: contract language classification, logistics narrative parsing
- Fine-tune pre-trained models (YOLO, BERT, ViT) on domain-specific government datasets using transfer learning
- Run GPU-accelerated training on Databricks Mosaic AI with A10g instances
- Deploy models in Palantir Foundry's AIP-integrated pipeline for operational decision support
- Log experiments, compare architectures, and version models with MLflow 3.0
- Understand the audit and explainability requirements that apply to DoD AI systems under DoD Directive 3000.09

## What a Neural Network Actually Is

Start here, because the foundation matters.

A feedforward neural network takes an input vector, multiplies it by a weight matrix, adds a bias, passes the result through a nonlinear activation function, and repeats that operation across multiple layers. The final layer produces an output — a classification, a regression value, a probability distribution. Training is the process of adjusting the weights to minimize a loss function, using the chain rule to propagate gradients backward through the layers.

That's the whole thing. Every architecture — convolutional networks, transformers, recurrent networks — is a variation on this pattern with structural constraints added for specific data types. CNNs add local connectivity and weight sharing for spatial data. Transformers add attention mechanisms for sequence data. LSTMs add gating for temporal dependencies.

The reason deep learning works so well across disparate domains is not that neural networks are inherently superior to other methods. It is that they are universal function approximators given sufficient width and depth, that gradient descent finds surprisingly good solutions for most practical loss landscapes, and that modern hardware (GPUs) can compute the matrix multiplications fast enough to make training feasible on large datasets.

What this means operationally: the choice to use deep learning over a gradient boosting tree or a logistic regression is not an automatic upgrade. Deep learning requires more data, more compute, longer training cycles, more complex debugging, and harder explainability. For a DoD readiness classification problem with 50,000 records and 40 features, XGBoost will likely outperform a neural network and be easier to explain to an auditor. For a satellite imagery classification task with 2 million labeled tiles, a CNN will outperform everything else.

Choose the right tool. Chapter 06 covers the cases where traditional ML wins. This chapter covers the cases where it doesn't.

## Feedforward Networks for Tabular Government Data

Government data is mostly tabular. Personnel records, financial obligations, logistics inventory, maintenance schedules — these are rows and columns, not images and text. The standard wisdom is that gradient boosted trees (XGBoost, LightGBM) dominate tabular data. That wisdom is broadly correct but not universal. Neural networks win on tabular data when:

- You have very large datasets (millions of rows) where trees start to plateau
- You need to jointly train on multiple input types (tabular + text + image features)
- You need learned embeddings for high-cardinality categorical variables (thousands of unit codes, equipment identifiers, contract vehicle codes)

The third case is the most practically relevant for government analytics. NAICS codes, unit identification codes (UICs), equipment NSNs, and contracting office codes each have thousands of distinct values. One-hot encoding collapses under that cardinality. Neural network embeddings learn dense representations that capture semantic relationships — two NSNs that are often co-requisitioned end up close in embedding space.

See `code-examples/python/01_tabular_neural_net.py` for the full implementation of an embedding-based readiness prediction network. The key architectural decisions:

**Learned embeddings for high-cardinality categoricals.** A unit code vocabulary of 5,000 UICs becomes a 16-dimensional dense vector per unit. The embedding learns that Carrier Strike Group 4 and Carrier Strike Group 8 should have similar representations because their maintenance patterns are similar — a fact that one-hot encoding cannot capture.

**Batch normalization between layers.** Government data has temporal distribution shifts: a unit at 80% readiness last quarter might be at 60% now because of a deployment cycle. BatchNorm stabilizes training when feature distributions shift between training and deployment.

**Early stopping with a validation set.** Never train to convergence on the full dataset. Hold out the most recent time period as your validation set — not a random 20% — because you want to know if the model generalizes to data that looks like deployment, not data that looks like training.

```mermaid
graph LR
    A[Unit Code<br/>5K categories] --> B[Embedding<br/>16-dim]
    C[Equipment Type<br/>200 categories] --> D[Embedding<br/>8-dim]
    E[Days since<br/>maintenance] --> F[Continuous<br/>features]
    G[Op hours] --> F
    H[Failure count<br/>90-day] --> F
    B --> I[Concatenate]
    D --> I
    F --> I
    I --> J[Dense 128<br/>BatchNorm + ReLU]
    J --> K[Dense 64<br/>BatchNorm + ReLU]
    K --> L[Dense 32<br/>BatchNorm + ReLU]
    L --> M[Output<br/>Priority Score 0-1]
```

*Figure: Embedding-based readiness network architecture. Categorical identifiers are learned as dense vectors; continuous features feed directly into the first hidden layer.*

## Convolutional Neural Networks: Satellite Imagery and Equipment Inspection

The DoD's ISR apparatus produces enormous volumes of imagery. Satellite imagery for facility monitoring. UAV imagery for battle damage assessment. Depot photography for equipment inspection. All of these are computer vision problems where CNNs are the right tool.

A CNN doesn't operate on flat pixel vectors. It scans the image with learned filters — small weight matrices that detect edges, textures, and eventually higher-level features — and builds a hierarchy of representations. Early layers learn edges. Middle layers learn shapes. Deep layers learn semantic objects. The key operations are convolution (local feature detection with shared weights), pooling (spatial downsampling), and fully connected layers for classification.

For government use cases, you almost never train a CNN from scratch. Scratch-trained CNNs need millions of labeled examples. You have, at most, tens of thousands of labeled images, and the labeling itself is expensive (annotators with clearances, annotation tools approved for classified data). Transfer learning is the practical path.

The full implementation is in `code-examples/python/02_cnn_satellite_imagery.py`. It fine-tunes a ResNet-50 pre-trained on ImageNet for facility type classification from overhead imagery. Key decisions:

**Separate learning rates for backbone and head.** The backbone (pre-trained ResNet layers) gets a 10x lower learning rate than the classification head. You want the head to learn quickly from your labeled imagery while the backbone adapts more slowly — too fast and it catastrophically forgets the ImageNet representations that are still useful.

**Data augmentation for satellite imagery.** Unlike photographs of everyday objects, satellite imagery has no canonical orientation. A logistics depot looks the same from the north as from the south. Apply `RandomVerticalFlip()` and `RandomHorizontalFlip()`. Apply `ColorJitter()` for variance in sensor calibration and atmospheric conditions. These augmentations double or triple effective dataset size without collecting new labels.

**Label smoothing in the loss function.** Government-labeled imagery frequently has ambiguous cases — a facility that is partially an airfield and partially a command center. Label smoothing (setting `label_smoothing=0.1` in `CrossEntropyLoss`) prevents the model from becoming overconfident on these ambiguous examples.

### Platform Spotlight: Databricks GPU Clusters

Training on a laptop is fine for prototyping. For datasets above 50,000 images, you need a GPU cluster.

On Databricks at FedRAMP High on AWS GovCloud (authorized February 27, 2025), you have access to A10g instances through Mosaic AI's serverless GPU compute — no long-term reservation required. The A10g has 24GB VRAM: enough for training ResNet-50, BERT-base, or running inference with models up to roughly 7 billion parameters in 8-bit quantization.

```python
# Multi-GPU training on Databricks using TorchDistributor
# Runs in a Databricks notebook where `spark` is already defined
from pyspark.ml.torch.distributor import TorchDistributor

def train_on_distributed(n_gpus: int = 4):
    """
    Wrapper for multi-GPU training via Databricks TorchDistributor.
    Handles rank assignment, process spawning, and gradient sync automatically.
    """
    def train_fn():
        import torch
        import os
        import torch.distributed as dist
        from torch.nn.parallel import DistributedDataParallel as DDP
        from torch.utils.data import DistributedSampler

        local_rank = int(os.environ["LOCAL_RANK"])
        device = torch.device(f"cuda:{local_rank}")

        dist.init_process_group(backend="nccl")

        model = build_facility_classifier(freeze_backbone=False)
        model = model.to(device)
        model = DDP(model, device_ids=[local_rank])

        # DistributedSampler ensures each worker gets a non-overlapping data shard
        train_ds = SatelliteImageDataset(train_dir, transform=train_transforms)
        sampler = DistributedSampler(train_ds)
        train_loader = DataLoader(train_ds, batch_size=32, sampler=sampler, num_workers=4)

        # ... training loop ...

        dist.destroy_process_group()

    distributor = TorchDistributor(
        num_processes=n_gpus,
        local_mode=False,
        use_gpu=True,
    )
    distributor.run(train_fn)
```

The practical workflow: write PyTorch training code in a Databricks notebook, configure a GPU ML cluster (Databricks Runtime 15.x ML), run training, and MLflow automatically captures every run — parameters, metrics per epoch, model artifacts. Register the trained model in Unity Catalog's ML Model Registry. Deploy via Mosaic AI Model Serving for real-time inference.

## Transformers and NLP for Government Documents

The federal government runs on documents. Solicitations. Performance Work Statements. Contracting Officer decisions. After-action reports. Inspector General findings. Congressional Budget Justifications. The volume is staggering — DoD alone processes hundreds of thousands of contract actions per year, each with associated narrative text.

Transformer models — built on the self-attention mechanism from the 2017 paper "Attention Is All You Need" — have become the dominant approach for any NLP task. The intuition behind self-attention: when processing a word, instead of looking only at adjacent words (as an RNN would), attention computes a relevance score between that word and every other word in the sequence. This captures long-range dependencies that recurrent networks systematically miss.

BERT (Bidirectional Encoder Representations from Transformers) is the standard pre-trained encoder for classification and extraction tasks. You fine-tune it on your labeled examples rather than training from scratch. Fine-tuning BERT-base on a classification task takes 3-4 epochs on a single GPU — roughly 20-30 minutes for datasets under 100,000 examples.

The full fine-tuning implementation is in `code-examples/python/03_transformer_nlp.py`. The use case: classifying contract description text into procurement categories (IT Services, Professional Services, Construction, Equipment and Supplies, Research and Development, Other). The HuggingFace `Trainer` API handles training loop, gradient accumulation, mixed-precision, and MLflow logging automatically.

### When Transformers Are Wrong for the Job

BERT has a 512-token maximum input length. A standard Federal Acquisition Regulation clause runs 3,000 tokens. A contracting officer's narrative findings in an Inspector General report can run 15,000 tokens. These don't fit.

Your options when documents exceed 512 tokens:
- **Long-context models:** Longformer handles 4,096 tokens; Llama-based models handle 8,192+. Available through HuggingFace or Databricks Mosaic AI Model Serving.
- **Chunking with aggregation:** Split the document into 512-token chunks, classify each chunk, aggregate (majority vote, or average the softmax outputs). Simple and often sufficient.
- **Hierarchical models:** Encode sentence-level representations with BERT, then encode the sentence sequence with a second lightweight transformer. Better performance, more complexity.

For purely keyword-driven extraction tasks — pulling specific fields out of standardized forms, extracting dollar amounts, dates, contract numbers — a rules-based approach or a fine-tuned token classification model (Named Entity Recognition) is faster, more reliable, and easier to explain than any large language model. When an auditor asks how the model classified a contract, "it matched the pattern `\$[\d,]+` in field 12" is a better answer than "the 110M-parameter model assigned 0.87 probability."

Use the simplest model that gets the job done.

## Transfer Learning: The Practical Path for Government AI

Government AI projects have a structural disadvantage relative to commercial ones: labeled data is expensive. Annotators need clearances. Annotation tools need ATOs. The pipeline needs approval. A commercial image recognition team might label a million images in a month. A DoD team doing equivalent work might label 50,000 in a year.

Transfer learning addresses this directly. A model pre-trained on ImageNet has already learned to detect edges, textures, shapes, and objects. Fine-tuning that model on 5,000 labeled images of maintenance anomalies is dramatically more effective than training a CNN from scratch on the same 5,000 images — because the pre-trained weights encode visual knowledge that transfers.

```mermaid
graph TD
    A[Pre-trained Model<br/>ImageNet / CommonCrawl] --> B{Transfer Strategy}
    B -->|Small dataset<br/>under 5K examples| C[Freeze backbone<br/>Train head only]
    B -->|Medium dataset<br/>5K to 50K examples| D[Freeze early layers<br/>Fine-tune deep layers + head]
    B -->|Large dataset<br/>50K+ examples| E[Fine-tune all layers<br/>Low LR on backbone]
    C --> F[Fast training<br/>Low overfitting risk]
    D --> G[Balanced speed<br/>and performance]
    E --> H[Maximum performance<br/>Requires careful regularization]
```

*Figure: Transfer learning strategy by dataset size. Government datasets typically fall in the small-to-medium range — freeze more of the backbone to prevent overfitting on limited labels.*

The government-specific wrinkle is domain gap. ImageNet contains photographs of everyday objects — dogs, chairs, cars. Your application may involve overhead imagery, thermal sensors, or equipment interiors that look nothing like those photographs. When the domain gap is large, training only the classification head underperforms. Test: if the model performs at chance on your validation set after 10 epochs of head-only training, the domain gap is too large. Unfreeze the last two or three backbone blocks and retrain with stronger regularization (higher dropout, lower learning rate, more data augmentation).

## DoD AI Governance: Directive 3000.09

DoD Directive 3000.09 establishes policy for autonomous weapons systems, but its engineering implications reach into any AI system used in operational military contexts. The relevant requirements for a data scientist:

**Human judgment must be exercised in use-of-force decisions.** Your model is decision support, not the decision maker. The interface must visually distinguish model output from human decision.

**The system must minimize unintended engagements.** Your false positive rate on a safety-critical class is a legal and policy constraint, not just a model quality metric. It goes in the requirements document. It gets tested. It gets certified.

**Systems must be designed for failure safety.** What does your model do when confidence is low? It must have a defined behavior — escalation to human review, flag for analyst queue — rather than defaulting silently to the highest-probability class.

The engineering translation of these requirements is in `code-examples/python/04_operational_inference_pipeline.py`. The key structural element is an `OperationalInferencePipeline` wrapper that enforces a confidence threshold (below threshold → `requires_human_review = True`), logs every inference to an audit trail, and never outputs a prediction without capturing the full probability distribution alongside it.

In a Palantir Foundry deployment, the `requires_human_review` flag triggers an AIP Logic Action that routes the item to a human analyst queue in Workshop. The prediction is not acted on until a human reviews it. That is the policy. Your code enforces it.

### Platform Spotlight: Palantir AIP for Operational AI

Palantir Foundry's AIP layer is where trained models become operational in high-consequence government environments. The integration pattern is not "deploy a REST endpoint and call it." Foundry models are registered in the platform and invoked through the Ontology.

When Kevin's YOLO model makes an inference about a vehicle in an imagery frame, that inference is not just a JSON response to an API call. It is a prediction attached to a `DetectedObject` Object Type in the Foundry Ontology, linked to the `ImageryFrame` it came from, linked to the `DroneAsset` that captured it. Every prediction has full data lineage. Every human override is captured as an Action in the Ontology. The entire inference chain is auditable.

This is the architectural reason that high-consequence government AI systems end up on Palantir rather than a pure ML engineering platform. The auditability and operational integration are built into the platform design, not bolted on afterward.

When the Inspector General asked for an audit of all vehicle detections where model confidence was below 90%, the Foundry Ontology answered the query in 3.2 seconds across 847,000 inference records. The same query against a flat file would have taken an hour of pandas work.

## Where This Goes Wrong

**Failure Mode 1: Training on the Wrong Distribution**

**The mistake:** The model trains and validates on historical data, then deploys on current data from a different operational context — different geography, different season, different equipment generation.

**Why smart people make it:** Training and validation metrics look good. The technical review passes. Nobody asks whether the test set matches the deployment distribution.

**How to recognize you're making it:**
- Model accuracy degrades sharply in the first month of production deployment
- The examples that fool the model all share a characteristic absent from the training set
- Prediction confidence scores on live data are systematically lower than on held-out test data
- The training data came from one theater of operations; deployment is in another

**What to do instead:** Treat distribution shift as a first-class engineering problem from day one. Log prediction confidence distributions in production. Alert when mean confidence drops more than 5 percentage points below training baseline. Plan for model retraining every time operational context changes significantly.

---

**Failure Mode 2: Using Deep Learning When It Isn't Warranted**

**The mistake:** A senior analyst asks for "an AI model" to predict equipment failures. You build a 6-layer neural network. It performs worse than logistic regression on the same features. The program office loses confidence in the entire AI effort.

**Why smart people make it:** Deep learning is current, impressive, and "neural network" carries weight in briefings. The pressure to show sophisticated technology is real in government contracts.

**How to recognize you're making it:**
- The dataset has fewer than 100,000 rows
- You have fewer than 10 informative features
- The XGBoost baseline you "quickly put together" matches or beats your tuned network

**What to do instead:** Always establish a strong baseline first. In practice: XGBoost with reasonable hyperparameters. If the neural network doesn't beat the baseline by 3+ percentage points on the primary metric, ship the XGBoost. Explainability is easier. Auditability is simpler. The contract sponsor is happier.

---

**Failure Mode 3: Ignoring the Confidence Score**

**The mistake:** Deploying a model that outputs a class label without exposing the confidence distribution to the end user or downstream system.

**Why smart people make it:** The API returns a label. The application displays a label. Clean and simple. The probability distribution feels like implementation detail.

**How to recognize you're making it:**
- Users treat model outputs as facts rather than probabilistic predictions
- There is no escalation path for low-confidence predictions in the production system
- The audit trail shows predictions but not confidence scores
- No one has defined what the model should do when it is uncertain

**What to do instead:** Always expose confidence scores. Define a threshold below which predictions route to human review. Document that threshold in the system's AI ethics review and update it when model behavior changes.

## Practical Takeaway: Operational Model Evaluation

Standard accuracy is not sufficient for evaluating operational AI. This is the evaluation framework that should accompany every model review:

| Metric | What it measures | Threshold guidance |
|---|---|---|
| Overall accuracy | Gross correctness | Depends on baseline (random, previous model) |
| Macro F1 | Performance across all classes, equal weight | Higher is better; watch for class imbalance masking |
| FPR on safety-critical class | False positives on the most dangerous error mode | Define contractually; typically < 1% |
| Expected Calibration Error (ECE) | Does 80% confidence actually mean 80% accuracy? | Below 0.05 is well-calibrated |
| Confidence at threshold | What % of predictions require human review? | Must be operationally sustainable for the analyst team |
| Latency P99 | Worst-case inference time | Define per use case (400ms for real-time; seconds acceptable for batch) |

Log all of these to MLflow on every evaluation run. Include `fpr_safety_critical_class` in every status brief alongside accuracy. The program office asking "how accurate is the model?" needs to hear the full answer — including the error modes that matter most.

See `code-examples/python/04_operational_inference_pipeline.py` for the complete evaluation implementation including confidence calibration curves and the reliability diagram.

## Platform Comparison

| Capability | Advana (via Databricks) | Navy Jupiter (via Databricks) | Palantir Foundry / AIP | Qlik | Databricks (standalone) |
|---|---|---|---|---|---|
| GPU training | A10g via GovCloud IL5 | A10g via GovCloud IL5 | External training; deploy via AIP | Not applicable | A10g GA, H100 preview |
| Pre-trained model access | HuggingFace via Databricks | HuggingFace via Databricks | AIP k-LLM (model-agnostic) | N/A | Unity Catalog Model Registry |
| Multi-GPU training | TorchDistributor | TorchDistributor | Code Repository (custom) | N/A | TorchDistributor |
| Experiment tracking | MLflow 3.0 | MLflow 3.0 | Foundry Model Registry | N/A | MLflow 3.0 |
| Inference serving | Mosaic AI Model Serving | Mosaic AI Model Serving | AIP Logic + Workshop | N/A | Mosaic AI Model Serving (250K+ QPS) |
| Prediction audit trail | MLflow inference tables | MLflow inference tables | Ontology Actions (full lineage) | N/A | MLflow inference tables |
| Human-in-the-loop routing | Custom (via Workflows) | Custom (via Workflows) | Native (AIP + Workshop queues) | N/A | Custom |
| DoD IL5 GPU | Yes (AWS GovCloud) | Yes (AWS GovCloud) | Yes (Azure Gov IL5) | N/A | Yes (AWS GovCloud) |

Databricks is the right platform for training and experimentation. Palantir Foundry is the right platform for operational deployment where lineage, auditability, and human-in-the-loop workflows are hard requirements. These two platforms have a formal partnership as of 2025: train on Databricks, register in Unity Catalog, export to Foundry via the Palantir-Databricks integration.

## Putting It Together

Kevin's final pipeline used four distinct phases:

**Training:** Databricks on AWS GovCloud (FedRAMP High, IL5), PyTorch 2.0, A10g instances. YOLOv8 pre-trained on COCO, fine-tuned on the classified imagery dataset. 18 training runs over 12 days. MLflow logged every run: architecture config, learning rate schedule, per-class average precision, and the false positive rate on civilian vehicle frames. The 0.3% FPR threshold was not hit until run 14.

**Evaluation:** The full evaluation suite ran against a held-out test set drawn from operational imagery from the deployment theater — not the training theater. This is the detail that almost everyone skips and that catches most distribution shift problems.

**Registration:** The trained model artifact registered in Unity Catalog's ML Model Registry with version tags, training data lineage, and the evaluation report attached as a tracked artifact. The model card documented: training data characteristics, known failure modes, confidence threshold, and the required human review rate at that threshold.

**Deployment:** Palantir Foundry on Azure Government IL5. The model was exported and registered in Foundry's model registry. An AIP Logic function wrapped model inference, applied the confidence threshold, and routed low-confidence predictions to the human analyst queue in Workshop. Every inference produced a `VehicleDetection` object in the Foundry Ontology — confidence score, bounding box, timestamp, source drone asset, and analyst determination where applicable.

The audit trail answered every Inspector General query. The FPR on civilian vehicles was 0.27% against live data — within spec. The program office certified the system for limited operational use.

That is what "production AI in a government context" actually means.

## Exercises

See the [exercises](./exercises/exercises.md) directory for hands-on practice problems.

---

**The one thing to remember:** Deep learning is the right tool for specific problems — large labeled datasets, unstructured inputs (images, text, audio), high-cardinality categorical embeddings. For everything else, simpler models win on performance, maintainability, and the ability to explain your decision to a contracting officer, an Inspector General, or a congressional oversight committee.

**What to do Monday morning:** Take the AI problem your team is currently working on. Answer two questions explicitly, in writing, before writing any model code: Does the dataset have enough labeled examples (rough guide: 50,000+ rows for tabular neural nets, 10,000+ images for fine-tuned CNNs, 5,000+ text examples for BERT fine-tuning)? Have you run the simplest reasonable baseline (XGBoost for tabular, frequency-weighted TF-IDF + logistic regression for text) and measured its performance? If the neural network doesn't beat that baseline by a defensible margin, the baseline is your deliverable.

**What comes next:** Chapter 09 covers MLOps — the engineering discipline of keeping trained models working in production after you've handed them off. Everything in this chapter ended with a registered model artifact. Chapter 09 is the story of what happens next: versioning, drift detection, retraining triggers, CI/CD pipelines for model updates, and the monitoring patterns that tell you when Kevin's vehicle detection model needs to be retrained because the operational context has shifted.
