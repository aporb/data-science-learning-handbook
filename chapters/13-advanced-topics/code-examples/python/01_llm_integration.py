"""
Chapter 13: LLM Integration on Federal Platforms
=================================================
Demonstrates authorized LLM usage patterns for government environments,
including model-agnostic client setup, LoRA/QLoRA fine-tuning on Databricks,
and prompt engineering for federal acquisition tasks.

Authorization context:
- Azure OpenAI (GPT-4) via Azure Government endpoints (IL4/IL5)
- Anthropic Claude via Palantir FedStart (IL5)
- Self-hosted Llama 3 / Mistral via air-gapped deployment (IL5/IL6)

All patterns in this file use environment variables for credentials.
Never hardcode API keys or endpoints in code committed to version control.
"""

import os
import json
import logging
from typing import Optional
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Section 1: Model-Agnostic LLM Client
# ---------------------------------------------------------------------------
# The federal environment requires switching models based on authorization
# level. This wrapper abstracts the provider-specific SDK calls so your
# application logic does not change when the approved model changes.

@dataclass
class LLMResponse:
    """Standardized response object across providers."""
    content: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    finish_reason: str


class FederalLLMClient:
    """
    Model-agnostic LLM client for federal environments.
    Supports Azure OpenAI (Government), Anthropic (via FedStart), and
    self-hosted models via OpenAI-compatible API.

    Usage:
        # For IL4/IL5 workloads on Azure Government
        client = FederalLLMClient(provider="azure_openai")

        # For IL5 via Palantir FedStart
        client = FederalLLMClient(provider="anthropic_fedstart")

        # For air-gapped self-hosted Llama 3
        client = FederalLLMClient(provider="local_openai_compat")

        response = client.complete(
            system_prompt="You are a federal acquisition expert.",
            user_message="Summarize the key risks in this contract."
        )
    """

    SUPPORTED_PROVIDERS = ["azure_openai", "anthropic_fedstart", "local_openai_compat"]

    def __init__(self, provider: str, timeout: int = 60):
        if provider not in self.SUPPORTED_PROVIDERS:
            raise ValueError(f"Provider '{provider}' not supported. "
                             f"Choose from: {self.SUPPORTED_PROVIDERS}")
        self.provider = provider
        self.timeout = timeout
        self._client = self._init_client()

    def _init_client(self):
        """Initialize the appropriate SDK client based on provider."""
        if self.provider == "azure_openai":
            # Requires: AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT
            # Use Azure Government endpoint for IL4/IL5, not commercial
            # Commercial: https://api.openai.com
            # Gov: https://your-resource.openai.azure.us (note: .azure.us, not .azure.com)
            from openai import AzureOpenAI
            endpoint = os.environ["AZURE_OPENAI_ENDPOINT"]
            if ".azure.com" in endpoint and not os.environ.get("ALLOW_COMMERCIAL_ENDPOINT"):
                logging.warning(
                    "Using commercial Azure endpoint. For IL4/IL5 data, "
                    "use Azure Government endpoint (.azure.us domain). "
                    "Set ALLOW_COMMERCIAL_ENDPOINT=1 to suppress this warning."
                )
            return AzureOpenAI(
                api_key=os.environ["AZURE_OPENAI_API_KEY"],
                azure_endpoint=endpoint,
                api_version="2024-08-01-preview"
            )

        elif self.provider == "anthropic_fedstart":
            # Claude via Palantir FedStart at IL5 uses a proxied endpoint.
            # The API contract matches Anthropic's standard SDK but routes
            # through Palantir's FedRAMP High / IL5 accredited infrastructure.
            import anthropic
            return anthropic.Anthropic(
                api_key=os.environ["ANTHROPIC_FEDSTART_API_KEY"],
                base_url=os.environ.get(
                    "ANTHROPIC_FEDSTART_ENDPOINT",
                    "https://api.anthropic.com"  # override with FedStart endpoint in production
                )
            )

        elif self.provider == "local_openai_compat":
            # For self-hosted Llama 3 / Mistral running vLLM or Ollama
            # in an air-gapped environment. vLLM exposes an OpenAI-compatible API.
            from openai import OpenAI
            return OpenAI(
                api_key=os.environ.get("LOCAL_MODEL_API_KEY", "not-used"),
                base_url=os.environ.get("LOCAL_MODEL_ENDPOINT", "http://localhost:8000/v1")
            )

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int = 2048,
        temperature: float = 0.1,  # Low temperature for government tasks requiring consistency
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        """
        Send a completion request. Returns a standardized LLMResponse.

        temperature=0.1 is deliberate: government tasks (contract analysis,
        policy summarization) need deterministic, reproducible outputs.
        Use temperature=0.7+ only for creative drafting tasks.
        """
        if self.provider == "azure_openai":
            return self._complete_openai(
                system_prompt, user_message, max_tokens, temperature, response_format
            )
        elif self.provider == "anthropic_fedstart":
            return self._complete_anthropic(
                system_prompt, user_message, max_tokens, temperature
            )
        elif self.provider == "local_openai_compat":
            return self._complete_openai(
                system_prompt, user_message, max_tokens, temperature, response_format
            )

    def _complete_openai(self, system_prompt, user_message, max_tokens,
                          temperature, response_format):
        model = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        kwargs = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        if response_format:
            kwargs["response_format"] = response_format

        response = self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        return LLMResponse(
            content=choice.message.content,
            model=model,
            provider=self.provider,
            input_tokens=response.usage.prompt_tokens,
            output_tokens=response.usage.completion_tokens,
            finish_reason=choice.finish_reason
        )

    def _complete_anthropic(self, system_prompt, user_message, max_tokens, temperature):
        model = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        response = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}]
        )
        return LLMResponse(
            content=response.content[0].text,
            model=model,
            provider=self.provider,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            finish_reason=response.stop_reason
        )


# ---------------------------------------------------------------------------
# Section 2: Contract Analysis Prompt Engineering
# ---------------------------------------------------------------------------
# Structured prompts for federal acquisition tasks.
# The key pattern: role + document type + explicit output schema + constraints.

CONTRACT_ANALYSIS_SYSTEM_PROMPT = """You are a federal acquisition expert specializing in DoD contracts
under FAR/DFARS. Your role is to analyze contract documents and extract structured information
with high precision. You must:
- Only state facts present in the provided contract text
- If information is absent from the document, state "Not specified in document"
- Never infer prices or dates not explicitly stated
- Flag any unusual or potentially high-risk clauses for contracting officer review"""

def extract_contract_structure(contract_text: str, client: FederalLLMClient) -> dict:
    """
    Extract key contract elements from a DoD contract document.
    Returns structured JSON suitable for downstream processing.

    Args:
        contract_text: Full text of the contract document
        client: Authorized LLM client for this classification level

    Returns:
        dict with keys: clins, performance_period, max_value, risk_clauses,
                        deliverables, liquidated_damages
    """
    # Truncate to fit context window if needed (most contracts are 50-200 pages)
    # For production, use RAG to retrieve relevant sections instead of full text
    max_context_chars = 80_000  # approximately 20K tokens
    if len(contract_text) > max_context_chars:
        logging.warning(
            f"Contract text ({len(contract_text):,} chars) exceeds context limit. "
            f"Truncating to {max_context_chars:,} chars. "
            "For full contracts, use the RAG pipeline in 02_rag_pipeline.py."
        )
        contract_text = contract_text[:max_context_chars]

    user_message = f"""Analyze the following federal contract and extract the required information.
Output ONLY valid JSON matching the schema below. Do not include any explanation outside the JSON.

Required JSON schema:
{{
  "contract_number": "string or null",
  "contract_type": "FFP|CPFF|T&M|IDIQ|BPA|other",
  "max_ordering_value": "dollar amount as string or null",
  "performance_period": {{
    "start": "date string or null",
    "end": "date string or null",
    "option_periods": "description or null"
  }},
  "clins": [
    {{
      "clin_number": "string",
      "description": "string",
      "quantity": "string or null",
      "unit": "string or null",
      "unit_price": "string or null",
      "total_value": "string or null"
    }}
  ],
  "key_deliverables": [
    {{
      "description": "string",
      "due_date": "string or null",
      "accepting_official": "string or null"
    }}
  ],
  "liquidated_damages": "description or null",
  "risk_clauses": ["list of clause numbers and titles that impose significant contractor risk"],
  "naics_code": "string or null",
  "place_of_performance": "string or null"
}}

CONTRACT TEXT:
{contract_text}"""

    response = client.complete(
        system_prompt=CONTRACT_ANALYSIS_SYSTEM_PROMPT,
        user_message=user_message,
        max_tokens=4096,
        temperature=0.0,  # Zero temperature for structured extraction
        response_format={"type": "json_object"}
    )

    try:
        result = json.loads(response.content)
        result["_metadata"] = {
            "model": response.model,
            "provider": response.provider,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens
        }
        return result
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse LLM JSON output: {e}")
        logging.debug(f"Raw LLM output: {response.content[:500]}")
        raise ValueError(f"LLM did not return valid JSON: {e}") from e


# ---------------------------------------------------------------------------
# Section 3: LoRA/QLoRA Fine-Tuning on Databricks
# ---------------------------------------------------------------------------
# Use this when a general-purpose LLM needs behavioral adaptation for
# domain-specific government tasks. Not for teaching the model data —
# that's what RAG handles. Fine-tuning changes HOW the model reasons.

def configure_lora_for_government_nlp(
    model_name: str = "meta-llama/Llama-3.1-8B-Instruct",
    task: str = "contract_classification",
    use_qlora: bool = True
) -> dict:
    """
    Configure LoRA/QLoRA parameters for a government NLP fine-tuning task.
    Call this before starting a Databricks GPU training run.

    Args:
        model_name: HuggingFace model ID (must be approved for import)
        task: One of contract_classification, policy_summarization, foia_triage
        use_qlora: If True, use 4-bit quantization (reduces memory ~4x)

    Returns:
        Configuration dict ready to pass to the training framework
    """
    # Task-specific LoRA rank recommendations:
    # r=8:  Light style/format adaptation (output structure changes)
    # r=16: Domain adaptation (government terminology, clause numbering)
    # r=32: Significant behavioral change (new reasoning pattern)
    # r=64: Major task shift (rarely needed — consider more data first)
    task_configs = {
        "contract_classification": {
            "r": 16,
            "target_modules": ["q_proj", "v_proj", "k_proj", "o_proj"],
            "lora_alpha": 32,
            "lora_dropout": 0.05,
            "epochs": 3,
            "learning_rate": 2e-4,
            "notes": "Classifies contracts by type (FFP/CPFF/T&M/IDIQ) and risk level"
        },
        "policy_summarization": {
            "r": 8,
            "target_modules": ["q_proj", "v_proj"],
            "lora_alpha": 16,
            "lora_dropout": 0.05,
            "epochs": 2,
            "learning_rate": 1e-4,
            "notes": "Generates structured summaries of DoD policy memoranda"
        },
        "foia_triage": {
            "r": 32,
            "target_modules": ["q_proj", "v_proj", "k_proj", "o_proj", "gate_proj"],
            "lora_alpha": 64,
            "lora_dropout": 0.1,
            "epochs": 5,
            "learning_rate": 2e-4,
            "notes": "Classifies document segments by FOIA exemption category"
        }
    }

    if task not in task_configs:
        raise ValueError(f"Unknown task '{task}'. Choose from: {list(task_configs.keys())}")

    task_cfg = task_configs[task]

    config = {
        "model_name": model_name,
        "lora": {
            "r": task_cfg["r"],
            "lora_alpha": task_cfg["lora_alpha"],
            "target_modules": task_cfg["target_modules"],
            "lora_dropout": task_cfg["lora_dropout"],
            "bias": "none",
            "task_type": "CAUSAL_LM"
        },
        "training": {
            "num_train_epochs": task_cfg["epochs"],
            "per_device_train_batch_size": 4,
            "gradient_accumulation_steps": 4,  # Effective batch size = 16
            "learning_rate": task_cfg["learning_rate"],
            "warmup_ratio": 0.03,
            "lr_scheduler_type": "cosine",
            "evaluation_strategy": "steps",
            "eval_steps": 100,
            "save_steps": 200,
            "fp16": not use_qlora,  # FP16 for LoRA; BF16 handled separately for QLoRA
            "bf16": False,
            "logging_steps": 10,
            "report_to": "mlflow"  # MLflow tracking in Databricks
        },
        "qlora": {
            "enabled": use_qlora,
            "load_in_4bit": use_qlora,
            "bnb_4bit_quant_type": "nf4",       # NormalFloat4 — best accuracy for LLMs
            "bnb_4bit_use_double_quant": True,   # Double quantization saves ~0.5 bits/param
            "bnb_4bit_compute_dtype": "bfloat16"
        },
        "notes": task_cfg["notes"],
        "estimated_gpu_memory_gb": _estimate_gpu_memory(
            model_name, use_qlora, task_cfg["r"]
        )
    }
    return config


def _estimate_gpu_memory(model_name: str, use_qlora: bool, lora_r: int) -> str:
    """Rough GPU memory estimate for training planning."""
    # Parameter counts for common models
    param_billions = {
        "meta-llama/Llama-3.1-8B-Instruct": 8,
        "meta-llama/Llama-3.1-13B-Instruct": 13,
        "meta-llama/Llama-3.1-70B-Instruct": 70,
        "mistralai/Mistral-7B-Instruct-v0.3": 7,
    }.get(model_name, 8)  # Default to 8B estimate

    if use_qlora:
        # 4-bit quantization: ~0.5 bytes/param for weights
        base_gb = param_billions * 0.5
    else:
        # BF16: 2 bytes/param for weights
        base_gb = param_billions * 2

    # LoRA adapters are tiny: rank * 2 * target_layers * hidden_dim / 1e9
    # Approximately 0.1-0.5 GB for typical configs
    adapter_gb = 0.3

    # Training overhead: gradients + optimizer states for adapters only
    training_overhead_gb = adapter_gb * 6  # Adam optimizer ~6x adapter size

    total_gb = base_gb + adapter_gb + training_overhead_gb
    return f"~{total_gb:.0f} GB (estimate — actual varies by batch size and sequence length)"


def run_databricks_fine_tuning(
    config: dict,
    train_dataset_path: str,
    eval_dataset_path: str,
    output_model_name: str,
    mlflow_experiment: str
) -> str:
    """
    Launch a fine-tuning run on a Databricks GPU cluster.
    Registers the resulting model in MLflow and Unity Catalog.

    This function is designed to run inside a Databricks notebook or job.
    Requires a GPU cluster (g5.4xlarge minimum for 8B QLoRA; g5.12xlarge for 13B).

    Args:
        config: Output from configure_lora_for_government_nlp()
        train_dataset_path: Unity Catalog path (catalog.schema.table) or file path
        eval_dataset_path: Unity Catalog path or file path for evaluation data
        output_model_name: Name to register in MLflow Model Registry
        mlflow_experiment: MLflow experiment name for tracking

    Returns:
        MLflow run ID for the training run
    """
    try:
        import mlflow
        import mlflow.transformers
        import torch
        from datasets import load_dataset
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            TrainingArguments,
            BitsAndBytesConfig
        )
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer
    except ImportError as e:
        raise ImportError(
            f"Required package not found: {e}. "
            "Install with: pip install transformers peft trl bitsandbytes mlflow datasets"
        ) from e

    mlflow.set_experiment(mlflow_experiment)

    with mlflow.start_run() as run:
        mlflow.log_params({
            "model_name": config["model_name"],
            "lora_r": config["lora"]["r"],
            "lora_alpha": config["lora"]["lora_alpha"],
            "use_qlora": config["qlora"]["enabled"],
            "epochs": config["training"]["num_train_epochs"],
            "learning_rate": config["training"]["learning_rate"]
        })

        # Load base model — with quantization if QLoRA
        bnb_config = None
        if config["qlora"]["enabled"]:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type=config["qlora"]["bnb_4bit_quant_type"],
                bnb_4bit_use_double_quant=config["qlora"]["bnb_4bit_use_double_quant"],
                bnb_4bit_compute_dtype=torch.bfloat16
            )

        print(f"Loading base model: {config['model_name']}")
        model = AutoModelForCausalLM.from_pretrained(
            config["model_name"],
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=False  # Never True for government environments
        )
        tokenizer = AutoTokenizer.from_pretrained(config["model_name"])
        tokenizer.pad_token = tokenizer.eos_token

        # Prepare model for QLoRA training
        if config["qlora"]["enabled"]:
            model = prepare_model_for_kbit_training(model)

        # Apply LoRA adapters
        lora_config = LoraConfig(
            r=config["lora"]["r"],
            lora_alpha=config["lora"]["lora_alpha"],
            target_modules=config["lora"]["target_modules"],
            lora_dropout=config["lora"]["lora_dropout"],
            bias=config["lora"]["bias"],
            task_type=config["lora"]["task_type"]
        )
        model = get_peft_model(model, lora_config)

        trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
        total_params = sum(p.numel() for p in model.parameters())
        print(f"Trainable parameters: {trainable_params:,} / {total_params:,} "
              f"({100 * trainable_params / total_params:.2f}%)")
        mlflow.log_metric("trainable_param_pct", 100 * trainable_params / total_params)

        # Load datasets (from Unity Catalog or file)
        train_data = load_dataset("json", data_files=train_dataset_path, split="train")
        eval_data = load_dataset("json", data_files=eval_dataset_path, split="train")

        # Training arguments
        training_args = TrainingArguments(
            output_dir=f"/tmp/{output_model_name}",
            **{k: v for k, v in config["training"].items()
               if k != "report_to"},  # handle report_to separately
            report_to="mlflow"
        )

        trainer = SFTTrainer(
            model=model,
            tokenizer=tokenizer,
            train_dataset=train_data,
            eval_dataset=eval_data,
            dataset_text_field="text",
            max_seq_length=2048,
            args=training_args,
        )

        print("Starting training run...")
        trainer.train()
        trainer.evaluate()

        # Log the fine-tuned model to MLflow
        mlflow.transformers.log_model(
            transformers_model={"model": model, "tokenizer": tokenizer},
            artifact_path="model",
            registered_model_name=output_model_name
        )

        print(f"Training complete. MLflow run ID: {run.info.run_id}")
        print(f"Model registered as: {output_model_name}")
        return run.info.run_id


# ---------------------------------------------------------------------------
# Section 4: Policy Summarization Example
# ---------------------------------------------------------------------------

POLICY_SUMMARY_SYSTEM_PROMPT = """You are a DoD policy analyst. When given a policy memorandum or
directive, produce a structured summary for decision-makers.

Format requirements:
- Lead with the document's key requirement or change in plain English
- Do not hedge or editorialize — state what the policy says
- Flag any compliance deadline
- Identify which organizations are affected
- Note any exceptions or waivers available"""


def summarize_policy_document(policy_text: str, client: FederalLLMClient) -> dict:
    """
    Produce a structured summary of a DoD policy document.
    Returns a dict with summary, requirements, deadlines, and affected_orgs.
    """
    user_message = f"""Summarize the following DoD policy document.
Output valid JSON matching this schema:
{{
  "one_sentence_summary": "string — the single most important thing this policy does",
  "effective_date": "string or null",
  "compliance_deadline": "string or null",
  "affected_organizations": ["list of org names or types"],
  "key_requirements": ["list of specific requirements — use action verbs"],
  "exceptions_waivers": "string or null",
  "supersedes": ["list of documents this replaces, or empty list"],
  "poc": "point of contact if listed, or null"
}}

POLICY TEXT:
{policy_text[:60_000]}"""

    response = client.complete(
        system_prompt=POLICY_SUMMARY_SYSTEM_PROMPT,
        user_message=user_message,
        max_tokens=2048,
        temperature=0.0,
        response_format={"type": "json_object"}
    )

    result = json.loads(response.content)
    result["_token_usage"] = {
        "input": response.input_tokens,
        "output": response.output_tokens
    }
    return result


# ---------------------------------------------------------------------------
# Demo / smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Quick smoke test. Set environment variables before running:

    For Azure OpenAI (Government):
        export AZURE_OPENAI_API_KEY="your-key"
        export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.us"
        export AZURE_OPENAI_DEPLOYMENT="gpt-4o"

    For local model (vLLM / Ollama):
        export LOCAL_MODEL_ENDPOINT="http://localhost:11434/v1"
        python 01_llm_integration.py
    """
    import sys

    print("=== Chapter 13: LLM Integration Demo ===\n")

    # Determine which provider to use based on available env vars
    if os.environ.get("AZURE_OPENAI_API_KEY"):
        provider = "azure_openai"
    elif os.environ.get("ANTHROPIC_FEDSTART_API_KEY"):
        provider = "anthropic_fedstart"
    elif os.environ.get("LOCAL_MODEL_ENDPOINT"):
        provider = "local_openai_compat"
    else:
        print("No LLM credentials found in environment.")
        print("Set AZURE_OPENAI_API_KEY, ANTHROPIC_FEDSTART_API_KEY, or LOCAL_MODEL_ENDPOINT.")
        print("\nShowing LoRA configuration demo instead:\n")

        # Show the fine-tuning config without needing credentials
        config = configure_lora_for_government_nlp(
            model_name="meta-llama/Llama-3.1-8B-Instruct",
            task="contract_classification",
            use_qlora=True
        )
        print("QLoRA Configuration for Contract Classification:")
        print(json.dumps(config, indent=2))
        sys.exit(0)

    print(f"Using provider: {provider}")
    client = FederalLLMClient(provider=provider)

    # Test with a minimal synthetic contract excerpt
    sample_contract = """
    CONTRACT NUMBER: W91QV2-25-C-0042
    CONTRACT TYPE: Firm Fixed Price (FFP)
    CONTRACTOR: Apex Defense Solutions LLC
    MAXIMUM CONTRACT VALUE: $4,250,000

    PERFORMANCE PERIOD: 1 October 2025 through 30 September 2026
    OPTION PERIOD I: 1 October 2026 through 30 September 2027 ($4,500,000)

    CLIN 0001: Program Management Support, 12 months, $850,000
    CLIN 0002: Software Development Services, 2,000 hours, $175/hr, $350,000
    CLIN 0003: Hardware Procurement (NTE), $3,050,000

    DELIVERABLES:
    - Monthly Status Report due the 5th of each month
    - Final Technical Report due 60 days prior to contract end

    LIQUIDATED DAMAGES: $500 per calendar day for late delivery of Final Technical Report.

    FAR CLAUSE 52.249-8: Default (Fixed-Price Supply and Service)
    FAR CLAUSE 52.232-33: Payment by Electronic Funds Transfer
    DFARS 252.204-7012: Safeguarding Covered Defense Information
    """

    print("\n--- Contract Analysis Test ---")
    result = extract_contract_structure(sample_contract, client)
    print(json.dumps({k: v for k, v in result.items() if not k.startswith("_")}, indent=2))
    print(f"\nToken usage: {result['_metadata']['input_tokens']} in / "
          f"{result['_metadata']['output_tokens']} out")
