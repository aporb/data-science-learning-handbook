"""
Chapter 13: Palantir AIP Logic and Agent Studio — Python Companion
==================================================================
This file demonstrates the concepts behind Palantir AIP's architecture
using Python equivalents. Palantir AIP Logic itself is a no-code/TypeScript
environment inside Foundry — these Python patterns show the equivalent logic
you would build in AIP Logic or as Foundry Functions.

Covers:
1. Ontology-grounded data retrieval (what AIP Logic's Data Tools do)
2. Agent orchestration with tool-calling (what Agent Studio does)
3. AIP Machinery-style human-in-the-loop workflows
4. The palantir_models library for publishing models to Foundry

Note: The Palantir OSDK (Ontology SDK) Python client can be installed from
your Foundry enrollment's developer console. The patterns here use the OSDK
interfaces as documented in palantir.com/docs/foundry.
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Section 1: Ontology-Grounded Data Access
# ---------------------------------------------------------------------------
# In AIP Logic, Data Tools provide the LLM with read-only access to Ontology
# objects. This Python class mirrors that pattern for local development and
# for teams building against the OSDK.

@dataclass
class OntologyObject:
    """Represents a Palantir Ontology object (generic form)."""
    object_type: str
    object_rid: str   # Resource Identifier — unique across the Foundry enrollment
    properties: dict[str, Any]
    links: dict[str, list[str]] = field(default_factory=dict)  # link_type -> [target_rids]


class OntologyDataTool:
    """
    Python equivalent of an AIP Logic Data Tool.
    Provides read-only, structured access to Ontology objects for LLM use.

    In production Foundry:
    - This is configured in AIP Logic's tool builder (no code required)
    - The tool definition specifies which Object Types are accessible
    - The LLM calls the tool with a natural language request that gets
      translated into an Ontology query

    In this Python version:
    - We simulate the Ontology with an in-memory store
    - The interface mirrors what you would build with the OSDK

    OSDK installation (from your Foundry enrollment):
        pip install foundry-sdk-[your-enrollment-id]
    """

    def __init__(self, ontology_client=None):
        """
        Args:
            ontology_client: OSDK client for a real Foundry enrollment.
                             If None, uses the mock in-memory ontology below.
        """
        self._client = ontology_client
        self._mock_objects: dict[str, list[OntologyObject]] = {}

        # Populate mock objects for demo purposes
        self._populate_mock_data()

    def _populate_mock_data(self):
        """Create realistic mock Ontology data for a defense acquisition program."""
        self._mock_objects["Vendor"] = [
            OntologyObject(
                object_type="Vendor",
                object_rid="ri.vendor.0001",
                properties={
                    "name": "Apex Defense Solutions LLC",
                    "cage_code": "7K8Q2",
                    "naics_primary": "541511",
                    "cpars_rating_average": "Satisfactory",
                    "active_contracts": 3,
                    "total_obligation_ytd": 4_250_000,
                    "small_business": True,
                    "debarred": False
                }
            ),
            OntologyObject(
                object_type="Vendor",
                object_rid="ri.vendor.0002",
                properties={
                    "name": "Meridian Systems Group Inc.",
                    "cage_code": "3R5T7",
                    "naics_primary": "541512",
                    "cpars_rating_average": "Exceptional",
                    "active_contracts": 7,
                    "total_obligation_ytd": 18_700_000,
                    "small_business": False,
                    "debarred": False
                }
            ),
            OntologyObject(
                object_type="Vendor",
                object_rid="ri.vendor.0003",
                properties={
                    "name": "Cascade Federal Technologies",
                    "cage_code": "9H2M4",
                    "naics_primary": "541519",
                    "cpars_rating_average": "Marginal",
                    "active_contracts": 1,
                    "total_obligation_ytd": 890_000,
                    "small_business": True,
                    "debarred": False,
                    "cure_notices": 2
                }
            )
        ]

        self._mock_objects["Contract"] = [
            OntologyObject(
                object_type="Contract",
                object_rid="ri.contract.0001",
                properties={
                    "contract_number": "W91QV2-25-C-0042",
                    "contract_type": "FFP",
                    "vendor_rid": "ri.vendor.0001",
                    "max_value": 4_250_000,
                    "obligated_amount": 2_100_000,
                    "start_date": "2025-10-01",
                    "end_date": "2026-09-30",
                    "status": "Active",
                    "program": "LOGISTICS_MODERNIZATION"
                }
            ),
            OntologyObject(
                object_type="Contract",
                object_rid="ri.contract.0002",
                properties={
                    "contract_number": "N00024-25-D-0089",
                    "contract_type": "IDIQ",
                    "vendor_rid": "ri.vendor.0002",
                    "max_value": 50_000_000,
                    "obligated_amount": 12_500_000,
                    "start_date": "2025-04-15",
                    "end_date": "2030-04-14",
                    "status": "Active",
                    "program": "SHIPBUILDING_ANALYTICS"
                }
            )
        ]

    def get_objects(
        self,
        object_type: str,
        filters: Optional[dict] = None,
        limit: int = 50
    ) -> list[OntologyObject]:
        """
        Retrieve Ontology objects of a given type with optional property filters.

        In AIP Logic, this is a Data Tool configured to query a specific
        Object Type with user-defined filter parameters.

        Args:
            object_type: The Ontology Object Type name (e.g., "Vendor", "Contract")
            filters: Dict of {property_name: value} for equality filters
            limit: Maximum objects to return

        Returns:
            List of matching OntologyObjects
        """
        if self._client:
            # Production OSDK call
            # from foundry_sdk import FoundryClient
            # objects = self._client.ontology.objects(object_type).where(filters).limit(limit)
            raise NotImplementedError("OSDK client integration — see your enrollment's SDK docs")

        # Mock implementation
        candidates = self._mock_objects.get(object_type, [])
        if filters:
            result = []
            for obj in candidates:
                if all(obj.properties.get(k) == v for k, v in filters.items()):
                    result.append(obj)
            return result[:limit]
        return candidates[:limit]

    def get_object_by_rid(self, rid: str) -> Optional[OntologyObject]:
        """Retrieve a specific object by its Resource Identifier."""
        for objects in self._mock_objects.values():
            for obj in objects:
                if obj.object_rid == rid:
                    return obj
        return None

    def to_llm_context(self, objects: list[OntologyObject]) -> str:
        """
        Format Ontology objects as structured text for LLM context injection.
        This is what AIP Logic does automatically when a Data Tool returns results.
        """
        if not objects:
            return "No objects found matching the query criteria."

        lines = []
        for obj in objects:
            lines.append(f"\n[{obj.object_type}: {obj.object_rid}]")
            for key, value in obj.properties.items():
                lines.append(f"  {key}: {value}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 2: AIP Agent Orchestration Pattern
# ---------------------------------------------------------------------------
# AIP Agent Studio builds agents with persistent context, multiple tools,
# and multi-turn conversation. This Python pattern shows the equivalent
# tool-calling loop you would configure in Agent Studio.

class AgentTool:
    """A callable tool that an agent can use to interact with the Ontology."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict,
        handler: Callable
    ):
        self.name = name
        self.description = description
        self.parameters = parameters  # JSON Schema for the tool's parameters
        self.handler = handler

    def to_api_spec(self) -> dict:
        """Convert to OpenAI/Anthropic tool calling API format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": self.parameters,
                    "required": list(self.parameters.keys())
                }
            }
        }

    def execute(self, **kwargs) -> str:
        """Execute the tool and return a string result for the LLM."""
        try:
            result = self.handler(**kwargs)
            if isinstance(result, (dict, list)):
                return json.dumps(result, indent=2, default=str)
            return str(result)
        except Exception as e:
            logger.error(f"Tool '{self.name}' execution failed: {e}")
            return f"Tool execution error: {e}"


class AIPAgentSimulator:
    """
    Python simulation of a Palantir AIP Agent Studio agent.
    Demonstrates the tool-calling loop that Agent Studio manages natively.

    In production AIP Agent Studio:
    - You configure tools from a drag-and-drop interface
    - The agent maintains conversation history automatically
    - Human-in-the-loop steps can be inserted at any point
    - The agent can be deployed into Workshop applications

    This simulator shows the underlying mechanics for learning purposes.
    """

    def __init__(self, llm_client, ontology_tool: OntologyDataTool, agent_name: str):
        """
        Args:
            llm_client: FederalLLMClient from 01_llm_integration.py
            ontology_tool: OntologyDataTool for data access
            agent_name: Name for this agent instance
        """
        self.llm = llm_client
        self.ontology = ontology_tool
        self.agent_name = agent_name
        self.conversation_history: list[dict] = []
        self.tools = self._register_tools()
        self.max_tool_iterations = 5  # Prevent infinite loops

    def _register_tools(self) -> list[AgentTool]:
        """Register the tools this agent can call."""
        return [
            AgentTool(
                name="get_vendors",
                description=(
                    "Query the Vendor Ontology to retrieve vendor information. "
                    "Can filter by CPARS rating, small business status, or NAICS code."
                ),
                parameters={
                    "cpars_rating": {
                        "type": "string",
                        "description": "Filter by CPARS rating: Exceptional, Very Good, Satisfactory, Marginal, Unsatisfactory",
                        "enum": ["Exceptional", "Very Good", "Satisfactory", "Marginal", "Unsatisfactory"]
                    }
                },
                handler=self._tool_get_vendors
            ),
            AgentTool(
                name="get_contracts_for_vendor",
                description="Retrieve active contracts for a specific vendor by their CAGE code.",
                parameters={
                    "cage_code": {
                        "type": "string",
                        "description": "The vendor's CAGE (Commercial and Government Entity) code"
                    }
                },
                handler=self._tool_get_contracts
            ),
            AgentTool(
                name="get_contracts_expiring_soon",
                description="Find contracts expiring within a specified number of days.",
                parameters={
                    "days_threshold": {
                        "type": "integer",
                        "description": "Number of days from today to check for expiring contracts"
                    }
                },
                handler=self._tool_expiring_contracts
            )
        ]

    def _tool_get_vendors(self, cpars_rating: str) -> list[dict]:
        """Data Tool: get vendors by CPARS rating."""
        objects = self.ontology.get_objects("Vendor")
        result = []
        for obj in objects:
            avg = obj.properties.get("cpars_rating_average", "")
            if avg.lower() == cpars_rating.lower():
                result.append({
                    "name": obj.properties["name"],
                    "cage_code": obj.properties["cage_code"],
                    "cpars_rating": obj.properties["cpars_rating_average"],
                    "active_contracts": obj.properties["active_contracts"],
                    "cure_notices": obj.properties.get("cure_notices", 0),
                    "debarred": obj.properties["debarred"]
                })
        return result

    def _tool_get_contracts(self, cage_code: str) -> list[dict]:
        """Data Tool: get contracts for a vendor by CAGE code."""
        vendors = self.ontology.get_objects("Vendor", filters={"cage_code": cage_code})
        if not vendors:
            return [{"error": f"No vendor found with CAGE code {cage_code}"}]

        vendor_rid = vendors[0].object_rid
        contracts = self.ontology.get_objects("Contract", filters={"vendor_rid": vendor_rid})

        return [
            {
                "contract_number": c.properties["contract_number"],
                "type": c.properties["contract_type"],
                "max_value": f"${c.properties['max_value']:,.0f}",
                "obligated": f"${c.properties['obligated_amount']:,.0f}",
                "end_date": c.properties["end_date"],
                "status": c.properties["status"],
                "program": c.properties["program"]
            }
            for c in contracts
        ]

    def _tool_expiring_contracts(self, days_threshold: int) -> list[dict]:
        """Data Tool: find contracts expiring within N days."""
        from datetime import timedelta
        today = datetime.now(timezone.utc).date()
        threshold_date = today + timedelta(days=days_threshold)

        contracts = self.ontology.get_objects("Contract")
        expiring = []
        for contract in contracts:
            end_date_str = contract.properties.get("end_date", "")
            try:
                end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
                if today <= end_date <= threshold_date:
                    vendor_rid = contract.properties.get("vendor_rid")
                    vendor = self.ontology.get_object_by_rid(vendor_rid)
                    vendor_name = vendor.properties["name"] if vendor else "Unknown"

                    expiring.append({
                        "contract_number": contract.properties["contract_number"],
                        "vendor": vendor_name,
                        "end_date": end_date_str,
                        "days_remaining": (end_date - today).days,
                        "max_value": f"${contract.properties['max_value']:,.0f}",
                        "status": contract.properties["status"]
                    })
            except ValueError:
                continue

        return sorted(expiring, key=lambda x: x["days_remaining"])

    def chat(self, user_message: str) -> str:
        """
        Process a user message with tool-calling loop.
        This is what happens under the hood in AIP Agent Studio
        when a user sends a message to an agent in a Workshop app.
        """
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        tool_specs = [t.to_api_spec() for t in self.tools]
        tool_map = {t.name: t for t in self.tools}

        system_prompt = f"""You are {self.agent_name}, an AI assistant for DoD acquisition analysis.
You have access to the Palantir Ontology which contains live data on vendors, contracts, and programs.
Always use your tools to answer questions about specific vendors or contracts — do not make up data.
When presenting data, be concise and include all relevant context for acquisition decisions."""

        current_messages = list(self.conversation_history)
        iterations = 0

        while iterations < self.max_tool_iterations:
            iterations += 1

            try:
                from openai import AzureOpenAI
                client = AzureOpenAI(
                    api_key=os.environ["AZURE_OPENAI_API_KEY"],
                    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
                    api_version="2024-08-01-preview"
                )
                response = client.chat.completions.create(
                    model=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
                    messages=[{"role": "system", "content": system_prompt}] + current_messages,
                    tools=tool_specs,
                    tool_choice="auto",
                    temperature=0.1
                )
            except (ImportError, KeyError):
                return self._chat_without_tools(system_prompt, user_message)

            message = response.choices[0].message

            if message.tool_calls:
                current_messages.append({
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": tc.type,
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        for tc in message.tool_calls
                    ]
                })
                for tool_call in message.tool_calls:
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)

                    logger.info(f"Agent calling tool: {tool_name}({tool_args})")
                    tool = tool_map.get(tool_name)
                    result = tool.execute(**tool_args) if tool else f"Unknown tool: {tool_name}"

                    current_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result
                    })
            else:
                final_answer = message.content
                self.conversation_history.append({
                    "role": "assistant",
                    "content": final_answer
                })
                return final_answer

        return "Maximum tool iterations reached. Please rephrase your question."

    def _chat_without_tools(self, system_prompt: str, user_message: str) -> str:
        """Fallback for environments without tool-calling support."""
        vendors = self.ontology.get_objects("Vendor")
        contracts = self.ontology.get_objects("Contract")

        context = "AVAILABLE DATA (from Ontology):\n"
        context += "VENDORS:\n" + self.ontology.to_llm_context(vendors)
        context += "\n\nCONTRACTS:\n" + self.ontology.to_llm_context(contracts)

        response = self.llm.complete(
            system_prompt=system_prompt + "\n\n" + context,
            user_message=user_message,
            temperature=0.1
        )
        self.conversation_history.append({
            "role": "assistant",
            "content": response.content
        })
        return response.content


# ---------------------------------------------------------------------------
# Section 3: AIP Machinery — Human-in-the-Loop Workflow
# ---------------------------------------------------------------------------

class HumanReviewStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


@dataclass
class WorkflowStep:
    """A step in an AIP Machinery-style automated workflow."""
    step_id: str
    step_name: str
    automated: bool
    confidence_threshold: float
    result: Optional[Any] = None
    confidence: Optional[float] = None
    human_decision: Optional[HumanReviewStatus] = None
    human_notes: Optional[str] = None


class ContractRiskWorkflow:
    """
    AIP Machinery-style workflow for contract risk assessment.
    Demonstrates human-in-the-loop gates for high-stakes decisions.

    In production AIP Machinery:
    - This workflow is defined in the Machinery UI
    - Workshop applications surface the human review queue
    - The system tracks which steps were automated vs. human-reviewed
    - Full audit trail is stored in the Ontology

    Confidence thresholds:
    - High confidence (>=0.85): Automated, logged
    - Medium confidence (0.60-0.85): Flagged for optional review
    - Low confidence (<0.60): Required human review before proceeding
    """

    def __init__(self, llm_client, auto_confidence_threshold: float = 0.85):
        self.llm = llm_client
        self.auto_threshold = auto_confidence_threshold
        self.audit_log: list[dict] = []

    def run(self, contract_text: str, contract_id: str) -> dict:
        """
        Run the contract risk assessment workflow.
        Returns a dict with results for each step and an overall risk rating.
        """
        steps = [
            WorkflowStep("01_extract", "Extract Contract Metadata", automated=True,
                         confidence_threshold=0.90),
            WorkflowStep("02_risk_score", "Score Contract Risk Factors", automated=True,
                         confidence_threshold=0.80),
            WorkflowStep("03_vendor_check", "Vendor Performance Check", automated=True,
                         confidence_threshold=0.95),
            WorkflowStep("04_recommend", "Generate Award Recommendation", automated=False,
                         confidence_threshold=0.0),  # Always human review
        ]

        workflow_context = {
            "contract_id": contract_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "steps": {}
        }

        for step in steps:
            result = self._execute_step(step, contract_text, workflow_context)
            workflow_context["steps"][step.step_id] = result

            if (result.get("confidence", 1.0) < step.confidence_threshold
                    and not step.automated):
                result["requires_human_review"] = True
                result["review_reason"] = (
                    f"Confidence {result.get('confidence', 0):.2f} below threshold "
                    f"{step.confidence_threshold:.2f} for step '{step.step_name}'"
                )
                self._log_audit(step, result, auto=False)
                break
            else:
                result["requires_human_review"] = not step.automated
                self._log_audit(step, result, auto=step.automated)

        workflow_context["completed_at"] = datetime.now(timezone.utc).isoformat()
        workflow_context["audit_log"] = self.audit_log
        return workflow_context

    def _execute_step(self, step: WorkflowStep, contract_text: str,
                       context: dict) -> dict:
        """Execute a single workflow step."""
        if step.step_id == "01_extract":
            return self._extract_metadata(contract_text)
        elif step.step_id == "02_risk_score":
            return self._score_risk_factors(contract_text)
        elif step.step_id == "03_vendor_check":
            return {
                "result": "Vendor check requires Ontology connection",
                "confidence": 0.95,
                "note": "See OntologyDataTool.get_objects('Vendor') for production implementation"
            }
        elif step.step_id == "04_recommend":
            return {
                "result": "Award recommendation requires human review",
                "confidence": 0.0,
                "human_review_required": True,
                "reason": "Award decisions are high-stakes and require contracting officer approval"
            }
        return {"result": "Unknown step", "confidence": 0.0}

    def _extract_metadata(self, contract_text: str) -> dict:
        """Use LLM to extract contract metadata with confidence score."""
        return {
            "result": {
                "contract_type": "FFP",
                "estimated_value": 4_250_000,
                "performance_period_months": 12
            },
            "confidence": 0.92,
            "model_used": "gpt-4o",
            "tokens_used": 847
        }

    def _score_risk_factors(self, contract_text: str) -> dict:
        """Score contract risk factors 0-100 with confidence."""
        return {
            "result": {
                "overall_risk_score": 42,
                "risk_factors": {
                    "contract_complexity": 35,
                    "vendor_past_performance": 25,
                    "timeline_risk": 60,
                    "technical_risk": 45
                },
                "risk_level": "Medium"
            },
            "confidence": 0.78,
            "flags": ["Timeline is aggressive for deliverable complexity"]
        }

    def _log_audit(self, step: WorkflowStep, result: dict, auto: bool) -> None:
        """Log workflow step to audit trail."""
        self.audit_log.append({
            "step_id": step.step_id,
            "step_name": step.step_name,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "automated": auto,
            "confidence": result.get("confidence"),
            "required_human_review": result.get("requires_human_review", False)
        })


# ---------------------------------------------------------------------------
# Section 4: Publishing a Model to Palantir Foundry
# ---------------------------------------------------------------------------
# The palantir_models library replaced foundry_ml as of October 31, 2025.
# Use this pattern when you have trained a model in Code Workspaces (Jupyter)
# and want to deploy it to the Foundry model registry for use in AIP Logic.

def publish_model_to_foundry_example():
    """
    Demonstrates the palantir_models publishing pattern.
    Run this from a Foundry Code Workspace (JupyterLab environment).

    This function is written as documentation — it requires the palantir_models
    package available only inside Foundry Code Workspaces.

    After publishing, the model can be:
    - Called from AIP Logic via a Logic Tool
    - Integrated into Ontology Functions
    - Invoked from downstream pipelines in Code Repositories
    """
    # Step 1: Train your model (example: sklearn classifier on contract data)
    example_code = """
    # --- Run inside Foundry Code Workspace ---
    import palantir_models as pm
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    import joblib
    import json

    # Train model on labeled contract data from a Foundry dataset
    # (dataset loaded via Code Workspaces dataset import sidebar)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Step 2: Define model adapter for Foundry registry
    class ContractRiskAdapter(pm.ModelAdapter):

        @classmethod
        def api_spec(cls):
            return pm.ModelApiSpec(
                inputs={"features": pm.TabularInput(schema=input_schema)},
                outputs={"risk_level": pm.TextOutput(), "score": pm.FloatOutput()}
            )

        def save(self, output_path):
            # Use joblib for sklearn models (safe binary format for same-Python-version loading)
            # Store metadata separately as JSON
            joblib.dump(self._model, f"{output_path}/clf.joblib")
            with open(f"{output_path}/metadata.json", "w") as f:
                json.dump({"model_version": "1.0", "trained_on": "contract_risk_dataset_v3"}, f)

        @classmethod
        def load(cls, input_path):
            adapter = cls()
            adapter._model = joblib.load(f"{input_path}/clf.joblib")
            return adapter

        def predict(self, inputs):
            features = inputs["features"]
            prediction = self._model.predict([features])[0]
            score = float(max(self._model.predict_proba([features])[0]))
            return {"risk_level": str(prediction), "score": score}

    # Step 3: Publish to Foundry model registry
    # Opens the Models sidebar in Code Workspaces and registers the model
    model_rid = pm.publish_model(
        adapter=ContractRiskAdapter(),
        model_name="contract-risk-classifier-v1",
        description="Classifies DoD contracts by risk level (Low/Medium/High/Critical)"
    )
    print(f"Model published: {model_rid}")
    # Now add this model as a Logic Tool in AIP Logic to expose it to LLM workflows
    """
    return example_code


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Demo: Run the Ontology data tool and human-in-the-loop workflow
    without requiring a Foundry connection.
    """
    print("=== Chapter 13: AIP Agent Patterns Demo ===\n")

    # 1. Demo: Ontology Data Tool
    print("--- Ontology Data Tool Demo ---")
    ontology = OntologyDataTool()

    print("\nAll vendors:")
    vendors = ontology.get_objects("Vendor")
    print(ontology.to_llm_context(vendors))

    print("\nVendors with Marginal CPARS rating:")
    marginal = ontology.get_objects("Vendor", filters={"cpars_rating_average": "Marginal"})
    print(ontology.to_llm_context(marginal))

    # 2. Demo: Human-in-the-Loop Workflow
    print("\n--- Human-in-the-Loop Workflow Demo ---")
    sample_contract = """
    CONTRACT NUMBER: W91QV2-25-C-0042
    CONTRACT TYPE: FFP
    VENDOR: Apex Defense Solutions LLC
    VALUE: $4,250,000
    PERFORMANCE PERIOD: 12 months
    DELIVERABLES: Final Technical Report in 11.5 months
    """

    workflow = ContractRiskWorkflow(llm_client=None)
    result = workflow.run(
        contract_text=sample_contract,
        contract_id="W91QV2-25-C-0042"
    )

    print(f"\nWorkflow completed: {result['contract_id']}")
    for step_id, step_result in result["steps"].items():
        confidence = step_result.get("confidence", "N/A")
        review = "HUMAN REVIEW REQUIRED" if step_result.get("requires_human_review") else "automated"
        print(f"  {step_id}: confidence={confidence} | {review}")

    print(f"\nAudit log entries: {len(result['audit_log'])}")
    for entry in result["audit_log"]:
        print(f"  {entry['step_name']}: automated={entry['automated']}, "
              f"confidence={entry['confidence']}")

    # 3. Show palantir_models publishing example
    print("\n--- Foundry Model Publishing Pattern ---")
    code_example = publish_model_to_foundry_example()
    print("Example code for Foundry Code Workspace:")
    print(code_example[:400] + "...")

    print("\n--- Agent Demo (requires Azure OpenAI credentials) ---")
    print("To run the conversational agent demo, set:")
    print("  AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT")
    print("  Then initialize:")
    print("  agent = AIPAgentSimulator(llm_client, ontology, 'AcquisitionBot')")
    print("  agent.chat('Which vendors have Marginal CPARS ratings with active contracts?')")
