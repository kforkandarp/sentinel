"""FastAPI application entry point for the Sentinel AI Security Gateway."""

from decimal import Decimal
import uuid
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from sentinel.agent.reasoning import ActionProposal, ActionType
from sentinel.audit.events import AuditEvent, AuditEventType
from sentinel.audit.logger import AuditLogger
from sentinel.detection.detector import PromptInjectionDetector
from sentinel.detection.models import DetectionResult
from sentinel.execution.executor import ActionExecutor, ExecutionBlockedError
from sentinel.gateway.ingestion import IngestedArtifact, ingest_document, ingest_text_internal
from sentinel.inspection.models import InspectionRoute
from sentinel.inspection.router import InspectionRouter
from sentinel.policy.gate import PolicyDecision, PolicyDecisionType, PolicyGate, TaskScope

VERSION = "0.1.0"

app = FastAPI(
    title="Sentinel AI Security Gateway",
    version=VERSION,
    description=(
        "Production AI Security Gateway demonstrating deterministic authorization boundaries "
        "and runtime instruction defense. Invariant: Detection != Authorization."
    ),
)

# In-memory service state (bounded buildathon footprint)
detector = PromptInjectionDetector()
router = InspectionRouter()
gate = PolicyGate()
executor = ActionExecutor(policy_gate=gate)
audit_logger = AuditLogger()


class TaskScopeInput(BaseModel):
    """User-delegated task scope (authorization input, not untrusted content)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_categories: list[str] = Field(
        ...,
        description="Authorized categories (e.g. ['laptop', 'cable']).",
    )
    max_budget: Decimal | None = Field(
        default=None,
        gt=Decimal("0.00"),
        description="Delegated budget ceiling authorized by user.",
    )


class ScanRequest(BaseModel):
    """Scan request combining untrusted external content with an explicit action proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str = Field(
        ...,
        min_length=1,
        description="Raw untrusted external content (document, review, web content).",
    )
    product_id: str = Field(..., description="Target product identifier.")
    category: str = Field(..., description="Proposed item category.")
    quantity: int = Field(..., gt=0, description="Proposed order quantity.")
    unit_price: Decimal = Field(..., gt=Decimal("0.00"), description="Unit price per item.")
    task_scope: TaskScopeInput | None = Field(
        default=None,
        description="Explicit user-delegated authorization constraints.",
    )


class ScanResponse(BaseModel):
    """Sanitized, machine-readable pipeline execution summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_hash: str
    correlation_id: str
    inspection_route: str
    inspection_reason: str
    detector_label: str
    detector_score: float
    policy_decision: str
    policy_reason: str
    executed: bool
    audit_events: list[str]


class IngestFileResponse(BaseModel):
    """Result of file ingestion without authorization authority."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    filename: str
    extracted_content: str
    content_type: str
    artifact_hash: str


@app.get("/health", summary="Gateway Health Check")
def health_check() -> dict[str, str]:
    """Lightweight operational readiness check."""
    return {
        "status": "ok",
        "service": "sentinel-gateway",
        "version": VERSION,
    }


@app.post("/ingest-file", response_model=IngestFileResponse, summary="Ingest Document File")
async def ingest_file_endpoint(file: UploadFile = File(...)) -> IngestFileResponse:
    """Ingest a TXT, Markdown, or PDF document using existing Phase 4 ingestion.

    The extracted content is strictly untrusted and conveys no execution authority.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing from upload.")

    try:
        content_bytes = await file.read()
        artifact: IngestedArtifact = ingest_document(content_bytes, file.filename)
        return IngestFileResponse(
            filename=file.filename,
            extracted_content=artifact.content,
            content_type=artifact.provenance.content_type,
            artifact_hash=artifact.provenance.artifact_hash,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to process document: {e}")


@app.post("/scan", response_model=ScanResponse, summary="Inspect Content and Authorize Action")
def scan_and_authorize(request: ScanRequest) -> ScanResponse:
    """End-to-end security pipeline execution:

    Ingest -> Route -> Detect -> Proposal -> PolicyGate -> ActionExecutor -> Audit.
    """
    correlation_id = str(uuid.uuid4())

    # 1. Gateway Ingestion (Establishes trusted provenance)
    artifact: IngestedArtifact = ingest_text_internal(
        content=request.content,
        correlation_id=correlation_id,
        client_id="api_caller",
    )

    audit_logger.log(
        AuditEvent(
            correlation_id=correlation_id,
            event_type=AuditEventType.INGESTED,
            details={
                "source_type": artifact.provenance.source_type,
                "workflow": artifact.provenance.workflow,
                "artifact_hash": artifact.provenance.artifact_hash,
                "content_type": artifact.provenance.content_type,
            },
        )
    )

    # 2. Inspection Router
    inspection_decision = router.route(artifact.content, artifact.provenance)
    audit_logger.log(
        AuditEvent(
            correlation_id=correlation_id,
            event_type=AuditEventType.INSPECTION_ROUTED,
            details={
                "route": inspection_decision.route.value,
                "reason": inspection_decision.reason,
            },
        )
    )

    if inspection_decision.route == InspectionRoute.BLOCK:
        audit_logger.log(
            AuditEvent(
                correlation_id=correlation_id,
                event_type=AuditEventType.ACTION_BLOCKED,
                details={"reason": f"Blocked by inspection router: {inspection_decision.reason}"},
            )
        )
        raise HTTPException(
            status_code=400,
            detail=f"Content blocked at inspection router: {inspection_decision.reason}",
        )

    # 3. Detection Layer (Locked DeBERTa-v3 model)
    det_result: DetectionResult = detector.detect(artifact.content)
    audit_logger.log(
        AuditEvent(
            correlation_id=correlation_id,
            event_type=AuditEventType.DETECTED,
            details={
                "label": det_result.label.value,
                "score": f"{det_result.score:.4f}",
                "model_name": det_result.model_name,
            },
        )
    )

    # 4. Action Proposal Formulation
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id=request.product_id,
        category=request.category,
        quantity=request.quantity,
        unit_price=request.unit_price,
        total=request.unit_price * request.quantity,
        currency="INR",
        correlation_id=correlation_id,
    )
    audit_logger.log(
        AuditEvent(
            correlation_id=correlation_id,
            event_type=AuditEventType.ACTION_PROPOSED,
            details={
                "action_type": proposal.action_type.value,
                "product_id": proposal.product_id,
                "category": proposal.category,
                "total": str(proposal.total),
                "currency": proposal.currency,
            },
        )
    )

    # 5. Deterministic Policy Gate (Authorization Boundary)
    scope_obj = None
    if request.task_scope is not None:
        scope_obj = TaskScope(
            allowed_categories=request.task_scope.allowed_categories,
            max_budget=request.task_scope.max_budget,
        )

    policy_decision: PolicyDecision = gate.evaluate(
        proposal=proposal,
        provenance=artifact.provenance,
        detection_result=det_result,
        task_scope=scope_obj,
    )
    audit_logger.log(
        AuditEvent(
            correlation_id=correlation_id,
            event_type=AuditEventType.POLICY_DECIDED,
            details={
                "decision": policy_decision.decision.value,
                "reason": policy_decision.reason,
            },
        )
    )

    # 6. Action Execution Boundary
    executed = False
    if policy_decision.decision == PolicyDecisionType.ALLOW:
        try:
            executor.execute(proposal, policy_decision)
            executed = True
            audit_logger.log(
                AuditEvent(
                    correlation_id=correlation_id,
                    event_type=AuditEventType.ACTION_EXECUTED,
                    details={"action_id": f"exec_{proposal.product_id}"},
                )
            )
        except ExecutionBlockedError as exc:
            audit_logger.log(
                AuditEvent(
                    correlation_id=correlation_id,
                    event_type=AuditEventType.ACTION_BLOCKED,
                    details={"reason": str(exc)},
                )
            )
    else:
        audit_logger.log(
            AuditEvent(
                correlation_id=correlation_id,
                event_type=AuditEventType.ACTION_BLOCKED,
                details={"reason": policy_decision.reason},
            )
        )

    audit_records = audit_logger.get_by_correlation_id(correlation_id)

    return ScanResponse(
        artifact_hash=artifact.provenance.artifact_hash,
        correlation_id=correlation_id,
        inspection_route=inspection_decision.route.value,
        inspection_reason=inspection_decision.reason,
        detector_label=det_result.label.value,
        detector_score=round(det_result.score, 4),
        policy_decision=policy_decision.decision.value,
        policy_reason=policy_decision.reason,
        executed=executed,
        audit_events=[evt.event_type.value for evt in audit_records],
    )