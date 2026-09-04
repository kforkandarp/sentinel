"""End-to-End Sentinel Pipeline Evaluation and Scenario Verification."""

from decimal import Decimal
from pathlib import Path
from pydantic import BaseModel, ConfigDict

from sentinel.agent.reasoning import ActionProposal, CommerceAgent
from sentinel.audit.events import AuditEvent, AuditEventType
from sentinel.audit.logger import AuditLogger
from sentinel.detection.detector import PromptInjectionDetector
from sentinel.detection.models import DetectionResult
from sentinel.execution.executor import ActionExecutor, ExecutionBlockedError
from sentinel.gateway.ingestion import IngestedArtifact, ingest_document
from sentinel.inspection.models import InspectionRoute
from sentinel.inspection.router import InspectionRouter
from sentinel.policy.gate import PolicyDecision, PolicyDecisionType, PolicyGate, TaskScope


class ScenarioResult(BaseModel):
    """Structured report of an end-to-end Sentinel scenario run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_name: str
    artifact_id: str
    correlation_id: str
    ground_truth: str
    detector_label: str
    detector_score: float
    inspection_route: str
    policy_decision: str
    policy_reason: str
    executed: bool
    audit_events: list[str]


def execute_e2e_pipeline(
    artifact_path: Path | str,
    ground_truth: str,
    scenario_name: str,
    product_id: str,
    category: str,
    quantity: int,
    unit_price: Decimal,
    task_scope: TaskScope | None = None,
    detector: PromptInjectionDetector | None = None,
    gate: PolicyGate | None = None,
    audit_logger: AuditLogger | None = None,
) -> tuple[ScenarioResult, AuditLogger]:
    """Execute the complete Sentinel pipeline:

    Ingest -> Route -> Detect -> Propose -> PolicyGate -> ActionExecutor -> Audit.
    """
    path = Path(artifact_path)
    if not path.is_file():
        raise FileNotFoundError(f"Artifact not found: {path}")

    active_detector = detector or PromptInjectionDetector()
    active_gate = gate or PolicyGate()
    active_logger = audit_logger or AuditLogger()
    executor = ActionExecutor(policy_gate=active_gate)
    router = InspectionRouter()
    agent = CommerceAgent()

    # 1. Ingestion
    content_bytes = path.read_bytes()
    artifact: IngestedArtifact = ingest_document(content_bytes, path.name)
    cid = artifact.provenance.correlation_id

    active_logger.log(
        AuditEvent(
            correlation_id=cid,
            event_type=AuditEventType.INGESTED,
            details={
                "source_type": artifact.provenance.source_type,
                "workflow": artifact.provenance.workflow,
                "content_type": artifact.provenance.content_type,
                "artifact_hash": artifact.provenance.artifact_hash,
            },
        )
    )

    # 2. Inspection Router
    inspection_decision = router.route(artifact.content, artifact.provenance)
    active_logger.log(
        AuditEvent(
            correlation_id=cid,
            event_type=AuditEventType.INSPECTION_ROUTED,
            details={
                "route": inspection_decision.route.value,
                "reason": inspection_decision.reason,
            },
        )
    )

    # 3. Detection (ML Inference via actual detect API)
    if inspection_decision.route == InspectionRoute.BLOCK:
        raise RuntimeError(f"Inspection router blocked artifact unexpectedly: {inspection_decision.reason}")

    det_result: DetectionResult = active_detector.detect(artifact.content)

    active_logger.log(
        AuditEvent(
            correlation_id=cid,
            event_type=AuditEventType.DETECTED,
            details={
                "label": det_result.label.value,
                "score": f"{det_result.score:.4f}",
                "model_name": det_result.model_name,
            },
        )
    )

    # 4. Agent Proposal
    proposal: ActionProposal = agent.propose_purchase(
        product_id=product_id,
        category=category,
        quantity=quantity,
        unit_price=unit_price,
        correlation_id=cid,
    )
    active_logger.log(
        AuditEvent(
            correlation_id=cid,
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

    # 5. Deterministic Policy Gate
    policy_decision: PolicyDecision = active_gate.evaluate(
        proposal=proposal,
        provenance=artifact.provenance,
        detection_result=det_result,
        task_scope=task_scope,
    )
    active_logger.log(
        AuditEvent(
            correlation_id=cid,
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
            active_logger.log(
                AuditEvent(
                    correlation_id=cid,
                    event_type=AuditEventType.ACTION_EXECUTED,
                    details={"action_id": f"exec_{proposal.product_id}"},
                )
            )
        except ExecutionBlockedError as e:
            active_logger.log(
                AuditEvent(
                    correlation_id=cid,
                    event_type=AuditEventType.ACTION_BLOCKED,
                    details={"reason": str(e)},
                )
            )
    else:
        active_logger.log(
            AuditEvent(
                correlation_id=cid,
                event_type=AuditEventType.ACTION_BLOCKED,
                details={"reason": policy_decision.reason},
            )
        )

    all_events = [evt.event_type.value for evt in active_logger.get_by_correlation_id(cid)]

    result = ScenarioResult(
        scenario_name=scenario_name,
        artifact_id=path.name,
        correlation_id=cid,
        ground_truth=ground_truth,
        detector_label=det_result.label.value,
        detector_score=round(det_result.score, 4),
        inspection_route=inspection_decision.route.value,
        policy_decision=policy_decision.decision.value,
        policy_reason=policy_decision.reason,
        executed=executed,
        audit_events=all_events,
    )

    return result, active_logger


def scan_adversarial_artifacts_for_detector_results(
    corpus_dir: Path | str,
    detector: PromptInjectionDetector | None = None,
) -> dict[str, DetectionResult]:
    """Scan all adversarial corpus files with the locked detector using detect()."""
    corpus_path = Path(corpus_dir)
    adv_dir = corpus_path / "adversarial"
    active_detector = detector or PromptInjectionDetector()

    results: dict[str, DetectionResult] = {}
    for file_path in sorted(adv_dir.iterdir()):
        if file_path.is_file():
            artifact = ingest_document(file_path.read_bytes(), file_path.name)
            res = active_detector.detect(artifact.content)
            results[file_path.name] = res
    return results