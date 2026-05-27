import uuid
import hashlib
from typing import Optional
from app.scanners.base import ScannerFinding


def new_uuid() -> str:
    return str(uuid.uuid4())


def make_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class GraphBuilder:
    """
    Converts scanner findings into graph nodes, edges, evidence items,
    findings and remediation tasks — all as plain dicts ready to insert into DB.
    """

    def __init__(self, organisation_id: str, project_id: Optional[str], scan_run_id: str):
        self.organisation_id = organisation_id
        self.project_id = project_id
        self.scan_run_id = scan_run_id

        self.nodes: list[dict] = []
        self.edges: list[dict] = []
        self.evidence_items: list[dict] = []
        self.findings: list[dict] = []
        self.remediation_tasks: list[dict] = []

        # Track nodes by type+name to avoid duplicates
        self._node_index: dict[str, str] = {}

    def _get_or_create_node(self, node_type: str, name: str, metadata: dict = None) -> str:
        key = f"{node_type}::{name}"
        if key in self._node_index:
            return self._node_index[key]
        node_id = new_uuid()
        self.nodes.append({
            "id": node_id,
            "organisation_id": self.organisation_id,
            "project_id": self.project_id,
            "node_type": node_type,
            "name": name,
            "metadata": metadata or {},
        })
        self._node_index[key] = node_id
        return node_id

    def _create_edge(self, source_id: str, target_id: str, edge_type: str,
                     confidence: float = 1.0, evidence_item_id: Optional[str] = None,
                     metadata: dict = None):
        self.edges.append({
            "id": new_uuid(),
            "organisation_id": self.organisation_id,
            "project_id": self.project_id,
            "source_node_id": source_id,
            "target_node_id": target_id,
            "edge_type": edge_type,
            "confidence": confidence,
            "evidence_item_id": evidence_item_id,
            "metadata": metadata or {},
        })

    def _create_evidence_item(self, scanner_finding: ScannerFinding) -> str:
        evidence_id = new_uuid()
        excerpt = scanner_finding.evidence_excerpt or scanner_finding.description[:200]
        self.evidence_items.append({
            "id": evidence_id,
            "organisation_id": self.organisation_id,
            "project_id": self.project_id,
            "scan_run_id": self.scan_run_id,
            "evidence_type": "scanner_output",
            "source_name": scanner_finding.scanner_name,
            "file_path": scanner_finding.file_path,
            "function_name": scanner_finding.function_name,
            "line_start": scanner_finding.line_start,
            "line_end": scanner_finding.line_end,
            "excerpt": excerpt,
            "redacted_excerpt": excerpt,
            "scanner_name": scanner_finding.scanner_name,
            "confidence": scanner_finding.confidence,
            "hash": make_hash(excerpt),
            "metadata": scanner_finding.metadata,
        })
        return evidence_id

    def build_from_scanner_results(self, scanner_results: dict, filename: str = "code") -> None:
        """Build the evidence graph from orchestrator output."""

        # Create code file node
        file_node_id = self._get_or_create_node("code_file", filename)

        # Create system node
        system_node_id = self._get_or_create_node("system", f"System: {filename}")

        self._create_edge(system_node_id, file_node_id, "DERIVED_FROM_CODE")

        # Process each scanner finding
        for raw in scanner_results.get("scanner_findings", []):
            finding = ScannerFinding(
                scanner_name=raw["scanner_name"],
                finding_type=raw["finding_type"],
                title=raw["title"],
                description=raw["description"],
                confidence=raw.get("confidence", 0.8),
                file_path=raw.get("file_path"),
                function_name=raw.get("function_name"),
                line_start=raw.get("line_start"),
                line_end=raw.get("line_end"),
                evidence_excerpt=raw.get("evidence_excerpt"),
                tags=raw.get("tags", []),
                suggested_node_type=raw.get("suggested_node_type"),
                metadata=raw.get("metadata", {}),
            )

            evidence_id = self._create_evidence_item(finding)
            self._process_finding(finding, file_node_id, system_node_id, evidence_id)

    def _process_finding(self, finding: ScannerFinding, file_node_id: str,
                         system_node_id: str, evidence_id: str) -> None:
        """Route scanner finding to appropriate graph nodes and edges."""

        ft = finding.finding_type

        if ft == "personal_data_detected":
            category = finding.metadata.get("data_category", "unknown")
            data_node_id = self._get_or_create_node("data_element", category,
                                                     {"category": category})
            self._create_edge(system_node_id, data_node_id, "PROCESSES_DATA",
                             finding.confidence, evidence_id)
            self._create_edge(file_node_id, data_node_id, "PROCESSES_DATA",
                             finding.confidence, evidence_id)
            self._add_obligation_edge(system_node_id, "GDPR Art. 5 — Data Protection Principles",
                                      "MAY_TRIGGER_OBLIGATION", finding.confidence, evidence_id)
            self._add_obligation_edge(system_node_id, "GDPR Art. 6 — Lawful Basis",
                                      "MAY_TRIGGER_OBLIGATION", finding.confidence, evidence_id)

        elif ft == "special_category_data":
            category = finding.metadata.get("special_category", "unknown")
            data_node_id = self._get_or_create_node("data_element", f"special:{category}",
                                                     {"special_category": category})
            self._create_edge(system_node_id, data_node_id, "PROCESSES_DATA",
                             finding.confidence, evidence_id)
            self._add_obligation_edge(system_node_id, "GDPR Art. 9 — Special Category Data",
                                      "TRIGGERS_OBLIGATION", 0.95, evidence_id)
            self._add_obligation_edge(system_node_id, "GDPR Art. 35 — DPIA",
                                      "MAY_TRIGGER_OBLIGATION", 0.9, evidence_id)
            self._create_finding_node(finding, evidence_id, "critical",
                                       "GDPR", ["GDPR_ART9", "GDPR_ART35"])

        elif ft == "ai_provider_detected":
            provider = finding.metadata.get("provider", "Unknown AI Provider")
            ai_node_id = self._get_or_create_node("ai_system", provider,
                                                   {"provider": provider})
            vendor_node_id = self._get_or_create_node("vendor", provider)
            self._create_edge(system_node_id, ai_node_id, "CALLS_AI_MODEL",
                             finding.confidence, evidence_id)
            self._create_edge(ai_node_id, vendor_node_id, "USES_VENDOR",
                             finding.confidence, evidence_id)
            self._add_obligation_edge(system_node_id, "GDPR Art. 28 — Data Processing Agreement",
                                      "MAY_TRIGGER_OBLIGATION", 0.9, evidence_id)
            self._add_obligation_edge(system_node_id, "AI Act Art. 6 — High-Risk Classification",
                                      "MAY_TRIGGER_OBLIGATION", 0.75, evidence_id)

        elif ft == "automated_decision_detected":
            decision_type = finding.metadata.get("decision_type", "automated decision")
            proc_node_id = self._get_or_create_node("processing_activity", decision_type)
            self._create_edge(system_node_id, proc_node_id, "GENERATES_FINDING",
                             finding.confidence, evidence_id)
            self._add_obligation_edge(system_node_id, "GDPR Art. 22 — Automated Decision-Making",
                                      "MAY_TRIGGER_OBLIGATION", 0.9, evidence_id)
            self._add_obligation_edge(system_node_id, "AI Act Art. 14 — Human Oversight",
                                      "MAY_TRIGGER_OBLIGATION", 0.85, evidence_id)
            self._create_finding_node(finding, evidence_id, "high",
                                       "GDPR", ["GDPR_ART22", "AI_ACT_ART14"])

        elif ft == "missing_human_oversight":
            self._add_obligation_edge(system_node_id, "GDPR Art. 22 — Automated Decision-Making",
                                      "TRIGGERS_OBLIGATION", 0.9, evidence_id)
            self._add_obligation_edge(system_node_id, "AI Act Art. 14 — Human Oversight",
                                      "TRIGGERS_OBLIGATION", 0.9, evidence_id)
            self._create_finding_node(finding, evidence_id, "critical",
                                       "GDPR", ["GDPR_ART22", "AI_ACT_ART14"])
            self._add_remediation(
                finding_title=finding.title,
                task_title="Implement mandatory human review mechanism",
                description=(
                    "Add a human review step before any automated decision takes effect. "
                    "The reviewer must have the authority, knowledge and tools to meaningfully "
                    "assess the AI output before acting on it. Document the review process."
                ),
                priority="urgent"
            )

        elif ft == "third_party_vendor":
            vendor = finding.metadata.get("vendor_name", "Unknown Vendor")
            vendor_node_id = self._get_or_create_node("vendor", vendor)
            self._create_edge(system_node_id, vendor_node_id, "USES_VENDOR",
                             finding.confidence, evidence_id)
            self._add_obligation_edge(vendor_node_id, "GDPR Art. 28 — Data Processing Agreement",
                                      "MAY_TRIGGER_OBLIGATION", 0.85, evidence_id)

        elif ft == "non_eea_transfer":
            transfer_node_id = self._get_or_create_node("third_party_transfer", "Non-EEA Transfer")
            self._create_edge(system_node_id, transfer_node_id, "SENDS_DATA_TO",
                             finding.confidence, evidence_id)
            self._add_obligation_edge(transfer_node_id, "GDPR Art. 44-49 — International Transfers",
                                      "MAY_TRIGGER_OBLIGATION", 0.85, evidence_id)
            self._create_finding_node(finding, evidence_id, "high",
                                       "GDPR", ["GDPR_ART44"])

        elif ft == "missing_retention_deletion":
            self._add_obligation_edge(system_node_id, "GDPR Art. 5 — Data Protection Principles",
                                      "MAY_TRIGGER_OBLIGATION", 0.8, evidence_id)
            self._create_finding_node(finding, evidence_id, "medium",
                                       "GDPR", ["GDPR_ART5"])
            self._add_remediation(
                finding_title=finding.title,
                task_title="Implement data retention schedule and deletion mechanism",
                description=(
                    "Define retention periods for each category of personal data. "
                    "Implement automated deletion when retention period expires. "
                    "Document the retention schedule in the Records of Processing Activities."
                ),
                priority="high"
            )

        elif ft == "secret_exposed":
            security_node_id = self._get_or_create_node("security_measure", "Secret Management")
            self._create_edge(file_node_id, security_node_id, "GENERATED_FINDING",
                             finding.confidence, evidence_id)
            self._create_finding_node(finding, evidence_id, "critical",
                                       "GDPR", ["GDPR_ART32"])
            self._add_remediation(
                finding_title=finding.title,
                task_title="Remove hardcoded secret and rotate credential",
                description=(
                    "Remove the exposed secret from the codebase immediately. "
                    "Rotate the compromised credential. "
                    "Store secrets in environment variables or a secrets manager."
                ),
                priority="urgent"
            )

        elif ft == "sensitive_data_logged":
            log_node_id = self._get_or_create_node("log_sink", "Application Logs")
            self._create_edge(system_node_id, log_node_id, "LOGS_TO",
                             finding.confidence, evidence_id)
            self._add_obligation_edge(log_node_id, "GDPR Art. 32 — Security of Processing",
                                      "MAY_TRIGGER_OBLIGATION", 0.8, evidence_id)

        elif ft == "missing_authentication":
            security_node_id = self._get_or_create_node("security_measure", "Authentication")
            self._create_edge(system_node_id, security_node_id, "GENERATED_FINDING",
                             finding.confidence, evidence_id)
            self._create_finding_node(finding, evidence_id, "high",
                                       "GDPR", ["GDPR_ART32"])

        elif ft in ("cookie_tracking_detected", "tracking_without_consent"):
            tracking_node_id = self._get_or_create_node("processing_activity", "Cookie/Tracking")
            self._create_edge(system_node_id, tracking_node_id, "PROCESSES_DATA",
                             finding.confidence, evidence_id)
            if ft == "tracking_without_consent":
                self._add_obligation_edge(tracking_node_id, "GDPR Art. 6 — Lawful Basis",
                                          "TRIGGERS_OBLIGATION", 0.85, evidence_id)
                self._create_finding_node(finding, evidence_id, "high",
                                           "GDPR", ["GDPR_ART6", "GDPR_ART7"])

    def _add_obligation_edge(self, source_node_id: str, obligation_name: str,
                              edge_type: str, confidence: float,
                              evidence_item_id: Optional[str] = None) -> None:
        obligation_node_id = self._get_or_create_node("obligation", obligation_name)
        self._create_edge(source_node_id, obligation_node_id, edge_type,
                         confidence, evidence_item_id)

    def _create_finding_node(self, scanner_finding: ScannerFinding,
                              evidence_id: str, severity: str,
                              risk_domain: str, obligation_tags: list[str]) -> str:
        finding_id = new_uuid()
        self.findings.append({
            "id": finding_id,
            "organisation_id": self.organisation_id,
            "project_id": self.project_id,
            "scan_run_id": self.scan_run_id,
            "title": scanner_finding.title,
            "description": scanner_finding.description,
            "severity": severity,
            "risk_domain": risk_domain,
            "status": "open",
            "confidence": scanner_finding.confidence,
            "observed_or_inferred": "observed",
            "legal_references": {"tags": obligation_tags},
            "evidence_item_ids": [evidence_id],
            "obligation_ids": [],
            "rationale": scanner_finding.description,
            "recommendation": f"Review and remediate: {scanner_finding.title}",
            "human_review_required": True,
            "metadata": scanner_finding.metadata,
        })
        return finding_id

    def _add_remediation(self, finding_title: str, task_title: str,
                          description: str, priority: str = "high") -> str:
        task_id = new_uuid()
        self.remediation_tasks.append({
            "id": task_id,
            "organisation_id": self.organisation_id,
            "project_id": self.project_id,
            "finding_id": None,
            "title": task_title,
            "description": description,
            "priority": priority,
            "status": "open",
            "owner_name": None,
            "owner_email": None,
            "due_date": None,
            "evidence_required": [f"Resolution evidence for: {finding_title}"],
            "completion_evidence_item_ids": [],
        })
        return task_id

    def to_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "evidence_items": self.evidence_items,
            "findings": self.findings,
            "remediation_tasks": self.remediation_tasks,
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "total_evidence_items": len(self.evidence_items),
                "total_findings": len(self.findings),
                "total_tasks": len(self.remediation_tasks),
            }
        }
