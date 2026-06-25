from pydantic import BaseModel
from typing import Optional
from datetime import datetime


# ── Compliance Report (existing, enhanced with 3-tier status) ─────────────────

class HostComplianceRow(BaseModel):
    host_id: str
    hostname: str
    ip_address: str
    os_type: str
    status: str
    compliance_status: str = "Never Scanned"
    last_scan_at: Optional[datetime]
    days_since_scan: Optional[float]
    total_missing: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    compliance_score: float

    model_config = {"from_attributes": True}


class ComplianceReportResponse(BaseModel):
    generated_at: datetime
    date_from: Optional[datetime]
    date_to: Optional[datetime]
    total_hosts: int
    compliant_hosts: int
    partial_hosts: int = 0
    non_compliant_hosts: int = 0
    never_scanned_hosts: int = 0
    fleet_compliance_rate: float
    rows: list[HostComplianceRow]


# ── Deployment History Report (existing) ──────────────────────────────────────

class DeploymentHistoryRow(BaseModel):
    deployment_id: str
    patch_name: str
    patch_severity: Optional[str]
    hostname: str
    host_id: str
    status: str
    scheduled_at: Optional[datetime]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_seconds: Optional[int]

    model_config = {"from_attributes": True}


class DeploymentHistoryReportResponse(BaseModel):
    generated_at: datetime
    date_from: Optional[datetime]
    date_to: Optional[datetime]
    total_deployments: int
    successful: int
    failed: int
    success_rate: float
    avg_duration_seconds: Optional[float]
    rows: list[DeploymentHistoryRow]


# ── Top Missing Patches Report ────────────────────────────────────────────────

class TopMissingPatchRow(BaseModel):
    kb_id: str
    title: str
    severity: str
    affected_hosts: int
    host_names: list[str]


class TopMissingPatchesResponse(BaseModel):
    generated_at: datetime
    total_unique_patches: int
    rows: list[TopMissingPatchRow]


# ── Risk Matrix Report ────────────────────────────────────────────────────────

class HostRiskRow(BaseModel):
    host_id: str
    hostname: str
    ip_address: str
    os_type: str
    risk_level: str
    risk_score: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    last_scan_at: Optional[datetime]

    model_config = {"from_attributes": True}


class RiskMatrixResponse(BaseModel):
    generated_at: datetime
    critical_hosts: int
    high_risk_hosts: int
    medium_risk_hosts: int
    low_risk_hosts: int
    unknown_hosts: int
    rows: list[HostRiskRow]


# ── Deployment Status Matrix (existing) ───────────────────────────────────────

class DeploymentMatrixCell(BaseModel):
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    deployment_id: str


class DeploymentMatrixRow(BaseModel):
    patch_id: str
    patch_name: str
    severity: Optional[str]
    classification: Optional[str]
    hosts: dict[str, DeploymentMatrixCell]


class DeploymentMatrixResponse(BaseModel):
    generated_at: datetime
    patches: list[DeploymentMatrixRow]
    hosts: list[dict]
    total_patches: int
    total_hosts: int


# ══════════════════════════════════════════════════════════════════════════════
# DOCUMENT REPORT SCHEMAS
# ══════════════════════════════════════════════════════════════════════════════


class DocMeta(BaseModel):
    title: str
    generated_at: datetime
    generated_by: str
    date_range: Optional[dict]
    report_id: str


class DocMissingPatch(BaseModel):
    kb_id: str
    title: str
    severity: str
    classification: Optional[str]
    days_missing: int


class DocHost(BaseModel):
    host_id: str
    hostname: str
    os: str
    compliance_score: float
    status: str
    last_scan: Optional[datetime]
    missing_patches: list[DocMissingPatch]
    failed_deployments_count: int
    recommendations: list[str]


class DocPatchSummary(BaseModel):
    kb_id: str
    title: str
    severity: str
    classification: Optional[str]
    affected_hosts: list[str]
    deployed_count: int
    failed_count: int
    success_rate: float
    recommendation: str


class DocFailureAnalysis(BaseModel):
    deployment_id: str
    kb_id: str
    hostname: str
    failed_at: Optional[datetime]
    error_message: Optional[str]
    attempt_number: int


class ComplianceDocumentResponse(BaseModel):
    meta: DocMeta
    summary: dict
    findings: list[str]
    hosts: list[DocHost]
    patch_summary: list[DocPatchSummary]
    failure_analysis: list[DocFailureAnalysis]


class DocDeployment(BaseModel):
    deployment_id: str
    kb_id: str
    title: str
    severity: Optional[str]
    hostname: str
    status: str
    scheduled_at: Optional[datetime]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_minutes: Optional[float]
    error_message: Optional[str]
    approved_by: Optional[str]
    retry_count: int


class DocByPatch(BaseModel):
    kb_id: str
    title: str
    severity: Optional[str]
    total_attempts: int
    success: int
    failed: int
    success_rate: float
    hosts_attempted: list[str]
    recommendation: str


class DocByHost(BaseModel):
    hostname: str
    total_deployments: int
    successful: int
    failed: int
    success_rate: float
    patches_attempted: list[str]
    recommendation: str


class DeploymentDocumentResponse(BaseModel):
    meta: DocMeta
    summary: dict
    findings: list[str]
    deployments: list[DocDeployment]
    by_patch: list[DocByPatch]
    by_host: list[DocByHost]
