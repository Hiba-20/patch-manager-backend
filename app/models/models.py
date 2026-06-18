import uuid
from sqlalchemy import Column, Integer, String, DateTime, Float, Text, ForeignKey, JSON, Enum as SQLEnum, Table, Date, Boolean, UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.database import Base

# Enums based on the UML Class Diagram
class OSType(str, enum.Enum):
    WINDOWS = "WINDOWS"
    LINUX_DEBIAN = "LINUX_DEBIAN"
    LINUX_RHEL = "LINUX_RHEL"
    LINUX_OTHER = "LINUX_OTHER"

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    VIEWER = "VIEWER"

class PatchStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLBACK = "ROLLBACK"

class ScanStatus(str, enum.Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class AuditAction(str, enum.Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    SCAN_LAUNCHED = "SCAN_LAUNCHED"
    PATCH_APPROVED = "PATCH_APPROVED"
    PATCH_DEPLOYED = "PATCH_DEPLOYED"
    HOST_REGISTERED = "HOST_REGISTERED"
    KEY_ROTATED = "KEY_ROTATED"


# Many-to-Many association table between Group and Host
group_host_association = Table(
    "group_host_association",
    Base.metadata,
    Column("group_id", UUID(as_uuid=True), ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
    Column("host_id", UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
)


class Group(Base):
    __tablename__ = "groups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    hosts = relationship("Host", secondary=group_host_association, back_populates="groups")

    # Domain / helper methods from class diagram
    def add_host(self, host: "Host") -> None:
        if host not in self.hosts:
            self.hosts.append(host)

    def remove_host(self, host: "Host") -> None:
        if host in self.hosts:
            self.hosts.remove(host)

    def get_hosts(self) -> list["Host"]:
        return self.hosts


class Host(Base):
    __tablename__ = "hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String, unique=True, nullable=False)
    ip_address = Column(String, nullable=False)
    os_type = Column(SQLEnum(OSType), nullable=False)
    os_version = Column(String)
    os_architecture = Column(String)
    api_key_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime)
    registered_at = Column(DateTime, default=datetime.utcnow)
    cached_scan_result = Column(JSON, nullable=True)
    cached_scan_at = Column(DateTime, nullable=True)

    # Relationships
    groups = relationship("Group", secondary=group_host_association, back_populates="hosts")
    hardware_info = relationship("HardwareInfo", back_populates="host", uselist=False, cascade="all, delete-orphan")
    software = relationship("Software", back_populates="host", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="host", cascade="all, delete-orphan")
    deployments = relationship("PatchDeployment", back_populates="host", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="target_host")

    # Domain / helper methods from class diagram
    def rotate_api_key(self) -> str:
        import secrets
        import hashlib
        new_key = secrets.token_urlsafe(32)
        self.api_key_hash = hashlib.sha256(new_key.encode()).hexdigest()
        return new_key

    def is_reachable(self) -> bool:
        if not self.is_active or not self.last_seen:
            return False
        return (datetime.utcnow() - self.last_seen).total_seconds() < 300


class Patch(Base):
    __tablename__ = "patches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    vendor = Column(String)
    os_type = Column(SQLEnum(OSType), nullable=False)
    severity = Column(String)
    cve_references = Column(JSON)  # List[str]
    ansible_playbook = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    deployments = relationship("PatchDeployment", back_populates="patch", cascade="all, delete-orphan")

    # Domain / helper methods from class diagram
    def is_applicable_to(self, host: Host) -> bool:
        return self.os_type == host.os_type


class PatchDeployment(Base):
    __tablename__ = "patch_deployments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patch_id = Column(UUID(as_uuid=True), ForeignKey("patches.id"), nullable=False)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("administrators.id"), nullable=True)
    status = Column(SQLEnum(PatchStatus), default=PatchStatus.PENDING, nullable=False)
    scheduled_at = Column(DateTime)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    ansible_job_id = Column(UUID(as_uuid=True), ForeignKey("ansible_jobs.id"), nullable=True)
    reboot_required = Column(Boolean, default=False)
    logs = Column(Text)

    # Relationships
    patch = relationship("Patch", back_populates="deployments")
    host = relationship("Host", back_populates="deployments")
    approver = relationship("Administrator", back_populates="approved_deployments")
    
    # Dual relationships for the circular AnsibleJob/PatchDeployment reference
    ansible_job = relationship("AnsibleJob", foreign_keys=[ansible_job_id], back_populates="deployment_ref")
    ansible_jobs_triggered = relationship("AnsibleJob", foreign_keys="AnsibleJob.deployment_id", back_populates="deployment")

    # Domain / helper methods from class diagram
    def approve(self, admin_id: uuid.UUID) -> None:
        self.approved_by = admin_id
        self.status = PatchStatus.PENDING

    def cancel(self) -> None:
        if self.status in [PatchStatus.PENDING, PatchStatus.IN_PROGRESS]:
            self.status = PatchStatus.FAILED

    def get_duration(self) -> int:
        if not self.started_at or not self.finished_at:
            return 0
        return int((self.finished_at - self.started_at).total_seconds())


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    launched_by = Column(UUID(as_uuid=True), ForeignKey("administrators.id", ondelete="SET NULL"), nullable=True)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.RUNNING, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    raw_output = Column(JSON)

    # Relationships
    host = relationship("Host", back_populates="scan_results")
    launcher = relationship("Administrator", back_populates="scans")
    software = relationship("Software", back_populates="scan", cascade="all, delete-orphan")
    hardware_info = relationship("HardwareInfo", back_populates="scan", cascade="all, delete-orphan")

    # Domain / helper methods from class diagram
    def get_duration(self) -> int:
        if not self.started_at or not self.finished_at:
            return 0
        return int((self.finished_at - self.started_at).total_seconds())

    def get_software_list(self) -> list["Software"]:
        return self.software


class Software(Base):
    __tablename__ = "software"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    version = Column(String)
    vendor = Column(String)
    install_date = Column(Date)
    package_manager = Column(String)

    # Relationships
    host = relationship("Host", back_populates="software")
    scan = relationship("ScanResult", back_populates="software")

    # Domain / helper methods from class diagram
    def has_known_cve(self) -> bool:
        return False


class HardwareInfo(Base):
    __tablename__ = "hardware_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    cpu_model = Column(String)
    cpu_cores = Column(Integer)
    ram_total_gb = Column(Float)
    ram_used_percent = Column(Float)
    disk_total_gb = Column(Float)
    disk_used_percent = Column(Float)
    updated_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    host = relationship("Host", back_populates="hardware_info")
    scan = relationship("ScanResult", back_populates="hardware_info")


class Administrator(Base):
    __tablename__ = "administrators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    approved_deployments = relationship("PatchDeployment", back_populates="approver")
    scans = relationship("ScanResult", back_populates="launcher")
    audit_logs = relationship("AuditLog", back_populates="user")

    # Domain / helper methods from class diagram
    def login(self, email: str, password_hash: str) -> str:
        return "jwt_token_placeholder"

    def logout(self) -> None:
        pass

    def generate_report(self) -> dict:
        return {"report": "summary"}


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("administrators.id", ondelete="SET NULL"), nullable=True)
    action = Column(SQLEnum(AuditAction), nullable=False)
    target_host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    status = Column(String)
    details = Column(JSON)
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("Administrator", back_populates="audit_logs")
    target_host = relationship("Host", back_populates="audit_logs")


class AnsibleJob(Base):
    __tablename__ = "ansible_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    deployment_id = Column(UUID(as_uuid=True), ForeignKey("patch_deployments.id", ondelete="CASCADE"), nullable=False)
    playbook = Column(Text)
    inventory_snapshot = Column(JSON)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    return_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)

    # Relationships
    deployment = relationship("PatchDeployment", foreign_keys=[deployment_id], back_populates="ansible_jobs_triggered")
    deployment_ref = relationship("PatchDeployment", foreign_keys=[PatchDeployment.ansible_job_id], back_populates="ansible_job")

    # Domain / helper methods from class diagram
    def run(self) -> None:
        self.started_at = datetime.utcnow()

    def get_status(self) -> PatchStatus:
        if self.return_code is None:
            return PatchStatus.IN_PROGRESS
        elif self.return_code == 0:
            return PatchStatus.SUCCESS
        else:
            return PatchStatus.FAILED