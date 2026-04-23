"""Security audit logging.

Features:
- All authentication attempts
- Command execution
- File access
- Security violations
"""

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import structlog

# from src.exceptions import SecurityError  # Future use

if TYPE_CHECKING:
    from src.storage.models import AuditLogModel
    from src.storage.repositories import AuditLogRepository

logger = structlog.get_logger()


@dataclass
class AuditEvent:
    """Security audit event."""

    timestamp: datetime
    user_id: int
    event_type: str
    success: bool
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    risk_level: str = "low"  # low, medium, high, critical

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/logging."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditStorage:
    """Abstract interface for audit event storage."""

    async def store_event(self, event: AuditEvent) -> None:
        """Store audit event."""
        raise NotImplementedError

    async def get_events(
        self,
        user_id: Optional[int] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Retrieve audit events with filters."""
        raise NotImplementedError

    async def get_security_violations(
        self, user_id: Optional[int] = None, limit: int = 100
    ) -> List[AuditEvent]:
        """Get security violations."""
        raise NotImplementedError


class InMemoryAuditStorage(AuditStorage):
    """In-memory audit storage for development/testing."""

    def __init__(self, max_events: int = 10000):
        self.events: List[AuditEvent] = []
        self.max_events = max_events

    async def store_event(self, event: AuditEvent) -> None:
        """Store event in memory."""
        self.events.append(event)

        # Trim old events if we exceed limit
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events :]

        # Log high-risk events immediately
        if event.risk_level in ["high", "critical"]:
            logger.warning(
                "High-risk security event",
                event_type=event.event_type,
                user_id=event.user_id,
                risk_level=event.risk_level,
                details=event.details,
            )

    async def get_events(
        self,
        user_id: Optional[int] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get filtered events."""
        filtered_events = self.events

        # Apply filters
        if user_id is not None:
            filtered_events = [e for e in filtered_events if e.user_id == user_id]

        if event_type is not None:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]

        if start_time is not None:
            filtered_events = [e for e in filtered_events if e.timestamp >= start_time]

        if end_time is not None:
            filtered_events = [e for e in filtered_events if e.timestamp <= end_time]

        # Sort by timestamp (newest first) and limit
        filtered_events.sort(key=lambda e: e.timestamp, reverse=True)
        return filtered_events[:limit]

    async def get_security_violations(
        self, user_id: Optional[int] = None, limit: int = 100
    ) -> List[AuditEvent]:
        """Get security violations."""
        return await self.get_events(
            user_id=user_id, event_type="security_violation", limit=limit
        )


class SQLiteAuditStorage(AuditStorage):
    """Durable SQLite-backed audit storage.

    Forensic evidence must survive a process restart — especially because
    the threat model for this bot includes a compromised user coercing
    Claude into killing the process (thereby erasing any in-memory log).
    This implementation writes every event to the ``audit_log`` table via
    the existing :class:`AuditLogRepository`, and lifts the
    ``details`` / ``session_id`` / ``risk_level`` fields from
    :class:`AuditEvent` into the ``event_data`` JSON column.
    """

    def __init__(self, repository: "AuditLogRepository") -> None:
        self.repository = repository

    def _event_to_model(self, event: AuditEvent) -> "AuditLogModel":
        """Translate ``AuditEvent`` into the storage-layer ``AuditLogModel``.

        ``AuditLogModel`` does not have a native place for session_id or
        risk_level, so both are folded into ``event_data`` under a
        single ``_meta`` sub-dict to avoid collision with caller keys.
        Review feedback: the previous ``_session_id`` / ``_risk_level``
        top-level keys could be silently overwritten by a caller passing
        ``details={"_session_id": "spoofed"}``; the nested ``_meta``
        namespace removes that footgun without growing the schema.
        """
        # Import here to avoid a circular import at module load time.
        from src.storage.models import AuditLogModel

        event_data: Dict[str, Any] = dict(event.details or {})
        event_data["_meta"] = {
            "session_id": event.session_id,
            "risk_level": event.risk_level,
        }

        return AuditLogModel(
            user_id=event.user_id,
            event_type=event.event_type,
            timestamp=event.timestamp,
            event_data=event_data,
            success=event.success,
            ip_address=event.ip_address,
        )

    def _model_to_event(self, model: "AuditLogModel") -> AuditEvent:
        """Reverse of :meth:`_event_to_model` for read paths."""
        event_data = dict(model.event_data or {})
        # Back-compat read path — accept both the new nested
        # ``_meta`` dict and the pre-fix flat ``_session_id`` /
        # ``_risk_level`` keys. Rows written by an earlier version
        # of SQLiteAuditStorage must still be deserialisable after
        # this upgrade.
        meta = event_data.pop("_meta", None)
        if isinstance(meta, dict):
            session_id = meta.get("session_id")
            risk_level = meta.get("risk_level") or "low"
        else:
            session_id = event_data.pop("_session_id", None)
            risk_level = event_data.pop("_risk_level", "low") or "low"

        return AuditEvent(
            timestamp=model.timestamp,
            user_id=model.user_id,
            event_type=model.event_type,
            success=bool(model.success),
            details=event_data,
            ip_address=model.ip_address,
            session_id=session_id,
            risk_level=risk_level,
        )

    async def store_event(self, event: AuditEvent) -> None:
        """Persist the event and warn on high-risk writes."""
        await self.repository.log_event(self._event_to_model(event))

        if event.risk_level in ("high", "critical"):
            logger.warning(
                "High-risk security event",
                event_type=event.event_type,
                user_id=event.user_id,
                risk_level=event.risk_level,
                details=event.details,
            )

    async def get_events(
        self,
        user_id: Optional[int] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Query events with all filters applied in SQL."""
        models = await self.repository.query(
            user_id=user_id,
            event_type=event_type,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
        return [self._model_to_event(m) for m in models]

    async def get_security_violations(
        self, user_id: Optional[int] = None, limit: int = 100
    ) -> List[AuditEvent]:
        """Return recent security-violation events (newest first)."""
        return await self.get_events(
            user_id=user_id, event_type="security_violation", limit=limit
        )


class AuditLogger:
    """Security audit logger."""

    def __init__(self, storage: AuditStorage):
        self.storage = storage
        logger.info("Audit logger initialized")

    async def log_auth_attempt(
        self,
        user_id: int,
        success: bool,
        method: str,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log authentication attempt."""
        risk_level = "medium" if not success else "low"

        event = AuditEvent(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            event_type="auth_attempt",
            success=success,
            details={"method": method, "reason": reason},
            ip_address=ip_address,
            risk_level=risk_level,
        )

        await self.storage.store_event(event)

        logger.info(
            "Authentication attempt logged",
            user_id=user_id,
            method=method,
            success=success,
            reason=reason,
        )

    async def log_session_event(
        self,
        user_id: int,
        action: str,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log session-related events."""
        event = AuditEvent(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            event_type="session",
            success=success,
            details={"action": action, **(details or {})},
            risk_level="low",
        )

        await self.storage.store_event(event)

    async def log_command(
        self,
        user_id: int,
        command: str,
        args: List[str],
        success: bool,
        working_directory: Optional[str] = None,
        execution_time: Optional[float] = None,
        exit_code: Optional[int] = None,
    ) -> None:
        """Log command execution."""
        # Determine risk level based on command
        risk_level = self._assess_command_risk(command, args)

        event = AuditEvent(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            event_type="command",
            success=success,
            details={
                "command": command,
                "args": args[:10],  # Limit args for storage
                "working_directory": working_directory,
                "execution_time": execution_time,
                "exit_code": exit_code,
            },
            risk_level=risk_level,
        )

        await self.storage.store_event(event)

        logger.info(
            "Command execution logged",
            user_id=user_id,
            command=command,
            success=success,
            risk_level=risk_level,
        )

    async def log_file_access(
        self,
        user_id: int,
        file_path: str,
        action: str,  # read, write, delete, create
        success: bool,
        file_size: Optional[int] = None,
    ) -> None:
        """Log file access."""
        # Assess risk based on file path and action
        risk_level = self._assess_file_access_risk(file_path, action)

        event = AuditEvent(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            event_type="file_access",
            success=success,
            details={"file_path": file_path, "action": action, "file_size": file_size},
            risk_level=risk_level,
        )

        await self.storage.store_event(event)

    async def log_security_violation(
        self,
        user_id: int,
        violation_type: str,
        details: str,
        severity: str = "medium",
        attempted_action: Optional[str] = None,
    ) -> None:
        """Log security violation."""
        # Map severity to risk level
        risk_mapping = {"low": "medium", "medium": "high", "high": "critical"}
        risk_level = risk_mapping.get(severity, "high")

        event = AuditEvent(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            event_type="security_violation",
            success=False,  # Security violations are always failures
            details={
                "violation_type": violation_type,
                "details": details,
                "severity": severity,
                "attempted_action": attempted_action,
            },
            risk_level=risk_level,
        )

        await self.storage.store_event(event)

        logger.warning(
            "Security violation logged",
            user_id=user_id,
            violation_type=violation_type,
            severity=severity,
            details=details,
        )

    async def log_rate_limit_exceeded(
        self,
        user_id: int,
        limit_type: str,  # request, cost
        current_usage: float,
        limit_value: float,
    ) -> None:
        """Log rate limit exceeded."""
        event = AuditEvent(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            event_type="rate_limit_exceeded",
            success=False,
            details={
                "limit_type": limit_type,
                "current_usage": current_usage,
                "limit_value": limit_value,
                "utilization": current_usage / limit_value if limit_value > 0 else 0,
            },
            risk_level="low",
        )

        await self.storage.store_event(event)

    def _assess_command_risk(self, command: str, args: List[str]) -> str:
        """Assess risk level of command execution."""
        high_risk_commands = {
            "rm",
            "del",
            "delete",
            "format",
            "fdisk",
            "dd",
            "chmod",
            "chown",
            "sudo",
            "su",
            "passwd",
            "curl",
            "wget",
            "ssh",
            "scp",
            "rsync",
        }

        medium_risk_commands = {
            "git",
            "npm",
            "pip",
            "docker",
            "kubectl",
            "make",
            "cmake",
            "gcc",
            "python",
            "node",
        }

        command_lower = command.lower()

        if any(risky in command_lower for risky in high_risk_commands):
            return "high"
        elif any(risky in command_lower for risky in medium_risk_commands):
            return "medium"
        else:
            return "low"

    def _assess_file_access_risk(self, file_path: str, action: str) -> str:
        """Assess risk level of file access."""
        sensitive_paths = [
            "/etc/",
            "/var/",
            "/usr/",
            "/sys/",
            "/proc/",
            "/.env",
            "/.ssh/",
            "/.aws/",
            "/secrets/",
            "config",
            "password",
            "key",
            "token",
        ]

        risky_actions = {"delete", "write"}

        path_lower = file_path.lower()

        # High risk: sensitive paths with write/delete
        if action in risky_actions and any(
            sensitive in path_lower for sensitive in sensitive_paths
        ):
            return "high"

        # Medium risk: any sensitive path access or risky actions
        if (
            any(sensitive in path_lower for sensitive in sensitive_paths)
            or action in risky_actions
        ):
            return "medium"

        return "low"

    async def get_user_activity_summary(
        self, user_id: int, hours: int = 24
    ) -> Dict[str, Any]:
        """Get activity summary for user."""
        start_time = datetime.now(UTC) - timedelta(hours=hours)
        events = await self.storage.get_events(
            user_id=user_id, start_time=start_time, limit=1000
        )

        # Aggregate statistics
        summary: Dict[str, Any] = {
            "user_id": user_id,
            "period_hours": hours,
            "total_events": len(events),
            "event_types": {},
            "risk_levels": {},
            "success_rate": 0,
            "security_violations": 0,
            "last_activity": None,
        }

        if events:
            summary["last_activity"] = events[0].timestamp.isoformat()

            successful_events = 0
            for event in events:
                # Count by type
                event_type = event.event_type
                summary["event_types"][event_type] = (
                    summary["event_types"].get(event_type, 0) + 1
                )

                # Count by risk level
                risk_level = event.risk_level
                summary["risk_levels"][risk_level] = (
                    summary["risk_levels"].get(risk_level, 0) + 1
                )

                # Count successes
                if event.success:
                    successful_events += 1

                # Count security violations
                if event.event_type == "security_violation":
                    summary["security_violations"] += 1

            summary["success_rate"] = successful_events / len(events)

        return summary

    async def get_security_dashboard(self) -> Dict[str, Any]:
        """Get security dashboard data."""
        # Get recent events (last 24 hours)
        start_time = datetime.now(UTC) - timedelta(hours=24)
        recent_events = await self.storage.get_events(start_time=start_time, limit=1000)

        # Get security violations
        violations = await self.storage.get_security_violations(limit=100)

        dashboard: Dict[str, Any] = {
            "period": "24_hours",
            "total_events": len(recent_events),
            "security_violations": len(violations),
            "active_users": len(set(e.user_id for e in recent_events)),
            "risk_distribution": {},
            "top_violation_types": {},
            "authentication_failures": 0,
        }

        # Analyze events
        for event in recent_events:
            # Risk distribution
            risk = event.risk_level
            dashboard["risk_distribution"][risk] = (
                dashboard["risk_distribution"].get(risk, 0) + 1
            )

            # Authentication failures
            if event.event_type == "auth_attempt" and not event.success:
                dashboard["authentication_failures"] += 1

        # Analyze violations
        for violation in violations:
            violation_type = violation.details.get("violation_type", "unknown")
            dashboard["top_violation_types"][violation_type] = (
                dashboard["top_violation_types"].get(violation_type, 0) + 1
            )

        return dashboard
