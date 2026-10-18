from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ConditionNode(BaseModel):
    """A bounded, data-only rule condition tree.

    Logical nodes use ``op`` (or the accepted JSON alias ``type``) and
    ``conditions``. Leaf nodes use a field, an allow-listed operator, and a
    literal value. No expression language is accepted.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    op: str | None = None
    type_: str | None = Field(default=None, alias="type")
    conditions: list["ConditionNode"] | None = None
    children: list["ConditionNode"] | None = None
    field: str | None = None
    operator: str | None = None
    value: Any = None

    @field_validator("op", "type_", mode="before")
    @classmethod
    def normalize_op(cls, value: Any) -> Any:
        return value.lower().strip() if isinstance(value, str) else value

    @field_validator("operator", mode="before")
    @classmethod
    def normalize_operator(cls, value: Any) -> Any:
        return value.lower().strip() if isinstance(value, str) else value

    @field_validator("field")
    @classmethod
    def validate_field(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        if not value or len(value) > 100 or not all(ch.isalnum() or ch in "._-" for ch in value):
            raise ValueError("condition field contains unsupported characters")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> "ConditionNode":
        child_nodes = self.conditions if self.conditions is not None else self.children
        operator_lower = (self.operator or "").lower()
        logical = (self.op or self.type_ or (operator_lower if child_nodes and operator_lower in {"and", "or"} else "")).lower()
        if logical:
            if logical not in {"and", "or"}:
                raise ValueError("condition logical operator must be AND or OR")
            if not child_nodes or len(child_nodes) > 100:
                raise ValueError("logical condition requires between 1 and 100 children")
            if self.field is not None or (self.operator is not None and operator_lower not in {"and", "or"}):
                raise ValueError("logical condition cannot also be a leaf")
        else:
            if not self.field or self.operator not in {"equals", "not_equals", "contains", "starts_with", "gt", "gte", "lt", "lte", "within_minutes"}:
                raise ValueError("leaf condition requires field and operator")
            if child_nodes:
                raise ValueError("leaf condition cannot have children")
        return self


ConditionNode.model_rebuild()


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str = Field(min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool = True
    condition: ConditionNode | None = None
    condition_tree: ConditionNode | None = None
    tags: list[str] = Field(default_factory=list, max_length=30)

    @model_validator(mode="after")
    def choose_condition(self) -> "RuleCreate":
        if self.condition is None and self.condition_tree is None:
            raise ValueError("condition is required")
        if self.condition is not None and self.condition_tree is not None:
            raise ValueError("provide condition once")
        return self


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool | None = None
    condition: ConditionNode | None = None
    condition_tree: ConditionNode | None = None
    tags: list[str] | None = Field(default=None, max_length=30)

    @model_validator(mode="after")
    def choose_condition(self) -> "RuleUpdate":
        if self.condition is not None and self.condition_tree is not None:
            raise ValueError("provide condition once")
        return self


class RuleTestRequest(BaseModel):
    event_ids: list[int] | None = Field(default=None, max_length=1000)


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    title: str | None = Field(default=None, min_length=1, max_length=240)
    name: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=10000)
    status: str = Field(default="open", max_length=40)
    priority: str = Field(default="medium", max_length=40)
    assignee: str | None = Field(default=None, max_length=160)
    metadata: dict[str, Any] = Field(default_factory=dict)
    indicators: list[str] = Field(default_factory=list, max_length=1000)
    vulnerability_ids: list[str] = Field(default_factory=list, max_length=1000)
    analyst_notes: str | None = Field(default=None, max_length=20000)
    asset_ids: list[int] = Field(default_factory=list, max_length=1000)
    event_ids: list[int] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def require_title(self) -> "CaseCreate":
        if not (self.title or self.name):
            raise ValueError("title or name is required")
        return self


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    title: str | None = Field(default=None, min_length=1, max_length=240)
    name: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=10000)
    status: str | None = Field(default=None, max_length=40)
    priority: str | None = Field(default=None, max_length=40)
    assignee: str | None = Field(default=None, max_length=160)
    metadata: dict[str, Any] | None = None
    indicators: list[str] | None = Field(default=None, max_length=1000)
    vulnerability_ids: list[str] | None = Field(default=None, max_length=1000)
    analyst_notes: str | None = Field(default=None, max_length=20000)
    asset_ids: list[int] | None = Field(default=None, max_length=1000)
    event_ids: list[int] | None = Field(default=None, max_length=1000)


class CaseNoteCreate(BaseModel):
    detail: str = Field(min_length=1, max_length=20000)
    actor: str | None = Field(default=None, max_length=160)


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str = Field(min_length=1, max_length=240)
    hostname: str | None = Field(default=None, max_length=255)
    ip: str | None = Field(default=None, max_length=255)
    kind: str | None = Field(default=None, max_length=100)
    risk: str | None = Field(default=None, max_length=40)
    status: str | None = Field(default=None, max_length=80)
    operating_system: str | None = Field(default=None, max_length=160)
    owner: str | None = Field(default=None, max_length=160)
    software: list[dict[str, Any]] | dict[str, Any] | None = None
    last_assessment_date: str | None = Field(default=None, max_length=80)
    notes: str | None = Field(default=None, max_length=10000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=240)
    hostname: str | None = Field(default=None, max_length=255)
    ip: str | None = Field(default=None, max_length=255)
    kind: str | None = Field(default=None, max_length=100)
    risk: str | None = Field(default=None, max_length=40)
    status: str | None = Field(default=None, max_length=80)
    operating_system: str | None = Field(default=None, max_length=160)
    owner: str | None = Field(default=None, max_length=160)
    software: list[dict[str, Any]] | dict[str, Any] | None = None
    last_assessment_date: str | None = Field(default=None, max_length=80)
    notes: str | None = Field(default=None, max_length=10000)
    metadata: dict[str, Any] | None = None


class AssetAssessmentRequest(BaseModel):
    """A deliberately narrow, explicitly authorized passive assessment."""

    kind: str = Field(pattern="^(tcp|http)$")
    confirm_authorized: bool = False
    port: int | None = Field(default=None, ge=1, le=65535)
    timeout_seconds: float = Field(default=3.0, gt=0.1, le=10.0)

    @model_validator(mode="after")
    def validate_request(self) -> "AssetAssessmentRequest":
        if not self.confirm_authorized:
            raise ValueError("explicit authorization confirmation is required")
        if self.kind == "tcp" and self.port is None:
            raise ValueError("a TCP assessment requires one explicit port")
        if self.kind == "http" and self.port is not None and self.port not in {80, 443, 8080, 8443}:
            raise ValueError("HTTP assessment ports must be 80, 443, 8080, or 8443")
        return self


class IndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    indicator: str | None = Field(default=None, max_length=4096)
    value: str | None = Field(default=None, max_length=4096)
    query: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def pick_indicator(self) -> "IndicatorRequest":
        if not (self.indicator or self.value or self.query):
            raise ValueError("indicator is required")
        return self

    def selected(self) -> str:
        return (self.indicator or self.value or self.query or "").strip()
