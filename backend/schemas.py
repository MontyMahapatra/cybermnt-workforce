from pydantic import BaseModel, ConfigDict, Field


class IngestEvent(BaseModel):
    type: str = Field(pattern="^(activity|heartbeat)$")
    timestamp: float
    device_id: str = Field(max_length=128)
    nonce: str = Field(max_length=64)
    idle_seconds: float | None = None
    is_idle: bool | None = None
    app_category: str | None = Field(default=None, pattern="^(productive|neutral|other|unknown)$")


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class EmployeeStatus(BaseModel):
    employee_id: str
    online: bool
    is_idle: bool | None
    last_seen: float | None
    active_alerts: int


class AlertOut(BaseModel):
    id: int
    employee_id: str
    alert_type: str
    severity: str
    message: str
    timestamp: float
    acknowledged: bool

    model_config = ConfigDict(from_attributes=True)
