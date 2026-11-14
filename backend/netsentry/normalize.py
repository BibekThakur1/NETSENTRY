from datetime import datetime, timezone
from ipaddress import ip_address
from pydantic import BaseModel, Field, field_validator, ConfigDict

TYPES = {'login_failed','login_success','connection','traffic','privilege_change','zeek_conn','zeek_dns','zeek_http','zeek_ssl'}

class EventInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    timestamp: datetime
    source_ip: str
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=20)
    duration: float | None = Field(default=None, ge=0)
    connection_uid: str | None = Field(default=None, max_length=100)
    hostname: str | None = Field(default=None, max_length=255)
    query: str | None = Field(default=None, max_length=500)
    source_format: str = Field(default='generic', max_length=30)
    raw_event: dict | None = None
    event_type: str
    username: str | None = Field(default=None, max_length=100)
    bytes_transferred: int = Field(default=0, ge=0)
    details: str | None = Field(default=None, max_length=2000)

    @field_validator('timestamp')
    @classmethod
    def valid_time(cls, v):
        if v.tzinfo is None: raise ValueError('timestamp must include timezone')
        return v.astimezone(timezone.utc)

    @field_validator('source_ip','destination_ip')
    @classmethod
    def valid_ip(cls, v):
        if v is not None: ip_address(v)
        return v

    @field_validator('event_type')
    @classmethod
    def valid_type(cls, v):
        if v not in TYPES: raise ValueError(f'event_type must be one of {sorted(TYPES)}')
        return v
