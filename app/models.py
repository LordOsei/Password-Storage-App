from pydantic import BaseModel, Field


class SecretCreate(BaseModel):
    site: str = Field(min_length=1, max_length=200)
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1)
    notes: str = Field(default="", max_length=256)


class SecretUpdate(BaseModel):
    site: str = Field(min_length=1, max_length=200)
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(default="")
    notes: str = Field(default="", max_length=256)


class SecretSummary(BaseModel):
    id: str
    site: str
    username: str
    notes: str
    created_at: str
