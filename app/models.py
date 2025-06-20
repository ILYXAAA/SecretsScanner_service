from pydantic import BaseModel
from typing import List

class ScanRequest(BaseModel):
    ProjectName: str
    RepoUrl: str
    RefType: str  # Commit, Branch, Tag
    Ref: str
    CallbackUrl: str

class PATTokenRequest(BaseModel):
    token: str

class RulesContent(BaseModel):
    content: str

class MultiScanItem(BaseModel):
    ProjectName: str
    RepoUrl: str
    RefType: str
    Ref: str
    CallbackUrl: str

class MultiScanRequest(BaseModel):
    repositories: List[MultiScanItem]

class MultiScanResponseItem(BaseModel):
    ProjectName: str
    RefType: str
    Ref: str
    commit: str

class MultiScanResponse(BaseModel):
    status: str
    message: str
    data: List[MultiScanResponseItem]

class LocalScanRequest(BaseModel):
    ProjectName: str
    RepoUrl: str
    CallbackUrl: str