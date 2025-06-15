from pydantic import BaseModel

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
