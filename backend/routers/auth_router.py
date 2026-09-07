from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from database import get_db
from models import DashboardUser
from schemas import LoginRequest, TokenResponse
from security import verify_password, create_access_token, append_audit_log
from rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(DashboardUser).filter_by(username=req.username).first()

    # Constant-shape response whether the user exists or the password is
    # wrong -- don't leak which one via timing or message differences.
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    token = create_access_token(subject=user.username, role=user.role.value)
    append_audit_log(db, actor=user.username, action="login")
    return TokenResponse(access_token=token, role=user.role.value)
