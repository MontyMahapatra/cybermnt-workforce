from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database import get_db
from models import DashboardUser
from security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> DashboardUser:
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")

    user = db.query(DashboardUser).filter_by(username=payload["sub"]).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer exists")

    # Re-check the role against the DB rather than trusting the JWT claim
    # alone -- a role change (e.g. someone demoted) takes effect immediately
    # instead of waiting for token expiry.
    if user.role.value != payload.get("role"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token role stale, please re-login")

    return user


def require_role(*allowed_roles: str):
    def checker(user: DashboardUser = Depends(get_current_user)) -> DashboardUser:
        if user.role.value not in allowed_roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user.role.value}' is not permitted to access this resource",
            )
        return user
    return checker
