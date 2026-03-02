from fastapi import APIRouter
router = APIRouter(prefix="/reports")
@router.get("")
async def placeholder():
    return {"status": "module coming in Phase 2"}
