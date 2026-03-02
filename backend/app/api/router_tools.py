from fastapi import APIRouter
router = APIRouter(prefix="/tools")
@router.get("")
async def placeholder():
    return {"status": "module coming in Phase 2"}
