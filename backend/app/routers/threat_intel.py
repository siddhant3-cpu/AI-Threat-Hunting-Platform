from fastapi import APIRouter, HTTPException, Query
from ..enrichment.threat_intel import enrich_ioc

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

@router.get("/enrich")
async def enrich_indicator(ioc: str = Query(..., description="The indicator value (IP, domain, or MD5/SHA256 hash) to enrich")):
    if not ioc or not ioc.strip():
        raise HTTPException(status_code=400, detail="IOC value cannot be empty.")
        
    try:
        enriched_data = await enrich_ioc(ioc)
        return enriched_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to enrich indicator: {str(e)}")
