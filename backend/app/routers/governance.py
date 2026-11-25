"""口径治理接口：受控共享记录、共享批次、合并统计与原始记录受限回查。"""
from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.services.governance import (
    DEFAULT_SCOPE,
    default_operator_scopes,
    governance,
)

router = APIRouter(prefix="/api/governance", tags=["口径治理"])

SCOPE_HEADER = "X-Operator-Scopes"


class SharedRecordPayload(BaseModel):
    query_content: str
    query_user: str
    scope: str = DEFAULT_SCOPE
    period: str | None = None
    request_id: str | None = None
    query_time: str | None = None
    duration_ms: int | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    status: str | None = None


class BatchPayload(BaseModel):
    period: str
    scope: str = DEFAULT_SCOPE
    force_new: bool = False
    operator_scopes: list[str] | None = None


class MergePayload(BaseModel):
    batch_ids: list[int]
    operator_scopes: list[str] | None = None


def _operator_scopes(
    request: Request | None,
    declared: list[str] | None = None,
) -> set[str]:
    """解析操作者权限范围：显式声明或请求头；未声明视为改进小组可读全部共享数据。

    共享记录与统计本身就是脱敏后公开给改进小组的材料，读与合并不受范围限制；
    真正的边界在原始记录：只有原权限范围能回查（见 _raw_scopes）。
    """
    if declared:
        return {str(item).strip() for item in declared if str(item).strip()}
    header = request.headers.get(SCOPE_HEADER) if request is not None else None
    if header not in (None, ""):
        # HTTP 头只允许 ASCII，非 ASCII 范围名以 URL 编码传入。
        return default_operator_scopes(unquote(header))
    return {"*"}


def _raw_scopes(
    request: Request | None,
    declared: list[str] | None = None,
) -> set[str]:
    """原始记录授权：只认显式声明或请求头，未声明一律拒绝。"""
    if declared:
        return {str(item).strip() for item in declared if str(item).strip()}
    header = request.headers.get(SCOPE_HEADER) if request is not None else None
    if header not in (None, ""):
        return default_operator_scopes(unquote(header))
    return set()


@router.post("/records")
def register_record(payload: SharedRecordPayload) -> dict[str, Any]:
    """登记查询并返回脱敏共享记录；原始内容不对外返回。"""
    return governance.register_record(
        query_content=payload.query_content,
        query_user=payload.query_user,
        scope=payload.scope,
        period=payload.period,
        request_id=payload.request_id,
        query_time=payload.query_time,
        duration_ms=payload.duration_ms,
        params=payload.params,
        status=payload.status,
    )


@router.get("/records")
def list_records(
    request: Request,
    scope: str | None = Query(default=None),
    period: str | None = Query(default=None),
    include_receipts: bool = Query(default=True),
) -> dict[str, Any]:
    """改进小组可见的受控共享记录，不含查询原文、个人标识和实参。

    未授权范围一律不返回；跨范围仅返回脱敏后的模式字段，令牌互相不可关联。
    """
    operator = _operator_scopes(request)
    items = [
        item for item in governance.list_public_records(
            scope=scope, period=period, include_receipts=include_receipts)
        if governance._allows(operator, str(item.get("权限范围", DEFAULT_SCOPE)))
    ]
    return {"items": items, "total": len(items)}


@router.get("/records/{shared_id}")
def get_record(shared_id: str, request: Request) -> dict[str, Any]:
    for record in governance.list_public_records():
        if str(record.get("共享记录标识")) == str(shared_id):
            if not governance._allows(
                _operator_scopes(request), str(record.get("权限范围", DEFAULT_SCOPE))
            ):
                raise HTTPException(403, f"无权查看共享记录 {shared_id}")
            return record
    raise HTTPException(404, f"共享记录 {shared_id} 不存在")


@router.get("/stats")
def live_stats(
    request: Request,
    scope: str = Query(default=DEFAULT_SCOPE),
    period: str | None = Query(default=None),
) -> dict[str, Any]:
    """实时受控统计：模式频次与权限范围内可复核合计。"""
    view, message = governance.live_stats(
        scope=scope, period=period, operator_scopes=_operator_scopes(request)
    )
    if view is None:
        raise HTTPException(403, message)
    return view


@router.post("/stats/merge")
def merged_stats(
    payload: MergePayload,
    request: Request,
) -> dict[str, Any]:
    """合并多个已发出共享批次；仅同一权限范围内可关联同一查询者。"""
    view, message = governance.merged_stats(
        payload.batch_ids, _operator_scopes(request, declared=payload.operator_scopes)
    )
    if view is None:
        raise HTTPException(400, message)
    return view


@router.get("/batches")
def list_batches(
    request: Request,
    scope: str | None = Query(default=None),
    period: str | None = Query(default=None),
) -> dict[str, Any]:
    operator = _operator_scopes(request)
    items = [
        item for item in governance.list_batches(scope=scope, period=period)
        if governance._allows(operator, str(item["统计范围"]["权限范围"]))
    ]
    return {"items": items, "total": len(items)}


@router.post("/batches")
def create_batch(payload: BatchPayload, request: Request) -> dict[str, Any]:
    """发出共享批次：范围、口径与统计随批次固化，已发出批次不可改写。"""
    batch, message = governance.create_batch(
        period=payload.period,
        scope=payload.scope,
        operator_scopes=_operator_scopes(request, payload.operator_scopes),
        force_new=payload.force_new,
    )
    if batch is None:
        raise HTTPException(403, message)
    return {"ok": True, "message": message or "共享批次已发出", "batch": batch}


@router.get("/batches/{batch_id}")
def get_batch(batch_id: int, request: Request) -> dict[str, Any]:
    batch, message = governance.get_batch(batch_id, _operator_scopes(request))
    if batch is None:
        raise HTTPException(404, message)
    return batch


@router.get("/batches/{batch_id}/recheck")
def recheck_batch(batch_id: int, request: Request) -> dict[str, Any]:
    """复核已发出批次：只报告与当前数据的差异，不改写已发出统计。"""
    result, message = governance.recheck_batch(batch_id, _operator_scopes(request))
    if result is None:
        raise HTTPException(404, message)
    return result


@router.get("/raw/by-shared/{shared_id}")
def get_raw_by_shared(
    shared_id: str,
    request: Request,
) -> dict[str, Any]:
    """按共享记录标识回查原始记录；仅原权限范围可用。"""
    raw, message = governance.get_raw_by_shared_id(
        shared_id, _raw_scopes(request)
    )
    if raw is None:
        raise HTTPException(403, message)
    return raw


@router.get("/raw/{raw_id}")
def get_raw(
    raw_id: int,
    request: Request,
) -> dict[str, Any]:
    """原始记录只供原权限范围内回查；未声明权限一律拒绝。"""
    raw, message = governance.get_raw_record(raw_id, _raw_scopes(request))
    if raw is None:
        raise HTTPException(403, message)
    return raw
