"""口径治理共享日志服务：把查询原文与用户标识转换成改进小组可用的受控统计记录。

设计要点：
- 原始记录（查询内容、查询用户、实参）只留在服务内部，仅允许原权限范围回查；
- 对外只暴露脱敏记录：结构化的查询模式、可复核的慢查类别、按范围加盐的查询者/请求令牌；
- 同一统计范围（权限范围 + 查询模式）内的结构相同查询汇入同一类，类型频率按实际请求去重；
- 同请求的重复回执保留为可见记录但不计入频次，避免同一请求被重复统计；
- 共享批次是发出时的不可变快照，范围与原统计口径随批次固化，后续权限或数据变化
  不会改写已发出批次的统计；
- 跨批次合并只在同一权限范围内可关联同一查询者，跨范围令牌不同，无法关联个人。
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime
from typing import Any

# 与查询日志模块保持一致的慢查阈值（毫秒）。
SLOW_THRESHOLD_MS = 3000
DEFAULT_SCOPE = "default"

# 统计口径：随批次固化，保证旧批次的范围与原始口径可追。
CALIBER: dict[str, Any] = {
    "规则版本": "governance-share-v1",
    "脱敏规则": "查询中的字符串、数字、日期、邮箱、手机号、IP、UUID 及用户标识字面量替换为 ?；"
                "用户标识与请求标识以范围级 HMAC 令牌代替",
    "模式归一化": "统一小写与空白；忽略字面量差异，仅保留查询结构",
    "统计键": ["权限范围", "模式标识"],
    "去重键": ["权限范围", "请求标识原文"],
    "慢查阈值_ms": SLOW_THRESHOLD_MS,
    "耗时分桶": ["<1s", "1-3s", "3-10s", "≥10s"],
    "可复核字段": ["共享记录标识", "请求标识", "查询模式", "慢查类别", "是否慢查", "耗时区间"],
}

_PERIOD_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_QUOTED_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[\w.-]+\b")
_PHONE_RE = re.compile(r"\b1[3-9]\d{9}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_USER_TOKEN_RE = re.compile(
    r"\b(?:username|account|member|buyer|payer|openid)"
    r"(?:[_:=-][a-zA-Z0-9_-]+|_\d+)(?!\s*=)\b", re.I
)
_ID_EQ_RE = re.compile(
    r"\b((?:username|account|member|buyer|payer|openid)(?:[a-z_]*_id)?(?:_?id)?|user_?id|uid|user|acct)"
    r"\s*=\s*([^\s,;)]+)", re.I
)


def _keep_column_drop_value(match: re.Match[str]) -> str:
    """保留列名，只去掉等号后的个人标识值。"""
    return f"{match.group(1)} = ?"


_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_WS_RE = re.compile(r"\s+")


def _scope_salt(secret: bytes, scope: str) -> bytes:
    return hmac.new(secret, f"scope|{scope}".encode("utf-8"), hashlib.sha256).digest()


def _token(secret: bytes, scope: str, kind: str, value: str) -> str:
    digest = hmac.new(
        _scope_salt(secret, scope), f"{kind}|{value}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return digest[:12]


def hash_pattern(template: str) -> str:
    return "M-" + hashlib.sha256(template.encode("utf-8")).hexdigest()[:12]


def sanitize_query(query: str, secret: bytes, scope: str, user: str = "") -> dict[str, Any]:
    """把查询原文归一化为可公开的查询模式，并统计被移除的个人标识/实参。"""
    text = str(query or "")
    removed = {
        "字符串实参": 0,
        "邮箱": 0,
        "手机号": 0,
        "身份证或UUID": 0,
        "IP地址": 0,
        "日期实参": 0,
        "数字实参": 0,
        "用户标识": 0,
    }

    # 查询者列等号后的取值先替换，保留列名，便于复核时看懂结构。
    removed["用户标识"] += len(_ID_EQ_RE.findall(text))
    text = _ID_EQ_RE.sub(_keep_column_drop_value, text)

    # 再按语义移除可识别的个人标识/实参，最后兜底移除其余字符串字面量。
    for key, frame in (
        ("邮箱", _EMAIL_RE),
        ("手机号", _PHONE_RE),
        ("身份证或UUID", _UUID_RE),
        ("IP地址", _IP_RE),
        ("用户标识", _USER_TOKEN_RE),
        ("日期实参", _DATE_RE),
        ("数字实参", _NUMBER_RE),
    ):
        def _drop(match: re.Match[str], key: str = key) -> str:
            removed[key] += 1
            return " ? "
        text = frame.sub(_drop, text)

    def _drop_quoted(match: re.Match[str]) -> str:
        removed["字符串实参"] += 1
        return " ? "

    text = _QUOTED_RE.sub(_drop_quoted, text)

    template = _WS_RE.sub(" ", text).strip().lower().rstrip(";").strip()
    return {
        "查询模式": template,
        "模式标识": hash_pattern(template),
        "查询者令牌": "P-" + _token(secret, scope, "person", str(user)) if user else "",
        "移除统计": removed,
    }


def classify_slow(query_template: str, is_slow: bool) -> str:
    """给出可复核的慢查类别：慢/常规 + 结构特征，复核者据模式即可复算。"""
    template = str(query_template).lower()
    if " join " in template or template.startswith("join"):
        feature = "多表关联"
    elif "group by" in template:
        feature = "聚合统计"
    elif "order by" in template:
        feature = "排序输出"
    elif " where " in template:
        feature = "条件过滤"
    else:
        feature = "单表查询"
    return f"{'慢查' if is_slow else '常规'}·{feature}"


def duration_bucket(ms: int) -> str:
    if ms < 1000:
        return "<1s"
    if ms < 3000:
        return "1-3s"
    if ms < 10000:
        return "3-10s"
    return "≥10s"


def caliber_fingerprint() -> str:
    return hashlib.sha256(
        json.dumps(CALIBER, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]


def parse_duration_ms(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    match = re.search(r"\d+", str(value))
    return int(match.group()) if match else 0


def parse_period(value: Any, fallback: str | None = None) -> str:
    match = _PERIOD_RE.search(str(value or ""))
    if match:
        return match.group(0)
    if fallback:
        match = _PERIOD_RE.search(str(fallback))
        if match:
            return match.group(0)
    return datetime.now().strftime("%Y-%m-%d")


def compute_stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    """根据受控记录计算模式频次与可复核合计；类型频率按实际请求去重。"""
    counted = [r for r in records if r.get("计入统计", True)]
    receipts = [r for r in records if not r.get("计入统计", True)]

    seen_requests: set[tuple[str, str]] = set()
    unique_records: list[dict[str, Any]] = []
    duplicate_count = 0
    for record in counted:
        key = (str(record.get("权限范围", DEFAULT_SCOPE)), str(record.get("请求标识", "")))
        if key in seen_requests:
            duplicate_count += 1
            continue
        seen_requests.add(key)
        unique_records.append(record)

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in unique_records:
        groups.setdefault(
            (str(record.get("权限范围", DEFAULT_SCOPE)), str(record.get("模式标识", ""))), []
        ).append(record)

    pattern_rows: list[dict[str, Any]] = []
    review_items: list[dict[str, Any]] = []
    for (scope, pattern_key), members in groups.items():
        members = sorted(
            members,
            key=lambda item: (str(item.get("统计周期", "")), str(item.get("请求标识", ""))),
        )
        token_counts: dict[str, int] = {}
        token_periods: dict[str, set[str]] = {}
        for member in members:
            token = str(member.get("查询者令牌", ""))
            token_counts[token] = token_counts.get(token, 0) + 1
            token_periods.setdefault(token, set()).add(str(member.get("统计周期", "")))
        repeated_tokens = {token for token, count in token_counts.items() if token and count >= 2}
        cross_period_tokens = {
            token for token, periods in token_periods.items() if token and len(periods) >= 2
        }
        repeated_slow = sum(
            1 for member in members
            if member.get("是否慢查") == "是"
            and str(member.get("查询者令牌", "")) in repeated_tokens
        )
        cross_period_slow = sum(
            1 for member in members
            if member.get("是否慢查") == "是"
            and str(member.get("查询者令牌", "")) in cross_period_tokens
        )
        slow_count = sum(1 for member in members if member.get("是否慢查") == "是")
        pattern_rows.append({
            "权限范围": scope,
            "模式标识": pattern_key,
            "查询模式": members[0].get("查询模式", ""),
            "慢查类别": "/".join(sorted({
                str(member.get("慢查类别", "")) for member in members if member.get("慢查类别")
            })),
            "请求频次": len(members),
            "慢查频次": slow_count,
            "查询者数": len([token for token in token_counts if token]),
            "重复查询者数": len(repeated_tokens),
            "重复慢查请求数": repeated_slow,
            "跨期查询者数": len(cross_period_tokens),
            "跨期重复慢查请求数": cross_period_slow,
            "涉及周期": sorted({str(member.get("统计周期", "")) for member in members}),
            "复核请求标识": [str(member.get("请求标识", "")) for member in members],
        })
        for member in members:
            review_items.append({
                "共享记录标识": member.get("共享记录标识"),
                "请求标识": member.get("请求标识"),
                "统计周期": member.get("统计周期"),
                "权限范围": scope,
                "模式标识": pattern_key,
                "查询模式": member.get("查询模式"),
                "慢查类别": member.get("慢查类别"),
                "是否慢查": member.get("是否慢查"),
                "耗时区间": member.get("耗时区间"),
                "查询者令牌": member.get("查询者令牌"),
            })

    pattern_rows.sort(key=lambda row: (-row["请求频次"], row["权限范围"], row["模式标识"]))
    slow_total = sum(1 for record in unique_records if record.get("是否慢查") == "是")
    duration_total = sum(int(record.get("执行耗时_ms") or 0) for record in unique_records)
    return {
        "记录数": len(records),
        "去重请求数": len(unique_records),
        "重复回执剔除数": len(receipts) + duplicate_count,
        "慢查请求数": slow_total,
        "模式合计": len(pattern_rows),
        "查询者合计": len(
            {str(r.get("查询者令牌", "")) for r in unique_records if r.get("查询者令牌")}
        ),
        "耗时合计_ms": duration_total,
        "模式频次": pattern_rows,
        "复核清单": review_items,
        "重复回执清单": [
            {
                "共享记录标识": receipt.get("共享记录标识"),
                "请求标识": receipt.get("请求标识"),
                "统计周期": receipt.get("统计周期"),
                "首次共享记录标识": receipt.get("首次共享记录标识"),
            }
            for receipt in receipts
        ],
    }


class GovernanceService:
    """受控日志与共享批次的持有者；原始数据永不进入公开输出。"""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret
        self._raw: list[dict[str, Any]] = []
        self._public: list[dict[str, Any]] = []
        self._batches: list[dict[str, Any]] = []
        self._request_index: dict[tuple[str, str], dict[str, Any]] = {}
        self._raw_seq = 0
        self._public_seq = 0
        self._batch_seq = 0

    # ---------- 原始记录 → 受控共享记录 ----------
    def register_record(
        self,
        *,
        query_content: str,
        query_user: str,
        scope: str = DEFAULT_SCOPE,
        period: str | None = None,
        request_id: str | None = None,
        query_time: str | None = None,
        duration_ms: int | str | None = None,
        params: dict[str, Any] | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        """登记一次实际查询请求，返回脱敏记录；同请求的重复回执不计入频次。"""
        scope = str(scope or DEFAULT_SCOPE)
        query_time = query_time or datetime.now().isoformat()
        period = parse_period(period, fallback=query_time)
        duration_ms = parse_duration_ms(duration_ms)
        is_slow = str(status or "") == "慢查询" or duration_ms > SLOW_THRESHOLD_MS
        request_id = str(request_id or f"auto-{uuid.uuid4().hex[:12]}")
        request_token = "R-" + _token(self._secret, scope, "request", request_id)
        sanitized = sanitize_query(query_content, self._secret, scope, query_user)

        first = self._request_index.get((scope, request_id))
        duplicate = first is not None
        receipt_no = int(first.get("回执次数", 1)) + 1 if duplicate else 1
        first_raw_id = first.get("_首次原始记录标识") if duplicate else None
        content_conflict = bool(
            duplicate and str(first.get("模式标识")) != str(sanitized["模式标识"])
        )

        self._raw_seq += 1
        raw = {
            "原始记录标识": self._raw_seq,
            "查询内容": str(query_content or ""),
            "查询用户": str(query_user or ""),
            "实参": copy.deepcopy(params or {}),
            "查询时间": query_time,
            "统计周期": period,
            "权限范围": scope,
            "请求标识原文": request_id,
            "执行耗时_ms": duration_ms,
            "是否慢查": is_slow,
            "回执序号": receipt_no,
            "内容不一致": content_conflict,
            "首次原始记录标识": first_raw_id if duplicate else self._raw_seq,
        }
        self._raw.append(raw)
        if duplicate:
            first["回执次数"] = receipt_no

        self._public_seq += 1
        public = {
            "共享记录标识": f"S-{self._public_seq:04d}",
            "模式标识": sanitized["模式标识"],
            "查询模式": sanitized["查询模式"],
            "慢查类别": classify_slow(sanitized["查询模式"], is_slow),
            "查询者令牌": sanitized["查询者令牌"],
            "统计周期": period,
            "权限范围": scope,
            "请求标识": request_token,
            "查询时间": str(query_time)[:10],
            "执行耗时_ms": duration_ms,
            "耗时区间": duration_bucket(duration_ms),
            "是否慢查": "是" if is_slow else "否",
            "计入统计": not duplicate,
            "重复回执": duplicate,
            "回执次数": receipt_no,
            "首次共享记录标识": first.get("共享记录标识") if duplicate else f"S-{self._public_seq:04d}",
            "脱敏计数": sanitized["移除统计"],
            "_请求标识原文": request_id,
            "_原始记录标识": raw["原始记录标识"],
            "_首次原始记录标识": raw["首次原始记录标识"],
        }
        if not duplicate:
            public["_首次原始记录标识"] = raw["原始记录标识"]
        self._public.append(public)
        if not duplicate:
            self._request_index[(scope, request_id)] = public
        return {
            "已登记": True,
            "原始记录标识": raw["原始记录标识"],
            "重复回执": duplicate,
            "内容不一致": content_conflict,
            "计入统计": not duplicate,
            "回执次数": receipt_no,
            "记录": self._public_view(public),
        }

    @staticmethod
    def _public_view(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: copy.deepcopy(value)
            for key, value in record.items()
            if not key.startswith("_")
        }

    def list_public_records(
        self,
        *,
        scope: str | None = None,
        period: str | None = None,
        include_receipts: bool = True,
    ) -> list[dict[str, Any]]:
        return [
            self._public_view(record)
            for record in self._public
            if (scope is None or record.get("权限范围") == scope)
            and (period is None or record.get("统计周期") == parse_period(period))
            and (include_receipts or record.get("计入统计", True))
        ]

    # ---------- 原始记录回查（原权限范围） ----------
    def get_raw_record(self, raw_id: int, operator_scopes: set[str]) -> tuple[dict[str, Any] | None, str]:
        for raw in self._raw:
            if int(raw.get("原始记录标识", 0)) == int(raw_id):
                if not self._allows(operator_scopes, str(raw.get("权限范围", DEFAULT_SCOPE))):
                    return None, "原始记录只允许在原权限范围内回查"
                return copy.deepcopy(raw), ""
        return None, f"原始记录 {raw_id} 不存在"

    def get_raw_by_shared_id(
        self, shared_id: str, operator_scopes: set[str]
    ) -> tuple[dict[str, Any] | None, str]:
        for public in self._public:
            if str(public.get("共享记录标识")) == str(shared_id):
                raw_id = int(public.get("_原始记录标识", 0))
                return self.get_raw_record(raw_id, operator_scopes)
        return None, f"共享记录 {shared_id} 不存在"

    def list_raw_records(
        self, operator_scopes: set[str], scope: str | None = None
    ) -> tuple[list[dict[str, Any]], str]:
        requested = (
            [scope] if scope
            else sorted({str(r.get("权限范围", DEFAULT_SCOPE)) for r in self._raw})
        )
        for item in requested:
            if not self._allows(operator_scopes, item):
                return [], f"无权回查权限范围 {item} 的原始记录"
        return [
            copy.deepcopy(raw)
            for raw in self._raw
            if scope is None or raw.get("权限范围") == scope
        ], ""

    @staticmethod
    def _allows(operator_scopes: set[str], scope: str) -> bool:
        return "*" in operator_scopes or scope in operator_scopes

    # ---------- 共享批次：发出即固化 ----------
    def create_batch(
        self,
        *,
        period: str,
        scope: str = DEFAULT_SCOPE,
        operator_scopes: set[str],
        force_new: bool = False,
        issued_by: str = "数据工程组",
    ) -> tuple[dict[str, Any] | None, str]:
        scope = str(scope or DEFAULT_SCOPE)
        period = parse_period(period)
        if not self._allows(operator_scopes, scope):
            return None, f"无权在权限范围 {scope} 内发出共享批次"

        issued = [
            batch for batch in self._batches
            if batch["统计范围"]["权限范围"] == scope
            and batch["统计范围"]["统计周期"] == period
            and batch["批次状态"] == "已发出"
        ]
        if issued and not force_new:
            return copy.deepcopy(issued[-1]), (
                "该范围与周期已有已发出批次，返回原批次；如需按新数据重发请显式 force_new"
            )

        records = [
            self._public_view(record) for record in self._public
            if record.get("权限范围") == scope and record.get("统计周期") == period
        ]
        stats = compute_stats(records)
        self._batch_seq += 1
        batch = {
            "共享批次标识": self._batch_seq,
            "批次状态": "已发出",
            "发出时间": datetime.now().isoformat(),
            "发出人": issued_by,
            "统计范围": {
                "权限范围": scope,
                "统计周期": period,
                "记录数": len(records),
                "去重请求数": stats["去重请求数"],
            },
            "原统计口径": copy.deepcopy(CALIBER),
            "口径版本": CALIBER["规则版本"],
            "口径指纹": caliber_fingerprint(),
            "前序批次": issued[-1]["共享批次标识"] if issued else None,
            "公开记录": records,
            "统计": stats,
            "已发出不可改写": True,
        }
        self._batches.append(batch)
        return copy.deepcopy(batch), ""

    def list_batches(
        self, *, scope: str | None = None, period: str | None = None
    ) -> list[dict[str, Any]]:
        return copy.deepcopy([
            {
                "共享批次标识": batch["共享批次标识"],
                "批次状态": batch["批次状态"],
                "发出时间": batch["发出时间"],
                "统计范围": batch["统计范围"],
                "口径版本": batch["口径版本"],
                "口径指纹": batch["口径指纹"],
                "前序批次": batch.get("前序批次"),
            }
            for batch in self._batches
            if (scope is None or batch["统计范围"]["权限范围"] == scope)
            and (period is None or batch["统计范围"]["统计周期"] == parse_period(period))
        ])

    def get_batch(
        self, batch_id: int, operator_scopes: set[str] | None = None
    ) -> tuple[dict[str, Any] | None, str]:
        for batch in self._batches:
            if int(batch["共享批次标识"]) == int(batch_id):
                if operator_scopes is not None and not self._allows(
                    operator_scopes, batch["统计范围"]["权限范围"]
                ):
                    return None, f"无权查看权限范围 {batch['统计范围']['权限范围']} 的共享批次"
                return copy.deepcopy(batch), ""
        return None, f"共享批次 {batch_id} 不存在"

    def recheck_batch(
        self, batch_id: int, operator_scopes: set[str]
    ) -> tuple[dict[str, Any] | None, str]:
        """对比已发出批次与当前数据，仅报告偏差，绝不改写已发出统计。"""
        batch, message = self.get_batch(batch_id, operator_scopes)
        if batch is None:
            return None, message
        scope = batch["统计范围"]["权限范围"]
        period = batch["统计范围"]["统计周期"]
        current_records = [
            self._public_view(record) for record in self._public
            if record.get("权限范围") == scope and record.get("统计周期") == period
        ]
        current = compute_stats(current_records)
        frozen = batch["统计"]
        changed = (
            frozen["去重请求数"] != current["去重请求数"]
            or frozen["慢查请求数"] != current["慢查请求数"]
            or frozen["模式合计"] != current["模式合计"]
        )
        frozen_by_pattern = {row["模式标识"]: row["请求频次"] for row in frozen["模式频次"]}
        return {
            "共享批次标识": batch_id,
            "批次状态": batch["批次状态"],
            "已发出统计": {
                "去重请求数": frozen["去重请求数"],
                "慢查请求数": frozen["慢查请求数"],
                "模式合计": frozen["模式合计"],
            },
            "当前实时统计": {
                "去重请求数": current["去重请求数"],
                "慢查请求数": current["慢查请求数"],
                "模式合计": current["模式合计"],
            },
            "存在差异": changed,
            "已发出统计保持冻结": True,
            "说明": "已发出批次按发出时的范围与口径冻结，新增数据只影响实时统计，不会回写旧批次。",
            "差异明细": [
                {
                    "模式标识": row["模式标识"],
                    "已发出频次": frozen_by_pattern.get(row["模式标识"], 0),
                    "当前频次": row["请求频次"],
                }
                for row in current["模式频次"]
                if frozen_by_pattern.get(row["模式标识"], 0) != row["请求频次"]
            ],
        }, ""

    # ---------- 实时统计 / 合并统计 ----------
    def live_stats(
        self,
        *,
        scope: str = DEFAULT_SCOPE,
        period: str | None = None,
        operator_scopes: set[str],
    ) -> tuple[dict[str, Any] | None, str]:
        scope = str(scope or DEFAULT_SCOPE)
        if not self._allows(operator_scopes, scope):
            return None, f"无权查看权限范围 {scope} 的共享统计"
        records = [
            self._public_view(record) for record in self._public
            if record.get("权限范围") == scope
            and (period is None or record.get("统计周期") == parse_period(period))
        ]
        view = self._build_view(records)
        view.update({
            "统计范围": {
                "权限范围": [scope],
                "统计周期": sorted({str(r.get("统计周期", "")) for r in records}),
                "记录数": len(records),
                "去重请求数": view["合计"]["请求合计"],
            },
            "口径": copy.deepcopy(CALIBER),
            "口径指纹": caliber_fingerprint(),
            "数据状态": "实时（未固化为共享批次）",
        })
        view["可关联范围"] = self.association_note({scope})
        return view, ""

    def merged_stats(
        self, batch_ids: list[int], operator_scopes: set[str]
    ) -> tuple[dict[str, Any] | None, str]:
        if not batch_ids:
            return None, "至少需要指定一个共享批次"
        selected: list[dict[str, Any]] = []
        for batch_id in batch_ids:
            batch, message = self.get_batch(batch_id, operator_scopes)
            if batch is None:
                return None, message
            selected.append(batch)

        records: list[dict[str, Any]] = []
        for batch in selected:
            records.extend(copy.deepcopy(batch["公开记录"]))
        scopes = sorted({batch["统计范围"]["权限范围"] for batch in selected})
        periods = sorted({batch["统计范围"]["统计周期"] for batch in selected})
        view = self._build_view(records)
        view.update({
            "批次": [batch["共享批次标识"] for batch in selected],
            "统计范围": {
                "权限范围": scopes,
                "统计周期": periods,
                "记录数": len(records),
                "去重请求数": view["合计"]["请求合计"],
            },
            "口径": [
                {
                    "共享批次标识": batch["共享批次标识"],
                    "口径版本": batch["口径版本"],
                    "口径指纹": batch["口径指纹"],
                }
                for batch in selected
            ],
            "口径一致": len({batch["口径指纹"] for batch in selected}) == 1,
            "已发出不可改写": True,
        })
        view["可关联范围"] = self.association_note(set(scopes))
        return view, ""

    def association_note(self, scopes: set[str]) -> dict[str, Any]:
        return {
            "共同权限范围": sorted(scopes),
            "跨范围关联": len(scopes) > 1,
            "同范围跨期关联": len(scopes) == 1,
            "同查询者跨期可关联": len(scopes) == 1,
            "说明": (
                "查询者令牌按权限范围加盐：同一范围内可跨周期关联同一查询者；"
                "不同范围的令牌不同，无法关联个人，只能做模式级合计。"
            ),
        }

    def _build_view(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        stats = compute_stats(records)
        return {
            "模式频次": stats["模式频次"],
            "合计": {
                "请求合计": stats["去重请求数"],
                "慢查合计": stats["慢查请求数"],
                "模式合计": stats["模式合计"],
                "查询者合计": stats["查询者合计"],
                "耗时合计_ms": stats["耗时合计_ms"],
                "重复回执剔除数": stats["重复回执剔除数"],
            },
            "复核清单": stats["复核清单"],
            "重复回执清单": stats["重复回执清单"],
            "复核说明": "合计中的每个请求都可在复核清单中按请求标识/共享记录标识回查；频次按实际请求去重。",
        }


def _build_default_secret() -> bytes:
    # 本地/测试默认固定密钥以保证令牌可复核；生产必须用环境变量注入。
    return os.environ.get(
        "GOVERNANCE_HMAC_SECRET", "local-dev-governance-share-v1"
    ).encode("utf-8")


governance = GovernanceService(_build_default_secret())


def default_operator_scopes(header_value: str | None, fallback: str | None = None) -> set[str]:
    raw = header_value if header_value not in (None, "") else (fallback or DEFAULT_SCOPE)
    return {item.strip() for item in str(raw).split(",") if item.strip()}
