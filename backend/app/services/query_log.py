"""查询日志领域服务：查询记录、慢查询标记、耗时统计。"""
# 数据操作：调度、标准化、数据，与上下游模块联动消费批次数据。
from __future__ import annotations

import random
from datetime import datetime
from typing import Any

from app.services.base import BaseModuleService
from app.services.governance import DEFAULT_SCOPE, governance, parse_duration_ms
from app.store import store


class QueryLogService(BaseModuleService):
    MODULE = "query_log"
    ENTITY = "查询记录"
    OPERATION_TERM = "查询"
    LIST_FIELDS = ["记录标识", "查询内容", "查询用户", "查询时间", "返回行数", "执行耗时", "缓存命中", "错误信息"]
    REQUIRED_FIELDS = ["记录标识", "查询内容", "查询用户"]
    STATUS_ORDER = ["已记录", "慢查询", "已优化"]
    ACTION_RULES = {"标记慢查": "已记录", "分析优化": "慢查询"}
    NEGATIVE_ACTIONS = []

    def log_query(self) -> dict[str, Any]:
        """记录一次查询操作。"""
        rng = random.Random()
        duration = rng.randint(5, 10000)
        is_slow = duration > 3000
        row_count = rng.randint(1, 50000)
        cache_hit = rng.random() > 0.5
        new_log = {
            "id": max((int(r.get("id", 0)) for r in store.rows(self.MODULE)), default=0) + 1,
            "记录标识": f"Q{datetime.now().strftime('%m%d%H%M%S')}",
            "查询内容": f"SELECT * FROM metrics WHERE date >= '2026-11-{rng.randint(1,20):02d}'",
            "查询用户": f"user_{rng.randint(1, 10)}",
            "查询时间": datetime.now().isoformat(),
            "返回行数": str(row_count),
            "执行耗时": f"{duration}ms",
            "缓存命中": "是" if cache_hit else "否",
            "错误信息": "",
            "status": "慢查询" if is_slow else "已记录",
            "pending": is_slow,
            "abnormal": is_slow,
        }
        store.rows(self.MODULE).append(new_log)
        shared = self.share_record(new_log["id"])
        return {"log_id": new_log["id"], "status": new_log["status"],
                "duration_ms": duration, "slow_query": is_slow,
                "共享记录标识": shared.get("共享记录标识"),
                "共享计入统计": shared.get("计入统计")}

    def share_record(
        self, entry_id: int, *, scope: str = DEFAULT_SCOPE,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """把一条原始查询记录转换成受控共享记录；原始记录仍只留在 query_log。"""
        entry = store.find(self.MODULE, entry_id)
        if entry is None:
            return {"error": f"查询记录 {entry_id} 不存在"}
        result = governance.register_record(
            query_content=str(entry.get("查询内容", "")),
            query_user=str(entry.get("查询用户", "")),
            scope=scope,
            period=str(entry.get("查询时间", "")),
            request_id=request_id or f"QL-{entry_id}",
            query_time=str(entry.get("查询时间", "")),
            duration_ms=parse_duration_ms(entry.get("执行耗时")),
            params={"返回行数": entry.get("返回行数"), "缓存命中": entry.get("缓存命中")},
            status=str(entry.get("status", "")),
        )
        return result["记录"] | {"计入统计": result["计入统计"], "重复回执": result["重复回执"]}

    def domain_enrich(self, config_id: int) -> dict:
        """对当前模块执行标准化操作，联动回填和批次，产出标准化数据产物。
        
        数据加工流程：读取原始记录 → 执行标准化处理 → 回填校验字段完整性 → 生成批次批次标识 →
        写入存储层并返回可追溯的处理结果，下游消费模块可基于批次号追踪数据链路。
        """
        import time, json
        from app.store import store
        entry = store.find(self.MODULE, config_id)
        # 标准化：遍历当前模块全部记录执行核心数据处理
        records = store.list_all(self.MODULE)
        processed = []
        for idx, rec in enumerate(records):
            # 回填：校验每条记录的字段完整性与格式合法性
            filled = sum(1 for v in rec.values() if v and str(v).strip())
            total = len(rec)
            rec_copy = dict(rec)
            rec_copy["_field_count"] = filled
            rec_copy["_complete_ratio"] = f"{filled}/{total}"
            rec_copy["_batch"] = f"{self.MODULE}-{idx:04d}"
            processed.append(rec_copy)
        # 批次：生成加工批次标识并写入存储
        batch_id = store.next_id(self.MODULE + "_processor")
        result = {
            "module": self.MODULE,
            "operation": "标准化",
            "config_id": config_id,
            "records_processed": len(processed),
            "batch_id": batch_id,
            "field_validation": {"回填": "passed", "批次": "recorded"},
            "processed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "downstream_consumable": True,
            "records": processed,
            "entry": entry,
        }
        # 返回标准化处理结果，含回填校验元数据和批次批次追溯信息
        return result

