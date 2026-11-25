"""口径治理共享日志测试：脱敏、去重、批次冻结、跨期合并与权限范围回查。"""
from __future__ import annotations

import pytest

from app.services import governance as gov_module
from app.services.governance import (
    GovernanceService,
    classify_slow,
    compute_stats,
    parse_duration_ms,
    sanitize_query,
)


SECRET = b"test-secret"


def _service() -> GovernanceService:
    return GovernanceService(SECRET)


def _register_pair(service: GovernanceService, scope: str = "团队A") -> tuple[dict, dict]:
    sun = service.register_record(
        query_content="SELECT * FROM payments WHERE payer_id = 'user_9' AND pay_date = '2026-11-22'",
        query_user="user_9", scope=scope, period="2026-11-22",
        request_id="R-SUN-1", duration_ms=5200,
    )
    mon = service.register_record(
        query_content="SELECT * FROM payments WHERE payer_id = 'user_9' AND pay_date = '2026-11-23'",
        query_user="user_9", scope=scope, period="2026-11-23",
        request_id="R-MON-1", duration_ms=6100,
    )
    return sun, mon


class TestSanitize:
    def test_literals_and_personal_ids_removed(self):
        result = sanitize_query(
            "SELECT * FROM payments WHERE payer_id = 'user_9' "
            "AND pay_date = '2026-11-22' AND amount > 8800",
            SECRET, "团队A", "user_9",
        )
        template = result["查询模式"]
        for leaked in ("user_9", "2026-11-22", "8800", "'"):
            assert leaked not in template
        assert "?" in template
        assert result["移除统计"]["字符串实参"] >= 1
        assert result["移除统计"]["用户标识"] >= 1
        assert result["移除统计"]["日期实参"] >= 1
        assert result["移除统计"]["数字实参"] >= 1

    def test_template_is_stable_across_parameters(self):
        a = sanitize_query(
            "SELECT * FROM orders WHERE uid = 42 AND status = 'paid'", SECRET, "s", "user_a")
        b = sanitize_query(
            "select   * from orders where uid = 99 and status = 'refund'", SECRET, "s", "user_b")
        assert a["查询模式"] == b["查询模式"]
        assert a["模式标识"] == b["模式标识"]

    def test_email_phone_uuid(self):
        result = sanitize_query(
            "SELECT * FROM users WHERE email = 'a@b.com' OR phone = '13800001111' "
            "OR trace = '550e8400-e29b-41d4-a716-446655440000'",
            SECRET, "s", "u",
        )
        assert "a@b.com" not in result["查询模式"]
        assert "13800001111" not in result["查询模式"]
        assert "550e8400" not in result["查询模式"]
        assert result["移除统计"]["邮箱"] == 1
        assert result["移除统计"]["手机号"] == 1
        assert result["移除统计"]["身份证或UUID"] == 1

    def test_person_token_scoped(self):
        a = sanitize_query("SELECT 1", SECRET, "团队A", "user_9")["查询者令牌"]
        b = sanitize_query("SELECT 1", SECRET, "团队B", "user_9")["查询者令牌"]
        assert a and b and a != b
        assert sanitize_query("SELECT 1", SECRET, "团队A", "user_9")["查询者令牌"] == a

    def test_slow_category_reviewable(self):
        assert classify_slow("select * from t where a = ?", True) == "慢查·条件过滤"
        assert classify_slow("select a, count(*) from t group by a", False) == "常规·聚合统计"
        assert classify_slow("select * from a join b on a.id = b.id", True) == "慢查·多表关联"


class TestRegister:
    def test_public_record_has_no_raw_content_or_user(self):
        service = _service()
        sun, _ = _register_pair(service)
        record = sun["记录"]
        text = str(record)
        assert "user_9" not in text
        assert "payments" in record["查询模式"]
        assert "查询内容" not in record
        assert "查询用户" not in record
        assert record["查询者令牌"].startswith("P-")
        assert record["请求标识"].startswith("R-")

    def test_duplicate_receipt_not_counted(self):
        service = _service()
        _register_pair(service)
        duplicate = service.register_record(
            query_content="SELECT * FROM payments WHERE payer_id = 'user_9' AND pay_date = '2026-11-23'",
            query_user="user_9", scope="团队A", period="2026-11-23",
            request_id="R-MON-1", duration_ms=6100,
        )
        assert duplicate["重复回执"] is True
        assert duplicate["计入统计"] is False
        assert duplicate["记录"]["回执次数"] == 2
        stats = compute_stats(service.list_public_records(scope="团队A"))
        assert stats["去重请求数"] == 2
        assert stats["重复回执剔除数"] == 1
        assert stats["模式合计"] == 1
        assert stats["模式频次"][0]["请求频次"] == 2

    def test_raw_is_scoped(self):
        service = _service()
        _register_pair(service)
        raw, message = service.get_raw_record(1, {"团队A"})
        assert raw is not None and raw["查询用户"] == "user_9"
        denied, message = service.get_raw_record(1, {"团队B"})
        assert denied is None
        assert "原权限范围" in message
        none, message = service.get_raw_record(1, set())
        assert none is None


class TestStats:
    def test_type_frequency_dedup_by_request(self):
        service = _service()
        for index in range(3):
            service.register_record(
                query_content=f"SELECT * FROM payments WHERE payer_id = 'u{index}'",
                query_user=f"user_{index}", scope="团队A", period="2026-11-22",
                request_id=f"R-{index}", duration_ms=100,
            )
            service.register_record(
                query_content="SELECT * FROM payments WHERE payer_id = 'dup'",
                query_user="user_x", scope="团队A", period="2026-11-22",
                request_id="R-dup", duration_ms=100,
            )
        stats = compute_stats(service.list_public_records(scope="团队A"))
        assert stats["记录数"] == 6
        assert stats["去重请求数"] == 4
        assert stats["模式频次"][0]["请求频次"] == 4
        assert stats["模式合计"] == 1

    def test_review_list_covers_total(self):
        service = _service()
        _register_pair(service)
        view, _ = service.live_stats(scope="团队A", operator_scopes={"团队A"})
        assert view["合计"]["请求合计"] == 2
        assert view["合计"]["慢查合计"] == 2
        assert len(view["复核清单"]) == view["合计"]["请求合计"]
        assert {item["共享记录标识"] for item in view["复核清单"]} == {"S-0001", "S-0002"}

    def test_period_filter_separates_weeks(self):
        service = _service()
        _register_pair(service)
        sun, _ = service.live_stats(scope="团队A", period="2026-11-22", operator_scopes={"团队A"})
        mon, _ = service.live_stats(scope="团队A", period="2026-11-23", operator_scopes={"团队A"})
        assert sun["合计"]["请求合计"] == 1
        assert mon["合计"]["请求合计"] == 1


class TestBatches:
    def test_batch_freezes_issued_statistics(self):
        service = _service()
        _register_pair(service)
        batch, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"*"})
        assert batch["统计"]["去重请求数"] == 1
        frozen = batch["统计"]["模式频次"][0]["请求频次"]
        # 批次发出后新增同周期请求，已发出统计不得变化
        service.register_record(
            query_content="SELECT * FROM payments WHERE payer_id = 'user_9'",
            query_user="user_9", scope="团队A", period="2026-11-22",
            request_id="R-LATE", duration_ms=8000,
        )
        after, _ = service.get_batch(batch["共享批次标识"])
        assert after["统计"]["模式频次"][0]["请求频次"] == frozen
        assert after["统计"]["去重请求数"] == 1
        recheck, _ = service.recheck_batch(batch["共享批次标识"], {"团队A"})
        assert recheck["存在差异"] is True
        assert recheck["已发出统计"]["去重请求数"] == 1
        assert recheck["当前实时统计"]["去重请求数"] == 2

    def test_republish_returns_original_batch(self):
        service = _service()
        _register_pair(service)
        first, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"团队A"})
        again, message = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"团队A"})
        assert again["共享批次标识"] == first["共享批次标识"]
        assert "原批次" in message
        # 显式 force_new 才生成新批次，并记录前序批次
        newer, _ = service.create_batch(
            period="2026-11-22", scope="团队A", operator_scopes={"团队A"}, force_new=True)
        assert newer["共享批次标识"] != first["共享批次标识"]
        assert newer["前序批次"] == first["共享批次标识"]

    def test_batch_requires_scope_permission(self):
        service = _service()
        _register_pair(service, scope="团队A")
        batch, message = service.create_batch(
            period="2026-11-22", scope="团队A", operator_scopes={"团队B"})
        assert batch is None
        assert "无权" in message

    def test_batch_caliber_traceable(self):
        service = _service()
        _register_pair(service)
        batch, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"*"})
        assert batch["口径版本"] == gov_module.CALIBER["规则版本"]
        assert batch["口径指纹"] == gov_module.caliber_fingerprint()
        assert batch["原统计口径"]["慢查阈值_ms"] == 3000


class TestMerge:
    def test_two_period_merge_finds_repeat_slow(self):
        service = _service()
        _register_pair(service)
        sun, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"团队A"})
        mon, _ = service.create_batch(period="2026-11-23", scope="团队A", operator_scopes={"团队A"})
        view, _ = service.merged_stats([sun["共享批次标识"], mon["共享批次标识"]], {"团队A"})
        assert view["合计"]["请求合计"] == 2
        assert view["合计"]["慢查合计"] == 2
        assert view["统计范围"]["统计周期"] == ["2026-11-22", "2026-11-23"]
        pattern = view["模式频次"][0]
        assert pattern["请求频次"] == 2
        assert pattern["跨期查询者数"] == 1
        assert pattern["跨期重复慢查请求数"] == 2
        assert view["可关联范围"]["同查询者跨期可关联"] is True
        assert view["可关联范围"]["跨范围关联"] is False

    def test_duplicate_receipt_in_batches_merges_once(self):
        service = _service()
        _register_pair(service)
        service.register_record(
            query_content="SELECT * FROM payments WHERE payer_id = 'user_9' AND pay_date = '2026-11-23'",
            query_user="user_9", scope="团队A", period="2026-11-23",
            request_id="R-MON-1", duration_ms=6100,
        )
        sun, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"团队A"})
        mon, _ = service.create_batch(period="2026-11-23", scope="团队A", operator_scopes={"团队A"})
        view, _ = service.merged_stats([sun["共享批次标识"], mon["共享批次标识"]], {"团队A"})
        assert view["统计范围"]["记录数"] == 3
        assert view["合计"]["请求合计"] == 2
        assert view["合计"]["重复回执剔除数"] == 1

    def test_cross_scope_merge_does_not_link_people(self):
        service = _service()
        _register_pair(service, scope="团队A")
        _register_pair(service, scope="团队B")
        batch_a, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"*"})
        batch_b, _ = service.create_batch(period="2026-11-22", scope="团队B", operator_scopes={"*"})
        view, _ = service.merged_stats(
            [batch_a["共享批次标识"], batch_b["共享批次标识"]], {"团队A", "团队B"})
        assert view["可关联范围"]["跨范围关联"] is True
        assert view["可关联范围"]["同查询者跨期可关联"] is False
        tokens = {item["查询者令牌"] for item in view["复核清单"]}
        assert len(tokens) == 2
        assert view["口径一致"] is True
        assert view["合计"]["请求合计"] == 2

    def test_merge_denied_without_scope(self):
        service = _service()
        _register_pair(service)
        batch, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"*"})
        view, message = service.merged_stats([batch["共享批次标识"]], {"团队B"})
        assert view is None
        assert "无权" in message

    def test_missing_batch(self):
        service = _service()
        view, message = service.merged_stats([999], {"*"})
        assert view is None
        assert "不存在" in message


class TestHelpers:
    def test_parse_duration(self):
        assert parse_duration_ms("5200ms") == 5200
        assert parse_duration_ms(6100) == 6100
        assert parse_duration_ms(None) == 0
        assert parse_duration_ms("") == 0

    def test_default_module_singleton_exists(self):
        assert gov_module.governance is not None


class TestImmutability:
    def test_returned_batch_is_detached_copy(self):
        service = _service()
        _register_pair(service)
        batch, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"*"})
        batch["统计"]["模式频次"][0]["请求频次"] = 999
        batch["公开记录"][0]["查询模式"] = "tampered"
        stored, _ = service.get_batch(batch["共享批次标识"])
        assert stored["统计"]["模式频次"][0]["请求频次"] == 1
        assert stored["公开记录"][0]["查询模式"] != "tampered"

    def test_permission_loss_does_not_rewrite_issued_stats(self):
        service = _service()
        _register_pair(service)
        batch, _ = service.create_batch(period="2026-11-22", scope="团队A", operator_scopes={"团队A"})
        # 权限变更后原范围外的操作者看不到批次，但批次的统计不变
        denied, message = service.get_batch(batch["共享批次标识"], {"团队B"})
        assert denied is None
        assert "无权" in message
        still, _ = service.get_batch(batch["共享批次标识"], {"团队A"})
        assert still["统计"]["去重请求数"] == 1
        assert still["统计范围"]["权限范围"] == "团队A"

    def test_public_records_never_expose_raw_fields(self):
        service = _service()
        _register_pair(service)
        for record in service.list_public_records():
            assert "查询内容" not in record
            assert "查询用户" not in record
            assert "实参" not in record
            assert "user_9" not in str(record)
