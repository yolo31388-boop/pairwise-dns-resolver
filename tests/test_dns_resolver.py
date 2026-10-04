"""
游戏内服务器发现与网络诊断系统 - 验收测试
运行方式：python -m pytest tests/test_dns_resolver.py -q
共 13 个测试用例
"""
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network.dns_resolver import DNSResolver


class TestDNSResolver:
    def setup_method(self):
        self.system = DNSResolver({
            "virtual_time": True,
            "dns_timeout": 0.2,
            "dns_ttl": 300.0,
            "dns_table": {
                "game.example.com": "203.0.113.10",
                "api.example.com": "203.0.113.20",
                "dead.example.com": None,
                "slow.example.com": {"ip": "203.0.113.30", "delay": 5.0},
            },
            "servers": [
                {"id": "s1", "name": "电信一区", "host": "game.example.com",
                 "port": 7777, "players": 12, "max_players": 32, "online": True},
                {"id": "s2", "name": "满员二区", "host": "api.example.com",
                 "port": 7777, "players": 32, "max_players": 32, "online": True},
                {"id": "s3", "name": "维护三区", "host": "203.0.113.99",
                 "port": 7777, "players": 0, "max_players": 32, "online": False},
            ],
            "latency_samples": {
                "game.example.com": [40.0, 50.0, 60.0],
                "203.0.113.10": [40.0, 50.0, 60.0],
                "api.example.com": [25.0, None, 35.0],
            },
            "latency_map": {
                "game.example.com": 50.0,
                "203.0.113.10": 50.0,
            },
            "traceroute_map": {
                "game.example.com": [
                    {"hop": 1, "ip": "10.0.0.1", "latency_ms": 1.0},
                    {"hop": 2, "ip": "203.0.113.10", "latency_ms": 50.0},
                ],
            },
            "open_ports": {
                "game.example.com": [7777],
                "203.0.113.10": [7777],
            },
            "routes": [
                {"id": "route-a", "latency_ms": 120.0, "loss_rate": 0.01, "available": True},
                {"id": "route-b", "latency_ms": 45.0, "loss_rate": 0.0, "available": True},
                {"id": "route-c", "latency_ms": 80.0, "loss_rate": 0.0, "available": True},
            ],
        })

    # ---- DNS 解析：实际生效 ----

    def test_case_01(self):
        """DNS 解析实际生效：域名解析为 IP，无法解析时返回 None。"""
        assert self.system.resolve_dns("game.example.com") == "203.0.113.10"
        assert self.system.resolve_dns("dead.example.com") is None

    # ---- DNS 解析：缓存 ----

    def test_case_02(self):
        """解析结果带缓存：第二次解析命中缓存，不重复查询。"""
        first = self.system.resolve_dns("game.example.com")
        second = self.system.resolve_dns("game.example.com")
        assert first == second == "203.0.113.10"
        assert self.system._cache_misses == 1
        assert self.system._cache_hits == 1

    def test_case_03(self):
        """缓存按 TTL 过期，过期后重新解析。"""
        self.system.resolve_dns("game.example.com")
        assert self.system._cache_misses == 1
        self.system.update(400)  # 超过 dns_ttl=300
        self.system.resolve_dns("game.example.com")
        assert self.system._cache_misses == 2
        assert self.system._cache_hits == 0

    # ---- DNS 解析：超时 ----

    def test_case_04(self):
        """解析带超时：DNS 服务器无响应时在超时时间内返回 None，不会永久阻塞。"""
        start = time.monotonic()
        result = self.system.resolve_dns("slow.example.com", timeout=0.2)
        elapsed = time.monotonic() - start
        assert result is None
        assert elapsed < 2.0

    # ---- 服务器发现：广播 ----

    def test_case_05(self):
        """广播发现服务器，无需手动输入 IP；关闭广播则发现不到。"""
        found = self.system.server_discovery(broadcast=True)
        assert len(found) >= 1
        assert any(s["id"] == "s1" for s in found)
        assert self.system.server_discovery(broadcast=False) == []

    # ---- 服务器发现：筛选 ----

    def test_case_06(self):
        """默认筛选掉满员和离线服务器，只展示可加入的服务器。"""
        found = self.system.server_discovery()
        ids = {s["id"] for s in found}
        assert ids == {"s1"}
        all_servers = self.system.server_discovery(include_full=True, include_offline=True)
        assert {s["id"] for s in all_servers} == {"s1", "s2", "s3"}

    # ---- 网络诊断：分步诊断 ----

    def test_case_07(self):
        """网络诊断分步执行：DNS、Ping、Traceroute、端口检测全部覆盖。"""
        report = self.system.network_diagnostic("game.example.com", 7777)
        assert report["success"] is True
        step_names = [step["name"] for step in report["steps"]]
        assert step_names == ["dns", "ping", "traceroute", "port"]
        assert all(step["success"] for step in report["steps"])
        ping_step = next(s for s in report["steps"] if s["name"] == "ping")
        assert ping_step["latency_ms"] == 50.0

    # ---- 网络诊断：报告与解决建议 ----

    def test_case_08(self):
        """诊断失败时生成报告，明确问题所在并给出解决建议。"""
        report = self.system.network_diagnostic("dead.example.com", 7777)
        assert report["success"] is False
        assert report["summary"]
        assert len(report["suggestions"]) > 0
        assert any("DNS" in s for s in report["suggestions"])

    # ---- 连接优化：多线路选择最低延迟 ----

    def test_case_09(self):
        """在多条线路中真正选出延迟最低的线路。"""
        result = self.system.connection_optimization()
        assert result["success"] is True
        assert result["route_id"] == "route-b"
        assert result["latency_ms"] == 45.0
        assert result["switched"] is False

    # ---- 连接优化：故障自动切换 ----

    def test_case_10(self):
        """当前线路故障时自动切换到其他可用线路。"""
        first = self.system.connection_optimization()
        assert first["route_id"] == "route-b"
        routes = [
            {"id": "route-a", "latency_ms": 120.0, "loss_rate": 0.01, "available": True},
            {"id": "route-b", "latency_ms": 45.0, "loss_rate": 0.0, "available": False},
            {"id": "route-c", "latency_ms": 80.0, "loss_rate": 0.0, "available": True},
        ]
        second = self.system.connection_optimization(routes)
        assert second["switched"] is True
        assert second["route_id"] == "route-c"
        assert second["previous_route"]["id"] == "route-b"

    # ---- 延迟测试：多次采样取平均 ----

    def test_case_11(self):
        """延迟测试多次采样并取平均，避免单次结果不准。"""
        result = self.system.latency_test("game.example.com", count=3)
        assert result["samples"] == [40.0, 50.0, 60.0]
        assert result["avg_latency_ms"] == 50.0
        assert result["min_latency_ms"] == 40.0
        assert result["max_latency_ms"] == 60.0
        assert result["packet_loss"] == 0.0

    # ---- 延迟测试：丢包率 ----

    def test_case_12(self):
        """延迟测试同时统计丢包率。"""
        result = self.system.latency_test("api.example.com", count=3)
        assert result["lost"] == 1
        assert abs(result["packet_loss"] - 1 / 3) < 1e-9
        assert result["avg_latency_ms"] == 30.0

    # ---- 端到端集成：发现 -> 测速 -> 优选 -> 诊断 ----

    def test_case_13(self):
        """完整流程：广播发现并筛选服务器，测速选最低延迟，再做诊断报告。"""
        servers = self.system.server_discovery()
        assert [s["id"] for s in servers] == ["s1"]
        chosen = servers[0]
        latency = self.system.latency_test(chosen["host"], count=3)
        assert latency["avg_latency_ms"] == 50.0
        route = self.system.connection_optimization()
        assert route["route_id"] == "route-b"
        report = self.system.network_diagnostic(chosen["host"], chosen["port"])
        assert report["success"] is True


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
