"""
游戏内服务器发现与网络诊断系统 - 验收测试
运行方式：python -m pytest tests/test_dns_resolver.py -q
共 13 个测试用例
"""
import socket
import threading
import time

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network.dns_resolver import DNSResolver, DNSResolutionError


class TestDNSResolver:
    def setup_method(self):
        self.system = DNSResolver()

    # ---------- DNS 解析 ----------

    def test_case_01(self):
        """resolve_dns: 真实解析 localhost，返回 127.0.0.1"""
        ips = self.system.resolve_dns("localhost")
        assert isinstance(ips, list) and ips
        assert "127.0.0.1" in ips

    def test_case_02(self):
        """resolve_dns: 带缓存，TTL内重复解析只查询一次"""
        calls = []

        def resolver(domain):
            calls.append(domain)
            return ["10.0.0.1"]

        system = DNSResolver({"resolver_func": resolver, "cache_ttl": 60})
        first = system.resolve_dns("game.example.com")
        second = system.resolve_dns("game.example.com")
        assert first == second == ["10.0.0.1"]
        assert len(calls) == 1

    def test_case_03(self):
        """resolve_dns: 缓存过期后重新解析"""
        calls = []

        def resolver(domain):
            calls.append(domain)
            return ["10.0.0.%d" % len(calls)]

        system = DNSResolver({"resolver_func": resolver, "cache_ttl": 0.05})
        system.resolve_dns("game.example.com")
        system.resolve_dns("game.example.com")
        assert len(calls) == 1
        time.sleep(0.08)
        system.resolve_dns("game.example.com")
        assert len(calls) == 2

    def test_case_04(self):
        """resolve_dns: 解析超时抛 DNSResolutionError，不会永久等待"""
        def slow_resolver(domain):
            time.sleep(1.0)
            return ["10.0.0.1"]

        system = DNSResolver({"resolver_func": slow_resolver, "dns_timeout": 0.1})
        start = time.monotonic()
        with pytest.raises(DNSResolutionError, match="超时"):
            system.resolve_dns("slow.example.com")
        assert time.monotonic() - start < 0.5

    def test_case_05(self):
        """resolve_dns: 域名解析失败抛 DNSResolutionError"""
        def bad_resolver(domain):
            raise socket.gaierror(-2, "Name or service not known")

        system = DNSResolver({"resolver_func": bad_resolver})
        with pytest.raises(DNSResolutionError):
            system.resolve_dns("no-such-host.invalid")

    # ---------- 服务器发现 ----------

    def test_case_06(self):
        """server_discovery: 能发现已登记/广播到的服务器"""
        self.system.register_server({"name": "s1", "host": "10.0.0.1", "port": 7000})
        servers = self.system.server_discovery(broadcast=False)
        assert len(servers) == 1
        assert servers[0]["host"] == "10.0.0.1"

    def test_case_07(self):
        """server_discovery: 默认筛选掉离线和已满的服务器"""
        self.system.register_server({"name": "ok", "host": "10.0.0.1", "port": 7000,
                                     "status": "online", "players": 5, "max_players": 32})
        self.system.register_server({"name": "full", "host": "10.0.0.2", "port": 7000,
                                     "status": "online", "players": 32, "max_players": 32})
        self.system.register_server({"name": "off", "host": "10.0.0.3", "port": 7000,
                                     "status": "offline"})
        servers = self.system.server_discovery(broadcast=False)
        names = {s["name"] for s in servers}
        assert names == {"ok"}
        all_servers = self.system.server_discovery(broadcast=False,
                                                   filter_full=False, filter_offline=False)
        assert len(all_servers) == 3

    def test_case_08(self):
        """server_discovery: 广播发现生效，并与登记结果合并去重"""
        self.system.register_server({"name": "local", "host": "10.0.0.1", "port": 7000})

        def responder():
            return [
                {"name": "bc1", "host": "10.0.0.1", "port": 7000},  # 与登记重复
                {"name": "bc2", "host": "10.0.0.9", "port": 7000},
            ]

        system = DNSResolver({"broadcast_responder": responder})
        system.register_server({"name": "local", "host": "10.0.0.1", "port": 7000})
        servers = system.server_discovery()
        hosts = {(s["host"], s["port"]) for s in servers}
        assert hosts == {("10.0.0.1", 7000), ("10.0.0.9", 7000)}

    # ---------- 网络诊断 ----------

    def test_case_09(self):
        """network_diagnostic: 对可达主机分步执行 dns/ping/traceroute/port 并报告成功"""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        def accept_loop():
            while True:
                try:
                    conn, _ = listener.accept()
                    conn.close()
                except OSError:
                    return
        threading.Thread(target=accept_loop, daemon=True).start()
        try:
            system = DNSResolver({"ping_timeout": 2.0})
            report = system.network_diagnostic("localhost", port)
        finally:
            listener.close()
        assert report["success"] is True
        step_names = [s["name"] for s in report["steps"]]
        assert step_names == ["dns", "ping", "traceroute", "port"]
        assert all(s["status"] == "ok" for s in report["steps"])

    def test_case_10(self):
        """network_diagnostic: DNS失败时终止诊断并给出修复建议"""
        def bad_resolver(domain):
            raise socket.gaierror(-2, "Name or service not known")

        system = DNSResolver({"resolver_func": bad_resolver})
        report = system.network_diagnostic("broken.invalid", 7000)
        assert report["success"] is False
        assert report["steps"][0]["name"] == "dns"
        assert report["steps"][0]["status"] == "fail"
        assert any("DNS" in tip for tip in report["suggestions"])

    # ---------- 连接优化 ----------

    def test_case_11(self):
        """connection_optimization: 多线路实测，选中平均延迟最低的线路"""
        latencies = {"fast": 0.01, "slow": 0.3}

        def ping(host, port, timeout):
            return latencies[host]

        system = DNSResolver({"ping_func": ping})
        servers = [
            {"name": "s1", "routes": [
                {"name": "line-a", "host": "fast", "port": 1},
                {"name": "line-b", "host": "slow", "port": 1},
            ]},
        ]
        best = system.connection_optimization(servers)
        assert best["route"] == "line-a"
        assert best["latency"] == pytest.approx(10.0, rel=0.01)

    def test_case_12(self):
        """connection_optimization: 当前线路故障（全丢包）时自动切换到备用线路"""
        latencies = {"fast": 0.01, "slow": 0.05}

        def ping(host, port, timeout):
            value = latencies.get(host)
            return value if value is not None else None

        system = DNSResolver({"ping_func": ping})
        servers = [
            {"name": "s1", "routes": [
                {"name": "line-a", "host": "fast", "port": 1},
                {"name": "line-b", "host": "slow", "port": 1},
            ]},
        ]
        best = system.connection_optimization(servers)
        assert best["route"] == "line-a"
        assert system.get_active_route()["route"] == "line-a"

        latencies["fast"] = None  # 主线路损坏，探测全部丢包
        switched = system.auto_switch()
        assert switched is not None
        assert switched["route"] == "line-b"
        assert system.get_active_route()["route"] == "line-b"

    # ---------- 延迟测试 ----------

    def test_case_13(self):
        """latency_test: 多次探测取平均，并统计丢包率"""
        replies = iter([0.1, None, 0.2, 0.3, 0.4])

        def ping(host, port, timeout):
            return next(replies)

        system = DNSResolver({"ping_func": ping, "ping_count": 5})
        result = system.latency_test({"host": "s1", "port": 7000})
        assert result["count"] == 5
        assert result["received"] == 4
        assert result["loss_rate"] == pytest.approx(0.2)
        assert result["avg_latency"] == pytest.approx(250.0)
        assert result["min_latency"] == pytest.approx(100.0)
        assert result["max_latency"] == pytest.approx(400.0)
        assert result["jitter"] == pytest.approx(300.0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
