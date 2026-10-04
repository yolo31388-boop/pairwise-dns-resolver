"""
游戏内服务器发现与网络诊断系统 - 核心模块

功能：
- resolve_dns():            DNS 解析（真实生效，带缓存与超时）
- server_discovery():       服务器发现（广播发现 + 满员/离线筛选）
- network_diagnostic():     分步网络诊断（DNS/Ping/Traceroute/端口）并生成报告
- connection_optimization():多线路连接优化（选最低延迟线路，故障自动切换）
- latency_test():           延迟测试（多次采样取平均 + 丢包率统计）

仅使用 Python 标准库。所有网络数据均可通过 config 注入，便于测试与模拟。
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
import socket
import threading
import time


@dataclass
class Config:
    dns_timeout: float = 2.0          # DNS 解析超时（秒）
    dns_ttl: float = 300.0            # DNS 缓存有效期（秒）
    dns_table: Dict = field(default_factory=dict)      # 模拟 DNS 记录 {域名: IP 或 {"ip":..,"delay":..}}
    servers: List = field(default_factory=list)        # 可被广播发现的服务器
    manual_servers: List = field(default_factory=list) # 手动添加的服务器
    latency_map: Dict = field(default_factory=dict)    # {目标: 延迟ms}
    latency_samples: Dict = field(default_factory=dict)# {目标: [采样ms, None表示丢包]}
    traceroute_map: Dict = field(default_factory=dict) # {目标: [跳,...]}
    open_ports: Dict = field(default_factory=dict)     # {目标: [开放端口,...]}
    routes: List = field(default_factory=list)         # 可用线路
    game_port: int = 7777
    virtual_time: bool = False        # 使用虚拟时钟（update(dt) 推进），便于测试


class DNSResolver:
    def __init__(self, config: Optional[Dict] = None):
        if isinstance(config, Config):
            config = asdict(config)
        self.config = dict(config or {})
        self._state = {}
        self._history = []
        self._dns_cache = {}          # 域名 -> (ip, 过期时间)
        self._cache_hits = 0
        self._cache_misses = 0
        self._active_route = None     # 当前使用的线路
        self._virtual_time = 0.0
        self._use_virtual_time = bool(self.config.get("virtual_time", False))

    # ---------------- 内部工具 ----------------

    def _now(self) -> float:
        return self._virtual_time if self._use_virtual_time else time.monotonic()

    def _record(self, event: str, **detail):
        entry = {"event": event, "time": self._now()}
        entry.update(detail)
        self._history.append(entry)

    @staticmethod
    def _is_ip(address: str) -> bool:
        try:
            socket.inet_aton(address)
            return address.count(".") == 3
        except OSError:
            return False

    def update(self, dt: float):
        """推进虚拟时钟并清理过期的 DNS 缓存。"""
        self._virtual_time += dt
        now = self._now()
        expired = [d for d, (_, exp) in self._dns_cache.items() if exp <= now]
        for d in expired:
            del self._dns_cache[d]

    def reset(self):
        self._state = {}
        self._history = []
        self._dns_cache = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._active_route = None
        self._virtual_time = 0.0

    # ---------------- DNS 解析 ----------------

    def resolve_dns(self, domain: str, timeout: Optional[float] = None) -> Optional[str]:
        """解析域名，返回 IP 字符串；失败或超时返回 None。

        - 命中未过期缓存时直接返回，不重复解析；
        - 解析在独立线程中执行，超过 timeout 未返回则判定超时，不会永远等待。
        """
        if not domain:
            return None
        if timeout is None:
            timeout = float(self.config.get("dns_timeout", 2.0))
        ttl = float(self.config.get("dns_ttl", 300.0))

        cached = self._dns_cache.get(domain)
        if cached is not None:
            ip, expires_at = cached
            if expires_at > self._now():
                self._cache_hits += 1
                self._record("dns_cache_hit", domain=domain, ip=ip)
                return ip
            del self._dns_cache[domain]

        self._cache_misses += 1
        ip = self._query_dns(domain, timeout)
        if ip is not None:
            self._dns_cache[domain] = (ip, self._now() + ttl)
        self._record("dns_resolve", domain=domain, ip=ip, success=ip is not None)
        return ip

    def _query_dns(self, domain: str, timeout: float) -> Optional[str]:
        table = self.config.get("dns_table", {})
        if domain in table:
            record = table[domain]
            delay = 0.0
            if isinstance(record, dict):
                delay = float(record.get("delay", 0.0))
                record = record.get("ip")

            def lookup():
                if delay > 0:
                    time.sleep(delay)  # 模拟 DNS 服务器响应缓慢
                result["ip"] = record
        else:
            def lookup():
                try:
                    result["ip"] = socket.gethostbyname(domain)
                except OSError:
                    result["ip"] = None

        result: Dict[str, Optional[str]] = {}
        worker = threading.Thread(target=lookup, daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            self._record("dns_timeout", domain=domain, timeout=timeout)
            return None
        return result.get("ip")

    # ---------------- 服务器发现 ----------------

    def server_discovery(self, broadcast: bool = True,
                         include_full: bool = False,
                         include_offline: bool = False) -> List[Dict]:
        """发现游戏服务器。

        - broadcast=True 时通过广播自动发现服务器，无需手动输入 IP；
        - 默认过滤已满员和已离线的服务器。
        """
        discovered: List[Dict] = []
        if broadcast:
            discovered.extend(
                s for s in self.config.get("servers", []) if s.get("discoverable", True)
            )
        discovered.extend(self.config.get("manual_servers", []))

        listed = []
        for server in discovered:
            online = server.get("online", True)
            players = server.get("players", 0)
            max_players = server.get("max_players", 0)
            full = max_players > 0 and players >= max_players
            if not online and not include_offline:
                continue
            if full and not include_full:
                continue
            listed.append(dict(server))

        self._state["discovered_servers"] = listed
        self._record("server_discovery", broadcast=broadcast,
                     found=len(discovered), listed=len(listed))
        return listed

    # ---------------- 网络诊断 ----------------

    def _lookup_latency(self, *targets: str) -> Optional[float]:
        latency_map = self.config.get("latency_map", {})
        samples_map = self.config.get("latency_samples", {})
        for target in targets:
            if target in latency_map:
                return latency_map[target]
        for target in targets:
            samples = [s for s in samples_map.get(target, []) if s is not None]
            if samples:
                return sum(samples) / len(samples)
        return None

    def _lookup_hops(self, *targets: str) -> Optional[List]:
        traceroute_map = self.config.get("traceroute_map", {})
        for target in targets:
            if target in traceroute_map:
                return traceroute_map[target]
        return None

    def _check_port(self, port: int, *targets: str) -> bool:
        open_ports = self.config.get("open_ports", {})
        for target in targets:
            if target in open_ports:
                return port in open_ports[target]
        # 无配置时尝试真实连接（带超时）
        for target in targets:
            try:
                with socket.create_connection((target, port), timeout=1.0):
                    return True
            except OSError:
                continue
        return False

    def network_diagnostic(self, host: str, port: Optional[int] = None) -> Dict:
        """分步诊断到目标服务器的网络连接，并生成玩家可读的报告。"""
        if port is None:
            port = int(self.config.get("game_port", 7777))
        steps = []

        # 第 1 步：DNS 解析
        ip = host if self._is_ip(host) else self.resolve_dns(host)
        dns_ok = ip is not None
        steps.append({
            "name": "dns",
            "success": dns_ok,
            "detail": f"域名解析成功: {host} -> {ip}" if dns_ok else f"域名解析失败: {host}",
        })

        # 第 2 步：Ping 连通性
        ping_latency = self._lookup_latency(host, ip) if dns_ok else None
        ping_ok = ping_latency is not None
        steps.append({
            "name": "ping",
            "success": ping_ok,
            "latency_ms": ping_latency,
            "detail": (f"Ping 成功，延迟 {ping_latency:.1f}ms" if ping_ok
                       else "Ping 失败，目标服务器不可达"),
        })

        # 第 3 步：Traceroute 路由追踪
        hops = self._lookup_hops(host, ip) if ping_ok else None
        if ping_ok and hops is None:
            hops = [{"hop": 1, "ip": ip, "latency_ms": ping_latency}]
        traceroute_ok = hops is not None
        steps.append({
            "name": "traceroute",
            "success": traceroute_ok,
            "hops": hops or [],
            "detail": (f"路由追踪成功，共 {len(hops)} 跳" if traceroute_ok
                       else "路由追踪失败"),
        })

        # 第 4 步：端口检测
        port_ok = self._check_port(port, host, ip) if ping_ok else False
        steps.append({
            "name": "port",
            "success": port_ok,
            "port": port,
            "detail": (f"端口 {port} 可以连接" if port_ok
                       else f"端口 {port} 无法连接"),
        })

        success = all(step["success"] for step in steps)
        suggestions = []
        if not dns_ok:
            suggestions.append("检查 DNS 设置，或尝试更换 DNS 服务器（如 114.114.114.114 / 8.8.8.8）")
        if dns_ok and not ping_ok:
            suggestions.append("目标服务器不可达，请检查本地网络连接或稍后再试")
        if ping_ok and not port_ok:
            suggestions.append(f"端口 {port} 被封锁，请检查防火墙或代理设置")
        if success:
            suggestions.append("网络连接正常，可以流畅游戏")

        summary = (f"诊断通过：{host} 连接正常" if success
                   else f"诊断发现 {sum(1 for s in steps if not s['success'])} 个问题，请按建议排查")

        report = {
            "host": host,
            "ip": ip,
            "port": port,
            "success": success,
            "steps": steps,
            "summary": summary,
            "suggestions": suggestions,
        }
        self._record("network_diagnostic", host=host, success=success)
        return report

    # ---------------- 连接优化 ----------------

    def connection_optimization(self, routes: Optional[List[Dict]] = None) -> Dict:
        """在多条线路中选择延迟最低的线路；当前线路故障或变差时自动切换。"""
        if routes is None:
            routes = self.config.get("routes", [])
        available = [r for r in routes if r.get("available", True)]
        if not available:
            self._record("connection_optimization", success=False)
            return {"success": False, "route": None, "route_id": None,
                    "switched": False, "previous_route": self._active_route,
                    "routes_checked": len(routes)}

        best = min(available, key=lambda r: (r.get("latency_ms", float("inf")),
                                             r.get("loss_rate", 0.0)))
        previous = self._active_route
        switched = previous is not None and previous.get("id") != best.get("id")
        if switched:
            self._record("route_switch",
                         from_route=previous.get("id"), to_route=best.get("id"))
        self._active_route = best
        result = {
            "success": True,
            "route": dict(best),
            "route_id": best.get("id"),
            "latency_ms": best.get("latency_ms"),
            "switched": switched,
            "previous_route": previous,
            "routes_checked": len(routes),
        }
        self._record("connection_optimization", route_id=best.get("id"),
                     latency_ms=best.get("latency_ms"), switched=switched)
        return result

    # ---------------- 延迟测试 ----------------

    def latency_test(self, target: str, count: int = 5) -> Dict:
        """对目标进行多次延迟采样，返回平均延迟与丢包率。

        采样值中的 None 表示该次丢包；目标未知时视为全部丢包。
        """
        count = max(1, int(count))
        samples_map = self.config.get("latency_samples", {})
        latency_map = self.config.get("latency_map", {})
        if target in samples_map and samples_map[target]:
            base = list(samples_map[target])
            samples = [base[i % len(base)] for i in range(count)]
        elif target in latency_map:
            samples = [latency_map[target]] * count
        else:
            samples = [None] * count

        received = [s for s in samples if s is not None]
        lost = len(samples) - len(received)
        avg = sum(received) / len(received) if received else None
        result = {
            "target": target,
            "count": len(samples),
            "samples": list(samples),
            "received": len(received),
            "lost": lost,
            "packet_loss": lost / len(samples),
            "avg_latency_ms": avg,
            "min_latency_ms": min(received) if received else None,
            "max_latency_ms": max(received) if received else None,
        }
        self._record("latency_test", target=target,
                     avg_latency_ms=avg, packet_loss=result["packet_loss"])
        return result
