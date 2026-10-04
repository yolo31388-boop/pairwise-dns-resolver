"""
游戏内服务器发现与网络诊断系统 - 核心模块

功能：
- DNS解析（带缓存与超时）
- 服务器发现（广播 + 筛选）
- 网络诊断（分步检测 + 报告）
- 连接优化（多线路 + 自动切换）
- 延迟测试（多次取平均 + 丢包率）

纯Python标准库实现。为便于测试，可通过 config 注入：
- resolver_func(domain) -> List[str]        自定义DNS查询
- ping_func(host, port, timeout) -> float|None  自定义延迟探测（秒），None表示丢包
- broadcast_responder() -> List[dict]       自定义广播发现响应
- traceroute_func(host) -> List[str]        自定义路由跟踪
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
import socket
import threading
import time


class DNSResolutionError(Exception):
    """DNS解析失败（解析不了或超时）"""


@dataclass
class Config:
    cache_ttl: float = 300.0          # DNS缓存有效期（秒）
    dns_timeout: float = 5.0          # DNS解析超时（秒）
    ping_count: int = 5               # 延迟测试次数
    ping_timeout: float = 2.0         # 单次探测超时（秒）
    discovery_port: int = 47777       # 服务器发现广播端口
    discovery_timeout: float = 2.0    # 广播发现等待时间（秒）
    switch_loss_threshold: float = 0.5  # 丢包率超过该值触发自动切换线路


_DISCOVERY_MAGIC = b"GSB_SERVER_DISCOVERY"


class DNSResolver:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.cache_ttl = float(self.config.get("cache_ttl", Config.cache_ttl))
        self.dns_timeout = float(self.config.get("dns_timeout", Config.dns_timeout))
        self.ping_count = int(self.config.get("ping_count", Config.ping_count))
        self.ping_timeout = float(self.config.get("ping_timeout", Config.ping_timeout))
        self.discovery_port = int(self.config.get("discovery_port", Config.discovery_port))
        self.discovery_timeout = float(self.config.get("discovery_timeout", Config.discovery_timeout))
        self.switch_loss_threshold = float(
            self.config.get("switch_loss_threshold", Config.switch_loss_threshold)
        )
        self._state = {}
        self._history = []
        self._cache: Dict[str, Tuple[List[str], float]] = {}
        self._servers: List[Dict] = []
        self._candidates: List[Dict] = []
        self._active_route: Optional[Dict] = None

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def update(self, dt: float):
        """清理过期的DNS缓存。"""
        now = time.monotonic()
        expired = [d for d, (_, ts) in self._cache.items() if now - ts >= self.cache_ttl]
        for d in expired:
            del self._cache[d]

    def reset(self):
        self._state = {}
        self._history = []
        self._cache = {}
        self._servers = []
        self._candidates = []
        self._active_route = None

    # ------------------------------------------------------------------
    # DNS解析：实际解析 + 缓存 + 超时
    # ------------------------------------------------------------------
    def resolve_dns(self, domain: str, use_cache: bool = True) -> List[str]:
        """解析域名，返回IP列表。带TTL缓存与超时控制，失败抛 DNSResolutionError。"""
        now = time.monotonic()
        if use_cache and domain in self._cache:
            ips, ts = self._cache[domain]
            if now - ts < self.cache_ttl:
                return list(ips)
            del self._cache[domain]

        ips = self._resolve_with_timeout(domain)
        if not ips:
            raise DNSResolutionError("DNS解析失败（无结果）: %s" % domain)
        self._cache[domain] = (list(ips), now)
        self._history.append(("resolve_dns", domain, time.time()))
        return list(ips)

    def _lookup(self, domain: str) -> List[str]:
        resolver = self.config.get("resolver_func")
        if resolver is not None:
            return list(resolver(domain))
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        return sorted({info[4][0] for info in infos})

    def _resolve_with_timeout(self, domain: str) -> List[str]:
        result: Dict = {}

        def worker():
            try:
                result["ips"] = self._lookup(domain)
            except Exception as exc:  # noqa: BLE001 - 统一包装为DNSResolutionError
                result["error"] = exc

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(self.dns_timeout)
        if thread.is_alive():
            raise DNSResolutionError(
                "DNS解析超时（>%ss）: %s" % (self.dns_timeout, domain)
            )
        if "error" in result:
            raise DNSResolutionError(
                "DNS解析失败: %s (%s)" % (domain, result["error"])
            )
        return result.get("ips", [])

    # ------------------------------------------------------------------
    # 服务器发现：广播 + 筛选
    # ------------------------------------------------------------------
    def register_server(self, server: Dict):
        """手动登记服务器（例如玩家手动输入IP）。"""
        self._servers.append(dict(server))

    def server_discovery(
        self,
        broadcast: bool = True,
        filter_full: bool = True,
        filter_offline: bool = True,
        timeout: Optional[float] = None,
    ) -> List[Dict]:
        """发现可用服务器：本地登记 + 广播发现，默认过滤已满和离线服务器。"""
        found = [dict(s) for s in self._servers]
        if broadcast:
            found.extend(self._broadcast_discover(timeout))

        # 按 (host, port) 去重
        seen = set()
        servers = []
        for s in found:
            key = (s.get("host"), s.get("port"))
            if key in seen:
                continue
            seen.add(key)
            servers.append(s)

        if filter_offline:
            servers = [s for s in servers if s.get("status", "online") == "online"]
        if filter_full:
            servers = [
                s
                for s in servers
                if s.get("players", 0) < s.get("max_players", float("inf"))
            ]
        self._history.append(("server_discovery", len(servers), time.time()))
        return servers

    def _broadcast_discover(self, timeout: Optional[float] = None) -> List[Dict]:
        responder = self.config.get("broadcast_responder")
        if responder is not None:
            try:
                return [dict(s) for s in responder()]
            except Exception:
                return []

        wait = self.discovery_timeout if timeout is None else timeout
        results: List[Dict] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.2)
            sock.sendto(_DISCOVERY_MAGIC, ("255.255.255.255", self.discovery_port))
        except OSError:
            return results

        deadline = time.monotonic() + wait
        try:
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    import json

                    info = json.loads(data.decode("utf-8"))
                    info.setdefault("host", addr[0])
                    results.append(info)
                except (ValueError, UnicodeDecodeError):
                    continue
        finally:
            sock.close()
        return results

    # ------------------------------------------------------------------
    # 延迟测试：多次取平均 + 丢包率
    # ------------------------------------------------------------------
    def latency_test(
        self,
        server: Dict,
        count: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Dict:
        """对服务器做多次延迟探测，返回平均/最小/最大延迟、抖动与丢包率（毫秒）。"""
        host = server.get("host", "")
        port = int(server.get("port", 80))
        count = self.ping_count if count is None else count
        timeout = self.ping_timeout if timeout is None else timeout

        samples: List[float] = []
        lost = 0
        for _ in range(count):
            r = self._ping_once(host, port, timeout)
            if r is None:
                lost += 1
            else:
                samples.append(r * 1000.0)

        avg = sum(samples) / len(samples) if samples else None
        return {
            "host": host,
            "port": port,
            "count": count,
            "received": len(samples),
            "loss_rate": lost / count if count else 1.0,
            "avg_latency": avg,
            "min_latency": min(samples) if samples else None,
            "max_latency": max(samples) if samples else None,
            "jitter": (max(samples) - min(samples)) if samples else None,
            "samples": samples,
        }

    def _ping_once(self, host: str, port: int, timeout: float) -> Optional[float]:
        ping = self.config.get("ping_func")
        if ping is not None:
            try:
                return ping(host, port, timeout)
            except Exception:
                return None
        try:
            start = time.monotonic()
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return time.monotonic() - start
        except OSError:
            return None

    # ------------------------------------------------------------------
    # 网络诊断：分步检测 + 报告
    # ------------------------------------------------------------------
    def network_diagnostic(self, host: str, port: int = 80) -> Dict:
        """分步诊断：DNS -> Ping -> 路由跟踪 -> 端口检测，输出报告与修复建议。"""
        steps: List[Dict] = []
        suggestions: List[str] = []

        # 第1步：DNS解析
        ips: List[str] = []
        try:
            ips = self.resolve_dns(host)
            steps.append({"name": "dns", "status": "ok", "detail": "解析到 %s" % ", ".join(ips)})
        except DNSResolutionError as exc:
            steps.append({"name": "dns", "status": "fail", "detail": str(exc)})
            suggestions.append("DNS解析失败：检查域名拼写，或更换DNS服务器（如 8.8.8.8 / 114.114.114.114）")
            return self._diagnostic_report(host, port, steps, suggestions)

        # 第2步：Ping（延迟与丢包）
        ping_result = self.latency_test({"host": host, "port": port}, count=3)
        if ping_result["loss_rate"] >= 1.0:
            steps.append({"name": "ping", "status": "fail", "detail": "全部丢包，主机不可达"})
            suggestions.append("主机不可达：检查本地网络连接 / 防火墙，或确认服务器是否在线")
            return self._diagnostic_report(host, port, steps, suggestions)
        steps.append({
            "name": "ping",
            "status": "ok",
            "detail": "平均延迟 %.1fms，丢包率 %.0f%%"
            % (ping_result["avg_latency"], ping_result["loss_rate"] * 100),
        })
        if ping_result["loss_rate"] > 0:
            suggestions.append("存在丢包：检查网络质量，或尝试切换线路")

        # 第3步：路由跟踪
        hops = self._traceroute(host)
        steps.append({"name": "traceroute", "status": "ok", "detail": "经过 %d 跳: %s" % (len(hops), " -> ".join(hops))})

        # 第4步：端口检测
        if self._check_port(host, port):
            steps.append({"name": "port", "status": "ok", "detail": "端口 %d 可连接" % port})
        else:
            steps.append({"name": "port", "status": "fail", "detail": "端口 %d 无法连接" % port})
            suggestions.append("端口不通：确认服务器已开启且端口 %d 未被防火墙拦截" % port)

        return self._diagnostic_report(host, port, steps, suggestions)

    def _diagnostic_report(self, host: str, port: int, steps: List[Dict], suggestions: List[str]) -> Dict:
        success = bool(steps) and all(s["status"] == "ok" for s in steps)
        report = {
            "host": host,
            "port": port,
            "success": success,
            "steps": steps,
            "suggestions": suggestions,
        }
        self._history.append(("network_diagnostic", host, success, time.time()))
        return report

    def _traceroute(self, host: str) -> List[str]:
        tracer = self.config.get("traceroute_func")
        if tracer is not None:
            try:
                return list(tracer(host))
            except Exception:
                pass
        return [host]  # 无权限做真实traceroute时的简化结果

    def _check_port(self, host: str, port: int, timeout: Optional[float] = None) -> bool:
        timeout = self.ping_timeout if timeout is None else timeout
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # 连接优化：多线路测速选优 + 故障自动切换
    # ------------------------------------------------------------------
    def connection_optimization(self, servers: List[Dict]) -> Optional[Dict]:
        """对所有服务器的所有线路测速，选择平均延迟最低且未完全丢包的线路。"""
        candidates: List[Dict] = []
        for server in servers:
            routes = server.get("routes") or [
                {"name": "default", "host": server.get("host"), "port": server.get("port", 80)}
            ]
            for route in routes:
                result = self.latency_test(
                    {"host": route.get("host"), "port": route.get("port", 80)}
                )
                if result["loss_rate"] >= 1.0:
                    continue
                candidates.append({
                    "server": server.get("name", route.get("host")),
                    "route": route.get("name", "default"),
                    "host": route.get("host"),
                    "port": route.get("port", 80),
                    "latency": result["avg_latency"],
                    "loss_rate": result["loss_rate"],
                })

        candidates.sort(key=lambda c: (c["latency"], c["loss_rate"]))
        self._candidates = candidates
        self._active_route = candidates[0] if candidates else None
        self._history.append((
            "connection_optimization",
            self._active_route["route"] if self._active_route else None,
            time.time(),
        ))
        return self._active_route

    def get_active_route(self) -> Optional[Dict]:
        return self._active_route

    def auto_switch(self) -> Optional[Dict]:
        """检测当前线路健康度，丢包率过高时自动切换到次优线路。"""
        if self._active_route is None:
            return None
        result = self.latency_test(
            {"host": self._active_route["host"], "port": self._active_route["port"]}
        )
        if result["loss_rate"] < self.switch_loss_threshold:
            self._active_route["latency"] = result["avg_latency"]
            return self._active_route

        for candidate in self._candidates:
            if candidate is self._active_route:
                continue
            check = self.latency_test({"host": candidate["host"], "port": candidate["port"]})
            if check["loss_rate"] < self.switch_loss_threshold:
                candidate["latency"] = check["avg_latency"]
                candidate["loss_rate"] = check["loss_rate"]
                self._history.append((
                    "auto_switch",
                    "%s->%s" % (self._active_route["route"], candidate["route"]),
                    time.time(),
                ))
                self._active_route = candidate
                return candidate
        return None
