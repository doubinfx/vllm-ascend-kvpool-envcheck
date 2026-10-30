#!/usr/bin/env python3
"""Offline vLLM-Ascend kvpool pre-deployment checker, catalog schema 7.1."""

from __future__ import annotations

import argparse
import copy
import datetime
import importlib.metadata
import itertools
import json
import os
import platform
import re
import secrets
import signal
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parent
DEFAULT_CATALOG = ROOT / "rules.json"
TOOL_VERSION = "14.1.1"
RESULT_SCHEMA_VERSION = "13.1"
REFERENCE_DOCUMENTS = [
    {
        "title": "vLLM-Ascend KV Cache Pool 用户手册",
        "url": "https://github.com/vllm-project/vllm-ascend/blob/main/docs/source/user_guide/feature_guide/kv_cache_pool_ascend_store.md",
        "source_commit": "1985de9f4fd77f9c4a0efdbc98cffc3f43cef305",
        "reviewed_at": "2026-10-20",
        "content_sha256": "981f0072ab021143f4f2f535852b5b73ccbf0e4ba789bfca14be46582854b938",
    }
]


class CatalogError(ValueError):
    pass


class InputError(ValueError):
    pass


class ProgressReporter:
    def __init__(self, enabled: bool, stream: Any = None):
        self.enabled = enabled
        self.stream = stream if stream is not None else sys.stderr

    @classmethod
    def from_mode(cls, mode: str, stream: Any = None) -> "ProgressReporter":
        target = stream if stream is not None else sys.stderr
        enabled = mode == "always" or (mode == "auto" and bool(getattr(target, "isatty", lambda: False)()))
        return cls(enabled, target)

    def _emit(self, message: str) -> None:
        if not self.enabled:
            return
        timestamp = datetime.datetime.now().astimezone().strftime("%H:%M:%S")
        self.stream.write(f"[{timestamp}] {message}\n")
        self.stream.flush()

    @contextmanager
    def stage(self, label: str, index: Optional[int] = None, total: Optional[int] = None):
        prefix = f"[进度 {index}/{total}]" if index is not None and total is not None else "[进度]"
        started = time.monotonic()
        self._emit(f"{prefix} {label}：开始")
        try:
            yield self
        except BaseException as exc:
            elapsed = time.monotonic() - started
            state = "已中断" if isinstance(exc, KeyboardInterrupt) else "失败"
            self._emit(f"{prefix} {label}：{state}，耗时 {elapsed:.1f}s")
            raise
        else:
            elapsed = time.monotonic() - started
            self._emit(f"{prefix} {label}：结束，耗时 {elapsed:.1f}s")


@dataclass(frozen=True)
class CheckContext:
    hardware: str
    backend: str
    managed_memory_mb: int
    deployment_mode: str = "multi-node"
    link_type: str = "roce"
    ssd_offload: bool = False
    ssd_path: Optional[str] = None
    progress: Optional[ProgressReporter] = None


def run_cmd(argv: List[str], timeout: int = 8) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def read_text(path: str, limit: int = 20000) -> str:
    try:
        return Path(path).read_text(errors="replace")[:limit]
    except OSError as exc:
        return f"<unavailable: {exc}>"


def read_utf8(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_utf8(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def redact(text: str) -> str:
    text = re.sub(r"(?i)(password|token|passwd)=\S+", r"\1=<redacted>", text)
    text = re.sub(r"(?im)^(\s*(?:serial number|serial|sn)\s*:\s*).*$", r"\1<redacted>", text)
    return text


def compact_sources(sources: List[Dict[str, Any]], limit: int = 280) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[int, str], Dict[str, Any]] = {}
    for item in sources:
        output = redact(item.get("output", ""))
        source = item["source"]
        if source == "npu-smi info":
            topology = parse_npu_topology(output)
            version = re.search(r"(?i)npu-smi\s+([^\s]+)", output)
            summary = f"npu_version={version.group(1) if version else 'UNKNOWN'}; topology={json.dumps(topology, ensure_ascii=False, separators=(',', ':'))}"
        else:
            clean_lines = [line for line in output.splitlines() if not re.match(r"^\s*[+\-=|]{5,}\s*$", line)]
            summary = "\n".join(clean_lines)
        summary = summary[:limit]
        key = (item["rc"], summary)
        if key not in grouped:
            grouped[key] = {"source": item["source"], "rc": item["rc"], "summary": summary, "occurrences": 1}
        else:
            grouped[key]["occurrences"] += 1
    return list(grouped.values())


def version_tuple(value: str) -> Optional[Tuple[int, ...]]:
    match = re.search(r"(?<!\d)(\d+)(?:\.(\d+))?(?:\.(\d+))?", value or "")
    return tuple(int(item or 0) for item in match.groups()) if match else None


def version_text(value: str) -> str:
    parsed = version_tuple(value)
    return ".".join(str(item) for item in parsed) if parsed else "UNKNOWN"


def run_memory_scan(script: Path, min_segment_mb: int) -> Dict[str, Any]:
    """执行一次 mem_scan.py 扫描并提取全局容量和诊断信息。"""
    rc, out, err = run_cmd([sys.executable, str(script), "-m", str(min_segment_mb)], timeout=600)
    matches = re.findall(r"Total free\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*GB", out)
    total_mb = float(matches[-1]) * 1024 if matches else None
    numa_summary = [
        {"node": int(node), "available_mb": float(free_gb) * 1024, "elapsed": elapsed.strip()}
        for node, free_gb, elapsed in re.findall(r"NUMA node\s+(\d+):\s+([0-9]+(?:\.[0-9]+)?)\s+GB\s+\(([^)]+)\)", out)
    ]
    total_line = re.search(r"Total free\s*:\s*[0-9]+(?:\.[0-9]+)?\s*GB\s+\(([^)]+)\)", out)
    diagnostic = None
    if rc != 0 or total_mb is None:
        diagnostic_lines = [
            line for line in (out + "\n" + err).splitlines()
            if line.strip() and "progress" not in line.lower() and not re.match(r"^\s*[-=]{5,}\s*$", line)
        ]
        diagnostic = redact("\n".join(diagnostic_lines[-12:]))
    return {
        "min_segment_mb": min_segment_mb,
        "rc": rc,
        "total_available_mb": total_mb,
        "numa_summary": numa_summary,
        "elapsed": total_line.group(1).strip() if total_line else None,
        "diagnostic": diagnostic,
    }


def probe_a3_memory_scan(managed_memory_mb: int) -> Dict[str, Any]:
    """按 1GB 优先、2MB 回退的策略检测 A3 全局可用纳管内存。"""
    script_name = "mem_scan.py"
    script = ROOT / "artifacts" / script_name
    base = {
        "method": "a3_mem_scan",
        "ok": False,
        "script": script_name,
        "scan_scope": "a3_fixed_ranges",
        "managed_memory_mb": managed_memory_mb,
    }
    if not script.exists():
        return {**base, "failure_kind": "capability", "available_memory_mb": None, "matched_granularity_mb": None, "error": "A3扫描脚本缺失", "scans": {}}

    # 先用 1GB 粒度判断，容量不足但扫描有效时再回退到 2MB 粒度。
    primary = run_memory_scan(script, 1024)
    primary_valid = primary.get("rc") == 0 and primary.get("total_available_mb") is not None
    primary_pass = primary_valid and primary["total_available_mb"] >= managed_memory_mb
    fallback = None
    if not primary_pass and primary_valid:
        fallback = run_memory_scan(script, 2)
    fallback_valid = fallback is not None and fallback.get("rc") == 0 and fallback.get("total_available_mb") is not None
    fallback_pass = fallback_valid and fallback["total_available_mb"] >= managed_memory_mb
    ok = bool(primary_pass or fallback_pass)
    valid_scan = primary_valid and (primary_pass or fallback_valid)
    # 结果按全局可用容量比较，不按 NUMA 节点或卡 die 均摊。
    valid_totals = [
        scan["total_available_mb"]
        for scan in (primary, fallback)
        if scan is not None and scan.get("rc") == 0 and scan.get("total_available_mb") is not None
    ]
    available_memory_mb = max(valid_totals) if valid_totals else None
    matched_granularity_mb = 1024 if primary_pass else (2 if fallback_pass else None)
    scans = {"1024": primary, "2": fallback}
    return {
        **base,
        "ok": ok,
        "failure_kind": None if ok else ("capacity" if valid_scan else "capability"),
        "available_memory_mb": available_memory_mb,
        "matched_granularity_mb": matched_granularity_mb,
        "scans": scans,
        "error": None if valid_scan else "未取得可用于全局容量判定的扫描结果",
    }


def read_proc_meminfo() -> Dict[str, str]:
    """读取静态大页相关的 /proc/meminfo 字段。"""
    values: Dict[str, str] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii", errors="replace").splitlines():
            match = re.match(r"^(HugePages_Total|HugePages_Free|HugePages_Rsvd|Hugepagesize):\s+(\d+)\s*(\w+)?$", line)
            if match:
                values[match.group(1)] = f"{match.group(2)} {match.group(3) or ''}".strip()
    except OSError:
        return {}
    return values


def parse_meminfo_number(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    match = re.match(r"^(\d+)", value)
    return int(match.group(1)) if match else None


def probe_a2_static_hugepages(managed_memory_mb: int) -> Dict[str, Any]:
    """根据 2MB 静态大页空闲数量检测 A2 全局可用纳管内存。"""
    meminfo = read_proc_meminfo()
    page_size_kb = parse_meminfo_number(meminfo.get("Hugepagesize"))
    total_pages = parse_meminfo_number(meminfo.get("HugePages_Total"))
    free_pages = parse_meminfo_number(meminfo.get("HugePages_Free"))
    required_pages = (managed_memory_mb + 1) // 2
    available_memory_mb = free_pages * 2 if free_pages is not None else None
    valid = page_size_kb == 2048 and total_pages is not None and free_pages is not None
    ok = bool(valid and free_pages >= required_pages)
    return {
        "method": "a2_static_hugepages",
        "ok": ok,
        "managed_memory_mb": managed_memory_mb,
        "page_size_kb": page_size_kb,
        "required_page_size_kb": 2048,
        "total_pages": total_pages,
        "free_pages": free_pages,
        "required_pages": required_pages,
        "available_memory_mb": available_memory_mb,
        "failure_kind": None if ok else ("capacity" if valid else "capability"),
        "error": (
            None
            if valid
            else "未取得2MB静态大页完整证据，要求Hugepagesize=2048kB且HugePages_Total/HugePages_Free可读"
        ),
    }


def probe_memory_capacity(hardware: str, managed_memory_mb: int) -> Dict[str, Any]:
    """按硬件选择 A2 静态大页或 A3 mem_scan 内存检测策略。"""
    if hardware == "A2":
        return probe_a2_static_hugepages(managed_memory_mb)
    if hardware == "A3":
        return probe_a3_memory_scan(managed_memory_mb)
    return {
        "method": "unsupported",
        "ok": False,
        "managed_memory_mb": managed_memory_mb,
        "failure_kind": "capability",
        "available_memory_mb": None,
        "error": f"未实现硬件 {hardware} 的内存检测策略",
    }


def is_docker_runtime() -> bool:
    if Path("/.dockerenv").exists() or Path("/.containerenv").exists():
        return True
    cgroup = read_text("/proc/1/cgroup", 4000).lower()
    return bool(re.search(r"docker|containerd|kubepods|libpod", cgroup))


def probe_docker_prereqs() -> Dict[str, Any]:
    """检查 Docker 内 NPU 设备、驱动目录和 HCCN 入口是否可用。"""
    devices = sorted(str(path) for path in Path("/dev").glob("davinci*"))
    return {
        "docker": is_docker_runtime(),
        "npu_smi": bool(shutil.which("npu-smi")),
        "hccn_tool": bool(find_hccn_tool()),
        "devices": devices,
        "davinci_device_count": len(devices),
        "driver_dir": Path("/usr/local/Ascend/driver").is_dir(),
        "hccn_conf": Path("/etc/hccn.conf").is_file(),
    }


def find_hccn_tool() -> Optional[str]:
    return shutil.which("hccn_tool") or next((str(path) for path in (
        Path("/usr/local/Ascend/driver/tools/hccn_tool"),
        Path("/usr/local/Ascend/driver/bin/hccn_tool"),
    ) if path.is_file() and os.access(path, os.X_OK)), None)


def parse_roce_ip(output: str) -> Optional[str]:
    candidates = [value for value in re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", output) if value not in ("0.0.0.0", "127.0.0.1")]
    return candidates[0] if candidates else None


def parse_roce_netmask(output: str) -> Optional[str]:
    match = re.search(r"(?im)^\s*netmask\s*:\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", output)
    return match.group(1) if match else None


def parse_roce_ping_result(output: str, rc: int, maximum_packet_loss_percent: float = 0.0) -> Dict[str, Any]:
    text = output.lower()
    result: Dict[str, Any] = {
        "ok": False,
        "failure_kind": "command",
        "reason": "",
        "transmitted": None,
        "received": None,
        "packet_loss_percent": None,
    }
    if "needs the following parameters" in text or "total count of input parameters is wrong" in text:
        result["reason"] = f"hccn_tool 参数错误（rc={rc}）"
        return result
    summary = re.search(
        r"(\d+)\s+packets?\s+transmitted\s*,\s*(\d+)\s+received\s*,\s*([0-9]+(?:\.[0-9]+)?)%\s+packet\s+loss",
        text,
    )
    if summary:
        transmitted, received = int(summary.group(1)), int(summary.group(2))
        packet_loss = float(summary.group(3))
        result.update(transmitted=transmitted, received=received, packet_loss_percent=packet_loss)
        if rc == 0 and transmitted > 0 and packet_loss <= maximum_packet_loss_percent:
            result.update(ok=True, failure_kind=None, reason=f"丢包率 {packet_loss:.2f}% 不高于要求 {maximum_packet_loss_percent:.2f}%")
        else:
            result.update(failure_kind="connectivity", reason=f"发送 {transmitted} 包，接收 {received} 包，丢包率 {packet_loss:.2f}%，rc={rc}")
        return result
    if rc != 0:
        result["reason"] = f"hccn_tool 命令执行失败（rc={rc}）"
        return result
    if re.search(r"timeout|unreachable|failed|failure|error|lost|link\s+down|invalid", text):
        result.update(failure_kind="connectivity", reason="输出包含失败、超时或不可达信息")
        return result
    result["reason"] = "命令成功但未取得可解析的收发包统计"
    return result


ROCE_ERROR_COUNTER_KEYS = (
    "mac_rx_fcs_err_pkt_num",
    "roce_rx_err_pkt_num",
    "roce_tx_err_pkt_num",
    "roce_verification_err_num",
    "roce_qp_status_err_num",
)


def parse_roce_error_counters(output: str) -> Dict[str, int]:
    values = {key.strip(): int(value) for key, value in re.findall(r"(?m)^\s*([A-Za-z0-9_]+)\s*:\s*(\d+)\s*$", output)}
    return {key: values.get(key, 0) for key in ROCE_ERROR_COUNTER_KEYS}


def probe_roce_npu_state(tool: str, npu_id: int, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """读取单张 NPU 的 RoCE IP、Link、health 和 MTU 静态状态。"""
    commands = {
        "ip": [tool, "-i", str(npu_id), "-ip", "-g"],
        "link": [tool, "-i", str(npu_id), "-link", "-g"],
        "health": [tool, "-i", str(npu_id), "-net_health", "-g"],
        "mtu": [tool, "-i", str(npu_id), "-mtu", "-g"],
    }
    outputs = {name: run_cmd(argv, timeout=10) for name, argv in commands.items()}
    ip_text = outputs["ip"][1]
    link_match = re.search(r"(?im)^\s*link\s+status\s*:\s*(\S+)", outputs["link"][1])
    health_match = re.search(r"(?im)^\s*net\s+health\s+status\s*:\s*(.+?)\s*$", outputs["health"][1])
    mtu_match = re.search(r"(?im)^\s*mtu\s*:\s*(\d+)\s*$", outputs["mtu"][1])
    state: Dict[str, Any] = {
        "npu_id": npu_id,
        "ip": parse_roce_ip(ip_text),
        "netmask": parse_roce_netmask(ip_text),
        "link_status": link_match.group(1).upper() if link_match else None,
        "net_health": health_match.group(1).strip() if health_match else None,
        "mtu": int(mtu_match.group(1)) if mtu_match else None,
        "command_rc": {name: item[0] for name, item in outputs.items()},
    }
    failures = []
    if any(rc != 0 for rc in state["command_rc"].values()):
        failures.append("至少一个 hccn_tool 查询命令失败")
    if not state["ip"] or not state["netmask"]:
        failures.append("RoCE IP 或掩码缺失")
    required_link = str(parameters["required_link"]).upper()
    required_health = str(parameters["required_health"])
    if state["link_status"] != required_link:
        failures.append(f"Link={state['link_status'] or 'UNKNOWN'}")
    if (state["net_health"] or "").casefold() != required_health.casefold():
        failures.append(f"net_health={state['net_health'] or 'UNKNOWN'}")
    if not state["mtu"] or state["mtu"] <= 32:
        failures.append(f"MTU={state['mtu']}")
    state["ok"] = not failures
    state["failures"] = failures
    if failures:
        state["diagnostic"] = redact("\n".join((out + "\n" + err).strip() for rc, out, err in outputs.values() if rc != 0 or not out)[-1000:])
    return state


def read_roce_error_counters(tool: str, npu_id: int) -> Dict[str, Any]:
    rc, out, err = run_cmd([tool, "-i", str(npu_id), "-stat", "-g"], timeout=10)
    return {"rc": rc, "counters": parse_roce_error_counters(out) if rc == 0 else {}, "diagnostic": redact(err[-500:]) if rc != 0 else None}


def run_roce_ping(tool: str, source: int, target: int, target_ip: str, packet_size: int, timeout_seconds: int = 15, maximum_packet_loss_percent: float = 0.0) -> Dict[str, Any]:
    argv = [tool, "-i", str(source), "-ping", "-g", "address", target_ip, "pkt", str(packet_size)]
    rc, out, err = run_cmd(argv, timeout=timeout_seconds)
    return {
        "source_npu": source,
        "target_npu": target,
        "target_ip": target_ip,
        "packet_size": packet_size,
        "command": ["hccn_tool", "-i", str(source), "-ping", "-g", "address", target_ip, "pkt", str(packet_size)],
        "rc": rc,
        "output": redact(out[-1000:]),
        "stderr": redact(err[-500:]),
        **parse_roce_ping_result(out + "\n" + err, rc, maximum_packet_loss_percent),
    }


def probe_roce_diagnostics(hardware: str, backend: str, link_parameters: Dict[str, Any], local_parameters: Dict[str, Any]) -> Dict[str, Any]:
    """执行 RoCE 端口静态检查和本机 NPU 卡间动态连通性检查。"""
    result: Dict[str, Any] = {"hardware": hardware, "backend": backend, "npu_states": [], "link": {}, "local": {}}
    tool = find_hccn_tool()
    if not tool:
        error = "未找到 hccn_tool，拒绝降级为普通 host ping"
        result["link"] = {"ok": False, "failure_kind": "capability", "error": error}
        result["local"] = {"ok": False, "executed": False, "failure_kind": "static_check_failed", "error": f"静态端口检查能力不足：{error}", "directions": []}
        return result
    rc, out, err = run_cmd(["npu-smi", "info"], timeout=10)
    topology = parse_npu_topology(out) if rc == 0 else {}
    npu_ids = topology.get("npu_ids", [])
    result["available_npu_ids"] = npu_ids
    if len(npu_ids) < 2:
        error = f"可用 NPU 少于 2 张：{npu_ids}; {redact(err)}"
        result["link"] = {"ok": False, "failure_kind": "capability", "error": error}
        result["local"] = {"ok": False, "executed": False, "failure_kind": "static_check_failed", "error": f"静态端口检查未通过：{error}", "directions": []}
        return result

    # 先检查每张可见 NPU 的端口状态，静态失败时不执行动态卡对测试。
    states = [probe_roce_npu_state(tool, npu_id, link_parameters) for npu_id in npu_ids]
    result["npu_states"] = states
    baseline_failures = [f"NPU {state['npu_id']}: {', '.join(state['failures'])}" for state in states if not state["ok"]]
    ips = [state["ip"] for state in states if state["ip"]]
    netmasks = {state["netmask"] for state in states if state["netmask"]}
    mtus = {state["mtu"] for state in states if state["mtu"]}
    if link_parameters["require_unique_ip"] and len(ips) != len(set(ips)):
        baseline_failures.append("RoCE IP 存在重复")
    if link_parameters["require_consistent_netmask_mtu"]:
        if len(netmasks) != 1:
            baseline_failures.append(f"RoCE 掩码不一致：{sorted(netmasks)}")
        if len(mtus) != 1:
            baseline_failures.append(f"RoCE MTU 不一致：{sorted(mtus)}")
    directions: List[Dict[str, Any]] = []
    packet_size = min(mtus) - 32 if len(mtus) == 1 else None
    state_by_id = {state["npu_id"]: state for state in states}
    connectivity_ready = not baseline_failures and packet_size is not None
    before: Dict[str, Dict[str, Any]] = {}
    after: Dict[str, Dict[str, Any]] = {}
    # 静态端口通过后，执行全部有向卡对，并比较测试窗口内的错误计数增量。
    if connectivity_ready:
        before = {str(npu_id): read_roce_error_counters(tool, npu_id) for npu_id in npu_ids}
        timeout_seconds = int(local_parameters["timeout_seconds"])
        maximum_packet_loss = float(local_parameters["required_packet_loss_percent"])
        pairs = list(itertools.permutations(npu_ids, 2))
        for source, target in pairs:
            directions.append(run_roce_ping(tool, source, target, state_by_id[target]["ip"], packet_size, timeout_seconds, maximum_packet_loss))
        after = {str(npu_id): read_roce_error_counters(tool, npu_id) for npu_id in npu_ids}

    counter_deltas: Dict[str, Dict[str, int]] = {}
    counter_failures = []
    counter_read_failure = False
    for npu_id in npu_ids if connectivity_ready else []:
        key = str(npu_id)
        if before[key]["rc"] != 0 or after[key]["rc"] != 0:
            counter_read_failure = True
            counter_failures.append(f"NPU {npu_id} 错误计数读取失败")
            continue
        counter_deltas[key] = {}
        for counter in ROCE_ERROR_COUNTER_KEYS:
            old = before[key]["counters"].get(counter, 0)
            new = after[key]["counters"].get(counter, 0)
            delta = new - old if new >= old else new
            counter_deltas[key][counter] = delta
            if delta > 0:
                counter_failures.append(f"NPU {npu_id} {counter} 增加 {delta}")
    error_counters = {"before": before, "after": after, "deltas": counter_deltas}

    result["link"] = {
        "ok": not baseline_failures,
        "failure_kind": None if not baseline_failures else "port_readiness",
        "error": "; ".join(baseline_failures) if baseline_failures else None,
    }
    failed_directions = [item for item in directions if not item["ok"]]
    if not connectivity_ready:
        result["local"] = {
            "ok": False,
            "executed": False,
            "failure_kind": "static_check_failed",
            "packet_size": packet_size,
            "direction_count": 0,
            "directions": directions,
            "error": "端口静态就绪检查未通过，未执行本机卡间数据通路检测",
        }
    else:
        local_failures = [item.get("reason", "有向卡对检测失败") for item in failed_directions] + counter_failures
        result["local"] = {
            "ok": not local_failures,
            "executed": True,
            "failure_kind": None if not local_failures else (
                "capability"
                if counter_read_failure
                else ("command" if any(item.get("failure_kind") == "command" for item in failed_directions) else "data_path")
            ),
            "packet_size": packet_size,
            "direction_count": len(directions),
            "directions": directions,
            "error_counters": error_counters,
            "error": "; ".join(
                ([f"{len(failed_directions)}/{len(directions)} 个有向卡对检测失败"] if failed_directions else [])
                + counter_failures
            ) or None,
        }
    return result


def parse_hccs_state(output: str) -> Dict[str, Any]:
    def parse_values(label: str, numeric: bool = True) -> List[Any]:
        match = re.search(rf"(?im)^\s*{re.escape(label)}\s*:\s*\[([^]]*)\]", output)
        if not match:
            return []
        values = match.group(1).split()
        if not numeric:
            return values
        try:
            return [int(value) for value in values]
        except ValueError:
            return []

    health = re.search(r"(?im)^\s*hccs health status\s*:\s*(\S+)", output)
    first_error = re.search(r"(?im)^\s*hccs first error lane\s*:\s*(\S+)", output)
    return {
        "health_status": health.group(1).upper() if health else None,
        "lane_mode": parse_values("hccs lane mode"),
        "link_lane_list": parse_values("hccs link lane list", numeric=False),
        "link_speed": parse_values("hccs link speed"),
        "retry_count": parse_values("hccs retry count"),
        "error_count": parse_values("hccs error count"),
        "first_error_lane": first_error.group(1) if first_error else None,
    }


def parse_hccs_topology(output: str) -> Dict[int, Dict[int, str]]:
    header: List[int] = []
    rows: Dict[int, Dict[int, str]] = {}
    for line in output.splitlines():
        phy_ids = [int(value) for value in re.findall(r"Phy-ID(\d+)", line)]
        if len(phy_ids) > 1 and not header:
            header = phy_ids
            continue
        match = re.match(r"^\s*Phy-ID(\d+)\s+(.+?)\s*$", line)
        if not match or not header:
            continue
        values = match.group(2).split()
        if len(values) >= len(header):
            rows[int(match.group(1))] = dict(zip(header, values[:len(header)]))
    return rows


def parse_npu_processes(output: str) -> List[Dict[str, Any]]:
    header = re.search(r"(?im)^\|\s*NPU\s+Chip\s*\|\s*Process id", output)
    if not header:
        return []
    processes = []
    for line in output[header.end():].splitlines():
        columns = [column.strip() for column in line.split("|")]
        if len(columns) < 4:
            continue
        location = re.fullmatch(r"(\d+)\s+(\d+)", columns[1])
        pid = re.fullmatch(r"\d+", columns[2])
        if not location or not pid:
            continue
        processes.append({
            "npu_id": int(location.group(1)),
            "chip_id": int(location.group(2)),
            "pid": int(pid.group(0)),
            "process_name": columns[3][:160],
        })
    return processes


def query_hccs_states(device_pairs: List[Tuple[int, int]], parameters: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str], bool]:
    states = []
    failures = []
    capability_failure = False
    for npu_id, chip_id in device_pairs:
        rc, out, err = run_cmd(["npu-smi", "info", "-t", "hccs", "-i", str(npu_id), "-c", str(chip_id)], timeout=15)
        parsed = parse_hccs_state(out) if rc == 0 else {}
        state = {"npu_id": npu_id, "chip_id": chip_id, "rc": rc, **parsed}
        state_failures = []
        if rc != 0:
            capability_failure = True
            state_failures.append(f"查询失败 rc={rc}: {redact(err[-300:])}")
        elif state.get("health_status") != str(parameters["required_health"]).upper():
            state_failures.append(f"health={state.get('health_status') or 'UNKNOWN'}")
        lengths = [len(state.get(key, [])) for key in ("lane_mode", "link_lane_list", "link_speed", "retry_count", "error_count")]
        if rc == 0 and (not lengths[0] or len(set(lengths)) != 1):
            capability_failure = True
            state_failures.append(f"HCCS 链路字段缺失或长度不一致: {lengths}")
        if rc == 0 and lengths[0] and len(set(lengths)) == 1:
            for index, (lane_mode, lane_list, speed) in enumerate(zip(state["lane_mode"], state["link_lane_list"], state["link_speed"]), start=1):
                if parameters["require_complete_lanes"] and (lane_mode <= 0 or not re.fullmatch(r"1+", lane_list) or len(lane_list) != lane_mode):
                    state_failures.append(f"link {index} lane 异常: mode={lane_mode}, list={lane_list}")
                if parameters["require_positive_speed"] and speed <= 0:
                    state_failures.append(f"link {index} speed={speed}")
        state["ok"] = not state_failures
        state["failures"] = state_failures
        states.append(state)
        failures.extend(f"card {npu_id}/die {chip_id}: {failure}" for failure in state_failures)
    return states, failures, capability_failure


def hccs_counter_snapshot(states: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[int]]]:
    return {
        f"{state['npu_id']}:{state['chip_id']}": {
            "retry_count": list(state.get("retry_count", [])),
            "error_count": list(state.get("error_count", [])),
        }
        for state in states
    }


def hccs_counter_deltas(before: Dict[str, Dict[str, List[int]]], after: Dict[str, Dict[str, List[int]]], maximum_delta: int = 0) -> Tuple[Dict[str, Dict[str, List[int]]], List[str]]:
    deltas: Dict[str, Dict[str, List[int]]] = {}
    failures = []
    for device, old_counters in before.items():
        new_counters = after.get(device)
        if new_counters is None:
            failures.append(f"card/die {device} 测试后计数缺失")
            continue
        deltas[device] = {}
        for name in ("retry_count", "error_count"):
            old_values = old_counters.get(name, [])
            new_values = new_counters.get(name, [])
            if len(old_values) != len(new_values):
                failures.append(f"card/die {device} {name} 长度变化")
                continue
            values = [new - old if new >= old else new for old, new in zip(old_values, new_values)]
            deltas[device][name] = values
            for link_index, value in enumerate(values, start=1):
                if value > maximum_delta:
                    failures.append(f"card/die {device} link {link_index} {name} 增加 {value}")
    return deltas, failures


def run_hccs_collective(script: Path, world_size: int, elements_per_peer: int, iterations: int, timeout_seconds: int) -> Dict[str, Any]:
    """运行独立的 HCCL 集合通信测试进程并解析其结果。"""
    argv = [
        sys.executable,
        str(script),
        "--world-size", str(world_size),
        "--elements-per-peer", str(elements_per_peer),
        "--iterations", str(iterations),
        "--timeout-seconds", str(timeout_seconds),
    ]
    started = time.monotonic()
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        out, err = proc.communicate(timeout=timeout_seconds + 30)
        rc = proc.returncode
    except KeyboardInterrupt:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
        raise
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
        rc = 124
        err = (err + "\nHCCL 动态测试超时，已终止整个测试进程组").strip()
    except OSError as exc:
        return {"ok": False, "rc": 127, "elapsed_seconds": round(time.monotonic() - started, 3), "result": None, "diagnostic": str(exc)}
    parsed = None
    for line in reversed(out.splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            parsed = candidate
            break
    return {
        "ok": bool(rc == 0 and parsed and parsed.get("ok")),
        "rc": rc,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "result": parsed,
        "diagnostic": redact("\n".join(line for line in (out + "\n" + err).splitlines() if line.strip())[-4000:]) if rc != 0 or not parsed else None,
    }


def probe_hccs_diagnostics(hardware: str, backend: str, static_parameters: Dict[str, Any], dynamic_parameters: Dict[str, Any]) -> Dict[str, Any]:
    """执行 A3 SIO/HCCS 静态拓扑检查和 HCCL 动态数据通路测试。"""
    result: Dict[str, Any] = {"hardware": hardware, "backend": backend, "static": {}, "dynamic": {}}
    rc, npu_output, npu_err = run_cmd(["npu-smi", "info"], timeout=15)
    topology = parse_npu_topology(npu_output) if rc == 0 else {}
    chip_ids_by_npu = topology.get("chip_ids_by_npu", {})
    device_pairs = [
        (npu_id, chip_id)
        for npu_id in topology.get("npu_ids", [])
        for chip_id in chip_ids_by_npu.get(npu_id, list(range(topology.get("chips_by_npu", {}).get(npu_id, 0))))
    ]
    if rc != 0 or not device_pairs:
        error = f"无法枚举 A3 card/die：npu-smi rc={rc}; {redact(npu_err[-500:])}"
        result["static"] = {"ok": False, "failure_kind": "capability", "device_pairs": device_pairs, "error": error}
        result["dynamic"] = {"ok": False, "executed": False, "failure_kind": "static_check_failed", "error": error}
        return result

    # 先检查每个可见 die 的 HCCS 状态，再校验 card/die 间的静态拓扑关系。
    states, state_failures, capability_failure = query_hccs_states(device_pairs, static_parameters)
    first_npu, first_chip = device_pairs[0]
    topo_rc, topo_out, topo_err = run_cmd(["npu-smi", "info", "-t", "topo", "-i", str(first_npu), "-c", str(first_chip)], timeout=15)
    topology_rows = parse_hccs_topology(topo_out) if topo_rc == 0 else {}
    physical_ids_by_npu = topology.get("physical_ids_by_npu", {})
    visible_physical_ids = sorted({value for values in physical_ids_by_npu.values() for value in values})
    physical_to_npu = {physical_id: npu_id for npu_id, values in physical_ids_by_npu.items() for physical_id in values}
    relation_counts: Dict[str, int] = {}
    topology_failures = []
    if topo_rc != 0 or not topology_rows or len(visible_physical_ids) != len(device_pairs):
        capability_failure = True
        topology_failures.append(f"拓扑证据不完整：topo rc={topo_rc}, 可见 physical ID={visible_physical_ids}, card/die={len(device_pairs)}; {redact(topo_err[-300:])}")
    else:
        for source, target in itertools.permutations(visible_physical_ids, 2):
            relation = topology_rows.get(source, {}).get(target)
            relation_counts[relation or "MISSING"] = relation_counts.get(relation or "MISSING", 0) + 1
            expected = (
                {str(static_parameters["same_card_relation"])}
                if physical_to_npu[source] == physical_to_npu[target]
                else {str(value) for value in static_parameters["cross_card_relations"]}
            )
            if relation not in expected:
                topology_failures.append(f"Phy-ID{source}->Phy-ID{target}={relation or 'MISSING'}，期望={'/'.join(sorted(expected))}")
    failures = state_failures + topology_failures
    static_ok = not failures
    before_counters = hccs_counter_snapshot(states)
    result["static"] = {
        "ok": static_ok,
        "failure_kind": None if static_ok else ("capability" if capability_failure else "link"),
        "visible_npu_ids": topology.get("npu_ids", []),
        "device_pairs": [{"npu_id": npu_id, "chip_id": chip_id} for npu_id, chip_id in device_pairs],
        "visible_physical_ids": visible_physical_ids,
        "topology_relation_counts": relation_counts,
        "dies": states,
        "error": "; ".join(failures) if failures else None,
    }
    # 静态拓扑或链路失败时跳过动态测试，避免重复产生同一阻塞问题。
    if not static_ok:
        result["dynamic"] = {
            "ok": False,
            "executed": False,
            "failure_kind": "static_check_failed",
            "error": "静态拓扑或链路检查未通过，未执行 HCCL 动态通信测试",
        }
        return result

    # 动态测试会独占全部可见 die；存在业务进程时保持保护性跳过。
    processes = parse_npu_processes(npu_output)
    if processes:
        result["dynamic"] = {
            "ok": False,
            "executed": False,
            "failure_kind": "devices_busy",
            "processes": processes,
            "error": f"检测到 {len(processes)} 个 NPU 进程；为避免影响业务，未执行独占式 HCCL 动态通信测试",
        }
        return result

    script = ROOT / "artifacts" / "hccs_test_a3.py"
    if not script.exists():
        result["dynamic"] = {"ok": False, "executed": False, "failure_kind": "capability", "error": "动态测试脚本 artifacts/hccs_test_a3.py 缺失"}
        return result
    # 动态测试结束后重新读取计数，只判断本次测试窗口内的增量。
    collective = run_hccs_collective(
        script,
        len(device_pairs),
        elements_per_peer=int(dynamic_parameters["elements_per_peer"]),
        iterations=int(dynamic_parameters["iterations"]),
        timeout_seconds=int(dynamic_parameters["timeout_seconds"]),
    )
    after_states, after_failures, after_capability_failure = query_hccs_states(device_pairs, static_parameters)
    after_counters = hccs_counter_snapshot(after_states)
    deltas, counter_failures = hccs_counter_deltas(before_counters, after_counters, int(dynamic_parameters["required_retry_error_delta"]))
    dynamic_failures = ([] if collective.get("ok") else ["HCCL all-to-all 通信或数据正确性校验失败"]) + after_failures + counter_failures
    result["dynamic"] = {
        "ok": not dynamic_failures,
        "executed": True,
        "failure_kind": None if not dynamic_failures else ("capability" if after_capability_failure or collective.get("rc") in (124, 127) else "data_path"),
        "world_size": len(device_pairs),
        "collective": collective,
        "error_counters": {"before": before_counters, "after": after_counters, "deltas": deltas},
        "error": "; ".join(dynamic_failures) if dynamic_failures else None,
    }
    return result


def probe_package_versions(names: List[str]) -> Dict[str, Any]:
    """读取本次适用规则要求的软件包版本。"""
    versions = {}
    for name in dict.fromkeys(names):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return {"versions": versions}


def probe_ssd_storage(path_text: str, backend: str) -> Dict[str, Any]:
    """根据后端规则检查 SSD Offload 路径类型、挂载和可用性。"""
    if not path_text:
        return {"path": path_text, "backend": backend, "ok": False, "error": "启用 SSD Offload 时必须提供 --ssd-path"}
    path = Path(path_text)
    result: Dict[str, Any] = {"path": path_text, "backend": backend, "ok": False}
    if not path.exists():
        result["error"] = "SSD 路径不存在"
        return result
    if path.is_dir():
        if backend == "memcache":
            result["error"] = "Memcache SSD 需要传入未挂载的块设备、分区或 loop 设备，不能传目录"
            return result
        if backend != "mooncake":
            result["error"] = f"尚未实现后端 {backend} 的 SSD Offload 存储检查策略"
            return result
        try:
            stat = os.statvfs(path)
            result["free_bytes"] = stat.f_bavail * stat.f_frsize
            result["ok"] = os.access(path, os.W_OK) and result["free_bytes"] > 0
            if not result["ok"]:
                result["error"] = "SSD 目录不可写或无可用空间"
            return result
        except OSError as exc:
            result["error"] = f"无法检查 SSD 目录：{exc}"
            return result
    if not path.is_block_device():
        result["error"] = "SSD 路径不是目录或块设备"
        return result
    if backend not in ("memcache", "mooncake"):
        result["error"] = f"尚未实现后端 {backend} 的 SSD Offload 存储检查策略"
        return result
    rc, out, err = run_cmd(["lsblk", "-J", "-o", "PATH,TYPE,FSTYPE,MOUNTPOINTS,PKNAME,SIZE", str(path)], timeout=10)
    result.update({"lsblk_rc": rc, "lsblk_error": err})
    if rc != 0:
        result["error"] = "lsblk 无法读取 SSD 设备信息"
        return result
    try:
        data = json.loads(out)
        devices = data.get("blockdevices", [])
        selected = next((item for item in devices if item.get("path") == str(path)), devices[0] if devices else {})
        mounts = selected.get("mountpoints") or []
        fstype = selected.get("fstype")
        result["device"] = selected
        result["ok"] = not fstype and not any(mounts)
        if not result["ok"]:
            result["error"] = "SSD 设备存在文件系统签名或挂载点，不能作为专用缓存设备"
    except (json.JSONDecodeError, StopIteration) as exc:
        result["error"] = f"无法解析 lsblk 输出：{exc}"
    return result


def probe_glibc() -> Dict[str, Any]:
    """读取容器内 glibc 版本及 ldd 诊断信息。"""
    rc, out, err = run_cmd(["ldd", "--version"], timeout=10)
    match = re.search(r"(?i)glibc[^0-9]*(\d+\.\d+)|ldd[^0-9]*(\d+\.\d+)", out or err)
    return {"version": next((item for item in (match.groups() if match else ()) if item), None), "rc": rc, "summary": (out or err)[:300]}


def probe_hdk() -> Dict[str, Any]:
    """从容器可见的驱动、npu-smi 和 Toolkit 信息中读取 HDK/CANN 版本。"""
    sources: List[Dict[str, Any]] = []
    for argv in (["npu-smi", "info"], ["npu-smi", "info", "-t", "board", "-i", "0"]):
        rc, out, err = run_cmd(list(argv), timeout=10)
        if out or err:
            sources.append({"source": " ".join(argv), "rc": rc, "output": redact(out or err)})
    paths = ["/usr/local/Ascend/driver/version.info", "/usr/local/Ascend/driver/version.info.txt", "/etc/ascend_install.info"]
    toolkit_roots = [Path("/usr/local/Ascend/ascend-toolkit/latest")]
    for env_name in ("ASCEND_TOOLKIT_HOME", "ASCEND_HOME_PATH"):
        if os.environ.get(env_name):
            toolkit_roots.append(Path(os.environ[env_name]))
    for root in toolkit_roots:
        paths.extend(str(path) for path in root.glob("**/ascend_toolkit_install.info"))
        paths.extend(str(path) for path in root.glob("**/version.cfg"))
    for path in dict.fromkeys(paths):
        if Path(path).exists():
            sources.append({"source": path, "rc": 0, "output": redact(read_text(path, 4000))})
    sources.sort(key=lambda item: int(bool(re.search(r"(?i)(hdk|firmware|driver|version)", item["output"]))), reverse=True)
    version_pattern = r"\d+\.\d+(?:\.\d+)?(?:[.-]?(?:rc|RC)\d+)?"
    found = None
    found_source = None
    cann_found = None
    cann_source = None
    for item in sources:
        match = re.search(rf"(?i)(?:hdk|firmware|driver|version)[^0-9]{{0,20}}({version_pattern})", item["output"])
        if not match:
            match = re.search(rf"(?<!\d)({version_pattern})(?!\d)", item["output"])
        if match:
            source_evidence = {"source": item["source"], "rc": item["rc"], "matched_line": next((line.strip() for line in item["output"].splitlines() if match.group(1) in line), "")[:280]}
            is_cann = "toolkit" in item["source"].lower() or "cann" in item.get("output", "").lower()
            if is_cann:
                cann_found = cann_found or match.group(1)
                cann_source = cann_source or source_evidence
            else:
                found = found or match.group(1)
                found_source = found_source or source_evidence
    return {"version": found, "version_source": found_source, "cann_version": cann_found, "cann_source": cann_source}


def probe_kernel() -> Dict[str, Any]:
    """读取容器所见的 Linux kernel 版本。"""
    rc, out, err = run_cmd(["uname", "-r"])
    return {"value": out if rc == 0 else platform.release(), "rc": rc, "stderr": err}


def parse_npu_topology(output: str) -> Dict[str, Any]:
    npu_ids = set()
    chips_by_npu: Dict[int, int] = {}
    chip_ids_by_npu: Dict[int, List[int]] = {}
    physical_ids_by_npu: Dict[int, List[int]] = {}
    names_by_npu: Dict[int, set[str]] = {}
    in_device_table = False
    current_npu: Optional[int] = None
    for line in output.splitlines():
        if re.search(r"\|\s*NPU\s+Name\s+\|", line, re.IGNORECASE):
            in_device_table = True
            continue
        if in_device_table and re.search(r"\|\s*NPU\s+Chip\s+\|", line, re.IGNORECASE):
            break
        if not in_device_table:
            continue
        columns = line.split("|")
        if len(columns) < 3:
            continue
        match = re.match(r"^\s*(\d+)\s+(.+?)\s*$", columns[1])
        if not match:
            continue
        npu_id = int(match.group(1))
        device_name = match.group(2).strip()
        if not device_name:
            continue
        chip_match = re.fullmatch(r"(\d+)(?:\s+(\d+))?", f"{npu_id} {device_name}")
        if chip_match and current_npu is not None:
            chip_id = int(chip_match.group(1))
            chip_ids_by_npu.setdefault(current_npu, []).append(chip_id)
            if chip_match.group(2) is not None:
                physical_ids_by_npu.setdefault(current_npu, []).append(int(chip_match.group(2)))
            continue
        npu_ids.add(npu_id)
        current_npu = npu_id
        chips_by_npu[npu_id] = chips_by_npu.get(npu_id, 0) + 1
        names_by_npu.setdefault(npu_id, set()).add(device_name)
    chip_counts = sorted(set(chips_by_npu.values()))
    device_names = sorted({name for names in names_by_npu.values() for name in names})
    return {
        "npu_count": len(npu_ids),
        "total_chip_count": sum(chips_by_npu.values()),
        "chips_per_npu": chip_counts[0] if len(chip_counts) == 1 else None,
        "npu_ids": sorted(npu_ids),
        "chips_by_npu": chips_by_npu,
        "chip_ids_by_npu": {npu_id: sorted(set(values)) for npu_id, values in sorted(chip_ids_by_npu.items())},
        "physical_ids_by_npu": {npu_id: sorted(set(values)) for npu_id, values in sorted(physical_ids_by_npu.items())},
        "device_names": device_names,
        "names_by_npu": {npu_id: sorted(names) for npu_id, names in sorted(names_by_npu.items())},
    }


def probe_hardware(identification: Dict[str, Any]) -> Dict[str, Any]:
    """根据 npu-smi 设备名称和 die 拓扑识别当前硬件型号。"""
    sources: List[Dict[str, Any]] = []
    rc, out, err = run_cmd(["npu-smi", "info"], timeout=10)
    if out or err:
        sources.append({"source": "npu-smi info", "rc": rc, "output": redact(out or err)})
    topologies = [parse_npu_topology(item["output"]) for item in sources if item["source"] == "npu-smi info"]
    # 只有全部可见设备同时满足名称和 die 数量要求时才确认硬件。
    matched = set()
    match_details: Dict[str, Any] = {}
    for topology in topologies:
        for hardware, spec in identification.items():
            names = topology.get("device_names", [])
            name_patterns = spec.get("name_patterns", [])
            names_match = bool(names and name_patterns) and all(
                any(re.fullmatch(str(pattern), name, re.IGNORECASE) for pattern in name_patterns)
                for name in names
            )
            dies_per_npu = spec.get("dies_per_npu")
            die_counts = topology.get("chips_by_npu", {})
            dies_match = dies_per_npu is None or bool(die_counts) and all(
                count == int(dies_per_npu) for count in die_counts.values()
            )
            if names_match and dies_match:
                matched_checks = ["all_device_names"]
                if dies_per_npu is not None:
                    matched_checks.append("dies_per_npu")
                matched.add(hardware.upper())
                match_details[hardware.upper()] = {
                    "source": "npu-smi info",
                    "matched": matched_checks,
                    "device_names": names,
                    "dies_by_npu": die_counts,
                }
    model = next(iter(matched)) if len(matched) == 1 else None
    observed = {
        "device_names": sorted({name for topology in topologies for name in topology.get("device_names", [])}),
        "dies_by_npu": {
            str(npu_id): count
            for topology in topologies
            for npu_id, count in topology.get("chips_by_npu", {}).items()
        },
    }
    command_diagnostic = "; ".join(f"{item['source']} rc={item['rc']}" for item in sources) or "未获取到 npu-smi/sysfs 输出"
    return {
        "model": model,
        "candidates": sorted(matched),
        "sources": compact_sources(sources),
        "match_details": match_details,
        "topologies": topologies,
        "observed": observed,
        "diagnostic": f"{command_diagnostic}; 观测标识={json.dumps(observed, ensure_ascii=False, separators=(',', ':'))}",
    }


def evaluator_parameters(rules: List[Dict[str, Any]], evaluator: str) -> Dict[str, Any]:
    return next((rule["parameters"] for rule in rules if rule["evaluator"] == evaluator), {})


PROBES: Dict[str, Callable[[CheckContext, List[Dict[str, Any]]], Dict[str, Any]]] = {
    "hdk": lambda context, rules: {**probe_hdk(), "hardware": context.hardware, "backend": context.backend},
    "kernel": lambda context, rules: {**probe_kernel(), "deployment_mode": context.deployment_mode},
    "memory_scan": lambda context, rules: probe_memory_capacity(context.hardware, context.managed_memory_mb),
    "manual_confirmation": lambda context, rules: {},
    "ssd_storage": lambda context, rules: probe_ssd_storage(context.ssd_path or "", context.backend),
    "roce_diagnostics": lambda context, rules: probe_roce_diagnostics(
        context.hardware,
        context.backend,
        evaluator_parameters(rules, "roce_link"),
        evaluator_parameters(rules, "roce_local"),
    ),
    "hccs_diagnostics": lambda context, rules: probe_hccs_diagnostics(
        context.hardware,
        context.backend,
        evaluator_parameters(rules, "hccs_static"),
        evaluator_parameters(rules, "hccs_dynamic"),
    ),
    "docker_prereqs": lambda context, rules: probe_docker_prereqs(),
    "package_versions": lambda context, rules: probe_package_versions([
        rule["parameters"]["package"] for rule in rules if rule["parameters"].get("package")
    ]),
    "glibc": lambda context, rules: probe_glibc(),
}


def validate_catalog(catalog: Dict[str, Any]) -> None:
    """校验规则目录结构、适用范围和 evaluator 所需运行参数。"""
    # 目录基础字段和全局支持范围
    if catalog.get("schema_version") != "7.1":
        raise CatalogError("仅支持 rules.json schema_version=7.1")
    for field in ("supported_hardware", "supported_backends", "supported_link_types", "supported_deployment_modes", "rules"):
        if not isinstance(catalog.get(field), list) or not catalog[field]:
            raise CatalogError(f"{field} 必须是非空数组")
    identification = catalog.get("hardware_identification", {})
    if set(catalog["supported_link_types"]) != {"roce", "hccs"}:
        raise CatalogError("supported_link_types 必须为 roce/hccs")
    if set(catalog["supported_deployment_modes"]) != {"single-node", "multi-node"}:
        raise CatalogError("supported_deployment_modes 必须为 single-node/multi-node")
    if not isinstance(identification, dict) or not set(identification) <= set(catalog["supported_hardware"]):
        raise CatalogError("hardware_identification 必须是已声明硬件的映射")
    if set(identification) != set(catalog["supported_hardware"]):
        raise CatalogError("hardware_identification 必须覆盖全部已声明硬件")

    # 硬件识别配置
    for hardware, spec in identification.items():
        patterns = spec.get("name_patterns") if isinstance(spec, dict) else None
        if not isinstance(patterns, list) or not patterns or not all(isinstance(pattern, str) and pattern for pattern in patterns):
            raise CatalogError(f"hardware_identification.{hardware}.name_patterns 必须是非空字符串数组")
        try:
            for pattern in patterns:
                re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise CatalogError(f"hardware_identification.{hardware}.name_patterns 存在无效正则：{exc}") from exc
        dies_per_npu = spec.get("dies_per_npu")
        if dies_per_npu is not None and (not isinstance(dies_per_npu, int) or isinstance(dies_per_npu, bool) or dies_per_npu <= 0):
            raise CatalogError(f"hardware_identification.{hardware}.dies_per_npu 必须是正整数")
    ids = set()

    # 规则公共字段、适用范围和修复定义
    for rule in catalog["rules"]:
        required = ("id", "problem", "impact", "hardware", "backends", "scope", "blocking", "probe", "evaluator", "parameters", "evidence_method", "remediation")
        missing = [field for field in required if field not in rule]
        if missing:
            raise CatalogError(f"规则 {rule.get('id', '<unknown>')} 缺少字段: {','.join(missing)}")
        if rule["id"] in ids:
            raise CatalogError(f"规则 ID 重复: {rule['id']}")
        ids.add(rule["id"])
        if not isinstance(rule["hardware"], list) or not isinstance(rule["backends"], list) or not isinstance(rule["parameters"], dict):
            raise CatalogError(f"规则 {rule['id']} 的 hardware/backends/parameters 类型无效")
        if rule["scope"] not in ("host", "docker"):
            raise CatalogError(f"规则 {rule['id']} 的 scope 无效: {rule['scope']}")
        if rule["probe"] not in PROBES:
            raise CatalogError(f"规则 {rule['id']} 使用未知 probe: {rule['probe']}")
        if rule["evaluator"] not in EVALUATORS:
            raise CatalogError(f"规则 {rule['id']} 使用未知 evaluator: {rule['evaluator']}")
        if not set(rule["hardware"]) - {"*"} <= set(catalog["supported_hardware"]):
            raise CatalogError(f"规则 {rule['id']} 使用了未声明硬件")
        if not set(rule["backends"]) - {"*"} <= set(catalog["supported_backends"]):
            raise CatalogError(f"规则 {rule['id']} 使用了未声明后端")
        link_types = rule.get("link_types")
        if link_types is not None and (
            not isinstance(link_types, list)
            or not link_types
            or any(link_type not in ("roce", "hccs") for link_type in link_types)
        ):
            raise CatalogError(f"规则 {rule['id']} 的 link_types 必须是非空 roce/hccs 数组")
        deployment_modes = rule.get("deployment_modes")
        if deployment_modes is not None and (
            not isinstance(deployment_modes, list)
            or not deployment_modes
            or any(mode not in ("single-node", "multi-node") for mode in deployment_modes)
        ):
            raise CatalogError(f"规则 {rule['id']} 的 deployment_modes 必须是非空 single-node/multi-node 数组")
        if not isinstance(rule["remediation"], dict) or "type" not in rule["remediation"] or "description" not in rule["remediation"]:
            raise CatalogError(f"规则 {rule['id']} remediation 无效")
        positioning = rule.get("positioning")
        if positioning is not None:
            required_positioning = ("layer", "target", "coverage", "excludes")
            if not isinstance(positioning, dict) or any(not positioning.get(key) for key in required_positioning[:-1]):
                raise CatalogError(f"规则 {rule['id']} positioning 无效")
            if not isinstance(positioning.get("excludes"), list) or not positioning["excludes"] or not all(isinstance(value, str) and value for value in positioning["excludes"]):
                raise CatalogError(f"规则 {rule['id']} positioning.excludes 必须是非空字符串数组")
        if rule.get("feature") not in (None, "ssd_offload"):
            raise CatalogError(f"规则 {rule['id']} 使用了未知 feature")
        if rule.get("exclude_feature") not in (None, "ssd_offload"):
            raise CatalogError(f"规则 {rule['id']} 使用了未知 exclude_feature")
        if rule["evaluator"] in ("hccs_static", "hccs_dynamic") and rule.get("link_types") != ["hccs"]:
            raise CatalogError(f"规则 {rule['id']} 必须限定 link_types=[hccs]")
        if rule["evaluator"] in ("roce_link", "roce_local") and rule.get("link_types") != ["roce"]:
            raise CatalogError(f"规则 {rule['id']} 必须限定 link_types=[roce]")
        if rule.get("feature") and rule.get("feature") == rule.get("exclude_feature"):
            raise CatalogError(f"规则 {rule['id']} 不能同时要求和排除同一 feature")

        # evaluator 专属运行参数
        required_parameters = {
            "hccs_static": ("same_card_relation", "cross_card_relations", "required_health", "require_complete_lanes", "require_positive_speed"),
            "hccs_dynamic": ("collective", "elements_per_peer", "iterations", "timeout_seconds", "required_retry_error_delta"),
            "roce_link": ("required_link", "required_health", "require_unique_ip", "require_consistent_netmask_mtu"),
            "roce_local": ("packet_size", "required_packet_loss_percent", "timeout_seconds"),
        }.get(rule["evaluator"], ())
        missing_parameters = [key for key in required_parameters if key not in rule["parameters"]]
        if missing_parameters:
            raise CatalogError(f"规则 {rule['id']} 缺少运行参数: {','.join(missing_parameters)}")
        if rule["evaluator"] == "hdk_requirement":
            requirements = rule["parameters"].get("requirements")
            if not isinstance(requirements, list) or not requirements:
                raise CatalogError(f"规则 {rule['id']} 的 parameters.requirements 必须是非空数组")
            combinations = []
            for requirement in requirements:
                if not isinstance(requirement, dict) or not all(requirement.get(key) for key in ("hardware", "backend", "minimum")):
                    raise CatalogError(f"规则 {rule['id']} 的 HDK 要求必须包含 hardware/backend/minimum")
                combination = (requirement["hardware"], requirement["backend"])
                if combination in combinations:
                    raise CatalogError(f"规则 {rule['id']} 的 HDK 组合重复: {combination[0]}/{combination[1]}")
                combinations.append(combination)
                if requirement["hardware"] not in rule["hardware"] or requirement["backend"] not in rule["backends"]:
                    raise CatalogError(f"规则 {rule['id']} 的 HDK 组合超出适用范围: {combination[0]}/{combination[1]}")
                minimum = version_tuple(str(requirement["minimum"]))
                preferred = version_tuple(str(requirement.get("preferred", ""))) if requirement.get("preferred") else None
                if minimum is None or (preferred is not None and compare_version(preferred, minimum) < 0):
                    raise CatalogError(f"规则 {rule['id']} 的 HDK 版本门限无效: {combination[0]}/{combination[1]}")
            expected = {(hardware, backend) for hardware in rule["hardware"] for backend in rule["backends"]}
            if set(combinations) != expected:
                raise CatalogError(f"规则 {rule['id']} 的 HDK 要求未完整覆盖适用组合")
        if rule["evaluator"] == "docker_prereqs":
            parameters = rule["parameters"]
            if set(parameters) != {"required_all", "required_any"}:
                raise CatalogError(f"规则 {rule['id']} 的 Docker 参数只能包含 required_all/required_any")
            required_all = parameters.get("required_all")
            required_any = parameters.get("required_any")
            if not isinstance(required_all, list) or not required_all or not all(isinstance(key, str) and key for key in required_all):
                raise CatalogError(f"规则 {rule['id']} 的 parameters.required_all 必须是非空字符串数组")
            if not isinstance(required_any, list) or not required_any or not all(
                isinstance(group, list) and len(group) >= 2 and all(isinstance(key, str) and key for key in group)
                for group in required_any
            ):
                raise CatalogError(f"规则 {rule['id']} 的 parameters.required_any 必须是至少含两个键的非空数组组")
        if rule["evaluator"] == "hccs_dynamic":
            for key in ("elements_per_peer", "iterations", "timeout_seconds"):
                value = rule["parameters"].get(key)
                if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                    raise CatalogError(f"规则 {rule['id']} 的 parameters.{key} 必须是正整数")
            maximum_delta = rule["parameters"].get("required_retry_error_delta")
            if not isinstance(maximum_delta, int) or isinstance(maximum_delta, bool) or maximum_delta < 0:
                raise CatalogError(f"规则 {rule['id']} 的 parameters.required_retry_error_delta 必须是非负整数")
            if rule["parameters"].get("collective") != "all_to_all_single":
                raise CatalogError(f"规则 {rule['id']} 仅支持 collective=all_to_all_single")
        if rule["evaluator"] == "roce_local":
            timeout_seconds = rule["parameters"].get("timeout_seconds")
            packet_loss = rule["parameters"].get("required_packet_loss_percent")
            if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
                raise CatalogError(f"规则 {rule['id']} 的 parameters.timeout_seconds 必须是正整数")
            if not isinstance(packet_loss, (int, float)) or isinstance(packet_loss, bool) or packet_loss < 0:
                raise CatalogError(f"规则 {rule['id']} 的 parameters.required_packet_loss_percent 必须是非负数")
    # probe 与 evaluator 的配对关系
    for probe_name, required_evaluators in {
        "roce_diagnostics": {"roce_link", "roce_local"},
        "hccs_diagnostics": {"hccs_static", "hccs_dynamic"},
    }.items():
        configured = {rule["evaluator"] for rule in catalog["rules"] if rule["probe"] == probe_name}
        if configured and configured != required_evaluators:
            raise CatalogError(f"probe {probe_name} 必须同时配置: {','.join(sorted(required_evaluators))}")


def applies(rule: Dict[str, Any], hardware: str, backend: str, link_type: str, deployment_mode: str) -> bool:
    link_types = rule.get("link_types")
    deployment_modes = rule.get("deployment_modes")
    return (
        ("*" in rule["hardware"] or hardware in rule["hardware"])
        and ("*" in rule["backends"] or backend in rule["backends"])
        and (not link_types or link_type in link_types)
        and (not deployment_modes or deployment_mode in deployment_modes)
    )


def feature_applies(rule: Dict[str, Any], ssd_offload: bool) -> bool:
    enabled_features = {"ssd_offload"} if ssd_offload else set()
    required = rule.get("feature")
    excluded = rule.get("exclude_feature")
    return (not required or required in enabled_features) and (not excluded or excluded not in enabled_features)


def validate_inputs(catalog: Dict[str, Any], hardware_arg: str, backend_arg: str, link_type_arg: str, deployment_mode_arg: str) -> Tuple[str, str, str, str, Dict[str, Any]]:
    """校验命令行输入并确认 --hardware 与当前环境硬件一致。"""
    backend = backend_arg.strip().lower()
    if backend not in catalog["supported_backends"]:
        raise InputError(f"--backend={backend_arg!r} 不在适用范围 {','.join(catalog['supported_backends'])} 内")
    hardware = hardware_arg.strip().upper()
    if hardware not in catalog["supported_hardware"]:
        raise InputError(f"--hardware={hardware_arg!r} 不在适用范围 {','.join(catalog['supported_hardware'])} 内")
    link_type = link_type_arg.strip().lower()
    if link_type not in catalog["supported_link_types"]:
        raise InputError(f"--link-type={link_type_arg!r} 不在适用范围 {','.join(catalog['supported_link_types'])} 内")
    deployment_mode = deployment_mode_arg.strip().lower()
    if deployment_mode not in catalog["supported_deployment_modes"]:
        raise InputError(f"--deployment-mode={deployment_mode_arg!r} 不在适用范围 {','.join(catalog['supported_deployment_modes'])} 内")
    if hardware == "A2" and link_type != "roce":
        raise InputError("A2 仅支持 --link-type roce")
    detected = probe_hardware(catalog.get("hardware_identification", {}))
    if not detected["model"]:
        detail = ", ".join(detected["candidates"]) if detected["candidates"] else "未识别到支持型号"
        raise InputError(f"无法确认当前环境硬件型号（{detail}）；证据：{detected['diagnostic']}，拒绝继续检测")
    if detected["model"] != hardware:
        raise InputError(f"--hardware={hardware} 与当前环境硬件 {detected['model']} 不一致")
    return hardware, backend, link_type, deployment_mode, {"requested": hardware, "detected": detected["model"], "identification": {"match_details": detected.get("match_details", {}), "topologies": detected.get("topologies", [])}, "sources": detected["sources"], "supported": catalog["supported_hardware"]}


def make_record(rule: Dict[str, Any], status: str, evidence: Any, detail: str) -> Dict[str, Any]:
    remediation = dict(rule["remediation"])
    record = {
        "id": rule["id"],
        "status": status,
        "problem": rule["problem"],
        "impact": rule["impact"],
        "detail": detail,
        "evidence_method": rule["evidence_method"],
        "evidence": evidence,
        "applicability": {"hardware": rule["hardware"], "backends": rule["backends"], "link_types": rule.get("link_types"), "deployment_modes": rule.get("deployment_modes"), "scope": rule["scope"]},
        "blocking": rule["blocking"],
        "remediation": remediation,
    }
    if "positioning" in rule:
        record["positioning"] = copy.deepcopy(rule["positioning"])
    return record


def is_blocking_result(result: Dict[str, Any]) -> bool:
    return bool(result["blocking"] and result["status"] in ("BLOCK", "MANUAL_REQUIRED", "NOT_EXECUTED"))


def compare_version(value: Tuple[int, ...], threshold: Tuple[int, ...]) -> int:
    width = max(len(value), len(threshold))
    left = value + (0,) * (width - len(value))
    right = threshold + (0,) * (width - len(threshold))
    return (left > right) - (left < right)


def build_version_evidence(rule: Dict[str, Any], probe: Dict[str, Any], raw_version: Optional[str]) -> Dict[str, Any]:
    value_key = rule["parameters"].get("value_key", "version")
    if value_key == "cann_version":
        source = probe.get("cann_source")
    elif rule["probe"] == "hdk":
        source = probe.get("version_source")
    elif rule["probe"] == "kernel":
        source = {"source": "uname -r", "rc": probe.get("rc"), "stderr": probe.get("stderr")}
    elif rule["probe"] == "glibc":
        source = {"source": "ldd --version", "rc": probe.get("rc"), "summary": probe.get("summary")}
    else:
        source = None
    return {"raw_version": raw_version, "normalized_version": version_text(raw_version or "") if raw_version else None, "source": source}


def evaluate_version(rule: Dict[str, Any], probes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """按规则中的版本比较条件判定通用版本依赖。"""
    params = rule["parameters"]
    probe = probes[rule["probe"]]
    value_text = str(probe.get(params.get("value_key", "version")) or "")
    value = version_tuple(value_text)
    evidence = build_version_evidence(rule, probe, value_text or None)
    if value is None:
        if params.get("suppress_if_unknown"):
            return None
        detail = probe.get("query_summary", "未取得可解析的版本字段")
        return make_record(rule, params.get("unknown_status", "BLOCK"), evidence, f"无法确认版本；{detail}。未知证据不能判定为通过")
    if "threshold" in params:
        comparison = compare_version(value, version_tuple(params["threshold"]) or (0,))
        problem_hit = comparison < 0 if params["operator"] == "lt" else comparison >= 0
    else:
        minimum = compare_version(value, version_tuple(params["min"]) or (0,))
        maximum = compare_version(value, version_tuple(params["max"]) or (0,))
        problem_hit = (minimum >= 0 if params.get("min_inclusive", True) else minimum > 0) and (maximum < 0 if params.get("max_exclusive", True) else maximum <= 0)
    status = ("BLOCK" if rule["blocking"] else "WARN") if problem_hit else "PASS"
    normalized = version_text(value_text)
    display = f"检测到版本={value_text}" + (f"（比较值={normalized}）" if value_text != normalized else "")
    return make_record(rule, status, evidence, display)


def evaluate_kernel_requirement(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """按部署模式和版本门限判定 Linux kernel 依赖。"""
    probe = probes[rule["probe"]]
    deployment_mode = probe.get("deployment_mode")
    required_deployment_modes = rule.get("deployment_modes", [])
    evidence = {**probe, "deployment_mode": deployment_mode, "required_deployment_modes": required_deployment_modes}
    if deployment_mode not in required_deployment_modes:
        result = make_record(rule, "NOT_APPLICABLE", evidence, "当前为单节点部署，KERNEL-001不影响单节点kvpool")
        result["blocking"] = False
        result["remediation"] = dict(rule["remediation"])
        result["remediation"]["description"] = "单节点部署无需处理该场景。"
        return result
    value_text = str(probe.get("value") or "")
    value = version_tuple(value_text)
    evidence.update(build_version_evidence(rule, probe, value_text or None))
    threshold_text = str(rule["parameters"]["threshold"])
    if value is None:
        return make_record(rule, rule["parameters"].get("unknown_status", "BLOCK"), evidence, f"多节点部署无法确认Linux kernel版本；要求>={threshold_text}。未知证据不能判定为通过")
    status = "PASS" if compare_version(value, version_tuple(threshold_text) or (0,)) >= 0 else "BLOCK"
    detail = f"部署模式={deployment_mode}；检测到Linux kernel={value_text}，要求>={threshold_text}"
    result = make_record(rule, status, evidence, detail)
    if status == "BLOCK":
        result["remediation"]["description"] = f"多节点部署将host Linux kernel升级到>={threshold_text}，重启或重建容器后复测。"
    return result


def evaluate_hdk_requirement(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """按 hardware/backend 矩阵判定 HDK 版本和兼容路径。"""
    probe = probes[rule["probe"]]
    hardware = probe.get("hardware")
    backend = probe.get("backend")
    requirement = next(
        (
            item for item in rule["parameters"]["requirements"]
            if item["hardware"] == hardware and item["backend"] == backend
        ),
        None,
    )
    if requirement is None:
        evidence = {"hardware": hardware, "backend": backend, "requirement": None}
        return make_record(rule, "BLOCK", evidence, "当前 hardware/backend 没有对应的 HDK 版本要求，不能判定为通过")

    raw_version = str(probe.get("version") or "")
    current = version_tuple(raw_version)
    minimum_text = str(requirement["minimum"])
    minimum = version_tuple(minimum_text) or (0,)
    evidence = {
        **build_version_evidence(rule, probe, raw_version or None),
        "hardware": hardware,
        "backend": backend,
        "minimum_version": minimum_text,
        "preferred_version": requirement.get("preferred"),
        "compatibility_dependency": requirement.get("compatibility_dependency"),
    }
    if current is None:
        return make_record(
            rule,
            rule["parameters"].get("unknown_status", "BLOCK"),
            evidence,
            f"无法确认 HDK 版本；当前组合要求>={minimum_text}。未知证据不能判定为通过",
        )

    status = "PASS" if compare_version(current, minimum) >= 0 else "BLOCK"
    normalized = version_text(raw_version)
    detected = raw_version + (f"（比较值={normalized}）" if raw_version != normalized else "")
    preferred_text = requirement.get("preferred")
    if status == "PASS" and preferred_text and compare_version(current, version_tuple(str(preferred_text)) or (0,)) < 0:
        detail = (
            f"检测到 HDK={detected}，匹配>={minimum_text}兼容路径；"
            f"同时要求 {requirement['compatibility_dependency']}，该软件依赖由独立场景判定"
        )
    elif status == "PASS" and preferred_text:
        detail = f"检测到 HDK={detected}，匹配>={preferred_text}路径"
    else:
        detail = f"检测到 HDK={detected}，当前 {hardware}/{backend} 要求>={minimum_text}"
    result = make_record(rule, status, evidence, detail)
    if status == "BLOCK":
        result["remediation"]["description"] = (
            f"将 host HDK 升级到>={minimum_text}，更新 Docker 挂载后重启容器并复测。"
        )
    return result


def evaluate_memory_scan(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """根据 A2 静态大页或 A3 mem_scan 证据判定纳管内存场景。"""
    probe = probes["memory_scan"]
    status = "PASS" if probe.get("ok") else "BLOCK"
    target_mb = probe.get("managed_memory_mb")
    available_mb = probe.get("available_memory_mb")
    if probe.get("method") == "a2_static_hugepages":
        detail = (
            f"检测方式=2MB静态大页；全局目标={target_mb}MB; 页大小={probe.get('page_size_kb') or '-'}kB; "
            f"总页数={probe.get('total_pages') if probe.get('total_pages') is not None else '-'}; "
            f"空闲页数={probe.get('free_pages') if probe.get('free_pages') is not None else '-'}; "
            f"需要页数={probe.get('required_pages')}; 可用容量={available_mb if available_mb is not None else '-'}MB"
        )
        if probe.get("error"):
            detail += f"; 错误={probe['error']}"
        if status == "BLOCK" and probe.get("failure_kind") == "capacity" and available_mb is not None:
            shortage_mb = target_mb - available_mb
            record_fix = f"A2静态2MB大页不足（目标 {target_mb}MB，可用 {available_mb}MB，缺口 {shortage_mb:.0f}MB）。在host侧配置或扩充HugePages后复测。"
        elif status == "BLOCK":
            record_fix = "检查容器可见的/proc/meminfo，确认Hugepagesize=2048kB且静态大页计数可读；修复后复测。"
        else:
            record_fix = rule["remediation"]["description"]
        result = make_record(rule, status, probe, detail)
        result["remediation"]["description"] = record_fix
        return result
    primary_mb = (probe.get("scans", {}).get("1024") or {}).get("total_available_mb")
    fallback_mb = (probe.get("scans", {}).get("2") or {}).get("total_available_mb")
    detail = (
        f"脚本={probe.get('script')}; 全局目标={target_mb}MB; "
        f"1GB扫描可用={primary_mb if primary_mb is not None else '-'}MB; "
        f"2MB扫描可用={fallback_mb if fallback_mb is not None else '-'}MB; "
        f"匹配粒度={probe.get('matched_granularity_mb') or '-'}MB"
    )
    if probe.get("error"):
        detail += f"; 错误={probe['error']}"
    if status == "BLOCK" and probe.get("failure_kind") == "capacity":
        shortage_mb = target_mb - available_mb if isinstance(target_mb, (int, float)) and isinstance(available_mb, (int, float)) else None
        shortage_text = f"，缺口 {shortage_mb:.0f}MB" if shortage_mb is not None else ""
        record_fix = f"全局可用容量不足（目标 {target_mb}MB，可用 {available_mb}MB{shortage_text}）。确认目标值后释放内存并复测；仍不足则排空业务并重启 host。"
    elif status == "BLOCK":
        record_fix = (
            "内存扫描未成功，先检查 Docker 权限、扫描脚本依赖和内核接口；"
            "修复后重新运行检测，无法恢复时再按维护流程排空业务并重启 host。"
        )
    else:
        record_fix = rule["remediation"]["description"]
    if probe.get("diagnostic"):
        detail += f"; 错误={probe['diagnostic']}"
    result = make_record(rule, status, probe, detail)
    result["remediation"]["description"] = record_fix
    return result


def evaluate_docker_prereqs(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """根据规则目录判定 Docker 设备、驱动和 HCCN 入口是否齐备。"""
    probe = probes["docker_prereqs"]
    missing_all = [key for key in rule["parameters"]["required_all"] if not probe.get(key)]
    failed_any = [group for group in rule["parameters"]["required_any"] if not any(probe.get(key) for key in group)]
    status = "PASS" if not missing_all and not failed_any else "BLOCK"
    hccn_entry = "hccn_conf" if probe.get("hccn_conf") else ("hccn_tool" if probe.get("hccn_tool") else None)
    evidence = {**probe, "satisfied_hccn_entry": hccn_entry, "missing_required_all": missing_all, "failed_required_any": failed_any}
    failures = list(missing_all) + [" 或 ".join(group) for group in failed_any]
    detail = "缺少: " + ", ".join(failures) if failures else f"Docker 设备和驱动可见；HCCN入口={hccn_entry}"
    result = make_record(rule, status, evidence, detail)
    if failures:
        result["remediation"]["description"] = f"重新创建容器并补齐以下设备、挂载或工具：{', '.join(failures)}，然后复测。"
    return result


def evaluate_manual_confirmation(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """生成无法自动取得外部设备版本时的人工确认结果。"""
    evidence = {
        "automatic_detection": False,
        "required_confirmation": rule["parameters"].get("required_confirmation", rule["evidence_method"]),
    }
    detail = "工具不执行交换机版本探测，必须完成运维人工确认后才能继续部署"
    return make_record(rule, "MANUAL_REQUIRED", evidence, detail)


def evaluate_package_version(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """判定规则要求的软件包是否安装且版本满足门限。"""
    name = rule["parameters"]["package"]
    version = probes["package_versions"]["versions"].get(name)
    threshold = rule["parameters"].get("threshold")
    evidence = {"package": name, "installed_version": version, "required_version": threshold}
    if not version:
        return make_record(rule, "BLOCK", evidence, f"未安装 {name}")
    if not threshold:
        return make_record(rule, "PASS", evidence, f"已安装 {name}={version}")
    current_key = package_version_key(version)
    threshold_key = package_version_key(threshold)
    if current_key is None or threshold_key is None:
        return make_record(rule, "BLOCK", evidence, f"{name} 版本无法解析：{version}")
    status = "BLOCK" if current_key < threshold_key else "PASS"
    return make_record(rule, status, evidence, f"检测到 {name}={version}，要求>={threshold}")


def evaluate_ssd_storage(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """根据 SSD 探测证据判定当前后端的 Offload 存储条件。"""
    probe = probes["ssd_storage"]
    status = "PASS" if probe.get("ok") else "BLOCK"
    detail = f"SSD 路径={probe.get('path')}; 后端={probe.get('backend')}"
    if probe.get("error"):
        detail += f"; 错误={probe['error']}"
    return make_record(rule, status, probe, detail)


def evaluate_roce_link(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """根据 RoCE NPU 端口静态状态判定设备侧链路是否就绪。"""
    probe = probes["roce_diagnostics"]
    link = probe["link"]
    status = "PASS" if link.get("ok") else "BLOCK"
    evidence = {
        "hardware": probe["hardware"],
        "backend": probe["backend"],
        "available_npu_ids": probe.get("available_npu_ids", []),
        "npu_states": probe.get("npu_states", []),
        "failure_kind": link.get("failure_kind"),
        "error": link.get("error"),
    }
    detail = f"可见 NPU={len(evidence['available_npu_ids'])}; 逐卡端口静态就绪检查={'通过' if status == 'PASS' else '失败'}"
    if link.get("error"):
        detail += f"; 错误={link['error']}"
    result = make_record(rule, status, evidence, detail)
    if status == "BLOCK" and link.get("failure_kind") == "capability":
        result["remediation"]["description"] = "检查 Docker 内 hccn_tool、NPU 设备权限和驱动挂载，恢复逐卡 IP/Link/health/MTU 查询能力后重试。"
    return result


def evaluate_roce_local(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """根据本机有向卡对 ping 和错误计数增量判定 RoCE 动态通路。"""
    probe = probes["roce_diagnostics"]
    local = probe["local"]
    if not local.get("executed", True) and local.get("failure_kind") == "static_check_failed":
        status = "NOT_EXECUTED"
    else:
        status = "PASS" if local.get("ok") else "BLOCK"
    evidence = {
        "hardware": probe["hardware"],
        "backend": probe["backend"],
        "available_npu_ids": probe.get("available_npu_ids", []),
        **local,
    }
    failed_count = sum(1 for item in local.get("directions", []) if not item.get("ok"))
    if status == "NOT_EXECUTED":
        detail = "端口静态检查未通过；本机卡间数据通路检测未执行"
    else:
        counter_deltas = local.get("error_counters", {}).get("deltas", {})
        counter_increase_count = sum(1 for counters in counter_deltas.values() for value in counters.values() if value > 0)
        detail = f"有向卡对={local.get('direction_count', len(local.get('directions', [])))}; 近 MTU 报文={local.get('packet_size')}B; 失败={failed_count}; 新增错误计数={counter_increase_count}"
    if local.get("error"):
        detail += f"; 错误={local['error']}"
    result = make_record(rule, status, evidence, detail)
    if status == "NOT_EXECUTED":
        result["blocking"] = False
        result["remediation"]["description"] = "使全部 NPU 端口静态就绪后重新检测。"
    if status == "BLOCK" and local.get("failure_kind") in ("capability", "command"):
        result["remediation"]["description"] = "本机卡间测试已执行但证据采集不完整；检查 hccn_tool 执行能力和错误计数查询权限后重试，不得将命令错误当作网络不通。"
    return result


def evaluate_hccs_static(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """根据 HCCS 静态拓扑、health、lane 和速率证据判定节点内链路。"""
    static = probes["hccs_diagnostics"]["static"]
    status = "PASS" if static.get("ok") else "BLOCK"
    detail = (
        f"可见 NPU={len(static.get('visible_npu_ids', []))}; "
        f"可见 die={len(static.get('device_pairs', []))}; "
        f"SIO/HCCS 静态检查={'通过' if status == 'PASS' else '失败'}"
    )
    if static.get("error"):
        detail += f"; 错误={static['error']}"
    result = make_record(rule, status, static, detail)
    if status == "BLOCK" and static.get("failure_kind") == "capability":
        result["remediation"]["description"] = "确认 Docker 已透传全部 A3 NPU、npu-smi 支持 topo/hccs 查询且驱动挂载完整；恢复静态诊断能力后复测。"
    return result


def evaluate_hccs_dynamic(rule: Dict[str, Any], probes: Dict[str, Any]) -> Dict[str, Any]:
    """根据 HCCL 动态测试和 HCCS 错误计数增量判定动态互联场景。"""
    dynamic = probes["hccs_diagnostics"]["dynamic"]
    if not dynamic.get("executed", True):
        status = "NOT_EXECUTED"
    else:
        status = "PASS" if dynamic.get("ok") else "BLOCK"
    detail = f"HCCL all-to-all={'未执行' if status == 'NOT_EXECUTED' else ('通过' if status == 'PASS' else '失败')}"
    if dynamic.get("world_size") is not None:
        detail += f"; ranks={dynamic['world_size']}"
    if dynamic.get("executed"):
        deltas = dynamic.get("error_counters", {}).get("deltas", {})
        increase_count = sum(1 for counters in deltas.values() for values in counters.values() for value in values if value > 0)
        detail += f"; 新增 retry/error 计数={increase_count}"
    if dynamic.get("error"):
        detail += f"; 原因={dynamic['error']}"
    result = make_record(rule, status, dynamic, detail)
    if status == "NOT_EXECUTED" and dynamic.get("failure_kind") == "static_check_failed":
        result["blocking"] = False
        result["remediation"]["description"] = "使全部 A3 SIO/HCCS 静态链路就绪后重新检测。"
    elif status == "NOT_EXECUTED" and dynamic.get("failure_kind") == "devices_busy":
        result["remediation"]["description"] = "排空或迁移当前 NPU 业务进程，在全部可见 NPU 空闲后重新检测；工具不会强制终止业务进程。"
    elif status != "PASS" and dynamic.get("failure_kind") == "capability":
        result["remediation"]["description"] = "确认容器内 Python、torch_npu 和 HCCL 可用，全部 A3 die 已透传且无残留测试进程，修复动态检测能力后复测。"
    return result


def package_version_key(value: str) -> Optional[Tuple[int, ...]]:
    match = re.match(r"^\s*(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?", value, re.IGNORECASE)
    if not match:
        return None
    release = tuple(int(item) for item in match.group(1).split("."))
    release = (release + (0, 0, 0, 0))[:4]
    prerelease = match.group(2)
    if prerelease:
        stage = {"a": -3, "b": -2, "rc": -1}[prerelease.lower()]
        serial = int(match.group(3) or 0)
    elif match.group(4) is not None:
        stage = 1
        serial = int(match.group(4))
    else:
        stage = 0
        serial = 0
    return release + (stage, serial)


EVALUATORS: Dict[str, Callable[[Dict[str, Any], Dict[str, Any]], Optional[Dict[str, Any]]]] = {
    "version_range": evaluate_version,
    "kernel_requirement": evaluate_kernel_requirement,
    "hdk_requirement": evaluate_hdk_requirement,
    "memory_scan": evaluate_memory_scan,
    "docker_prereqs": evaluate_docker_prereqs,
    "manual_confirmation": evaluate_manual_confirmation,
    "package_version": evaluate_package_version,
    "ssd_storage": evaluate_ssd_storage,
    "roce_link": evaluate_roce_link,
    "roce_local": evaluate_roce_local,
    "hccs_static": evaluate_hccs_static,
    "hccs_dynamic": evaluate_hccs_dynamic,
}


def build_probe_plan(rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """按 probe 将适用 Docker 规则分组，供共享探测执行。"""
    plan: Dict[str, List[Dict[str, Any]]] = {}
    for rule in rules:
        if rule["scope"] == "docker":
            plan.setdefault(rule["probe"], []).append(rule)
    return plan


PROBE_LABELS = {
    "memory_scan": "纳管内存检查",
    "hdk": "版本检查",
    "kernel": "Linux kernel 版本检查",
    "manual_confirmation": "人工确认准备",
    "hccs_diagnostics": "A3 节点内互联检查",
    "roce_diagnostics": "RoCE 检查",
    "docker_prereqs": "Docker 设备与挂载检查",
    "package_versions": "后端软件包检查",
    "glibc": "glibc 版本检查",
    "ssd_storage": "SSD Offload 存储检查",
}


def collect_check_results(catalog: Dict[str, Any], context: CheckContext) -> List[Dict[str, Any]]:
    """筛选适用规则，合并执行 probe，并生成问题场景结果。"""
    # 先筛选本次硬件、后端、链路、部署模式和功能开关适用的规则。
    applicable_rules = [
        rule for rule in catalog["rules"]
        if applies(rule, context.hardware, context.backend, context.link_type, context.deployment_mode)
        and feature_applies(rule, context.ssd_offload)
    ]

    # 再按 probe 合并执行，多个规则共享一次底层探测。
    probe_plan = build_probe_plan(applicable_rules)
    progress = context.progress or ProgressReporter(False)
    probe_results = {}
    total = len(probe_plan)
    for index, (name, probe_rules) in enumerate(probe_plan.items(), start=1):
        rule_ids = ",".join(rule["id"] for rule in probe_rules)
        label = f"{rule_ids} {PROBE_LABELS.get(name, name)}"
        with progress.stage(label, index, total):
            probe_results[name] = PROBES[name](context, probe_rules)

    # 最后按规则顺序将探测结果转换为问题场景结果。
    check_results = []
    for rule in applicable_rules:
        if rule["scope"] == "host":
            result = make_record(rule, "NOT_EXECUTED", {}, "当前工具仅支持 Docker；该场景标记为 host，不在容器内执行")
        else:
            result = EVALUATORS[rule["evaluator"]](rule, probe_results)
        if result is not None:
            check_results.append(result)
    return check_results


def is_memory_capacity_shortage(record: Dict[str, Any]) -> bool:
    evidence = record.get("evidence", {})
    return (
        record.get("id") == "MEM-001"
        and record.get("status") == "BLOCK"
        and evidence.get("failure_kind") == "capacity"
        and evidence.get("method") == "a3_mem_scan"
    )


def fix_memory_with_drop_caches(rule: Dict[str, Any], context: CheckContext, record: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """在满足 A3 容量修复条件时执行 Drop Cache 并复测内存容量。"""
    action: Dict[str, Any] = {
        "id": record["id"],
        "type": "drop_caches_then_rescan",
        "status": "SKIPPED",
        "message": "",
        "before_evidence": record.get("evidence", {}),
        "operation": {"sync": None, "drop_caches": {"path": "/proc/sys/vm/drop_caches", "value": 3}},
        "after_evidence": None,
    }
    # 只有 A3 扫描确认容量不足时才允许执行 Drop Cache，其他情况保持人工处理。
    if not is_memory_capacity_shortage(record):
        if record.get("evidence", {}).get("method") == "a2_static_hugepages":
            action["type"] = "manual_static_hugepages"
            action["message"] = "A2静态2MB大页不足或检测能力不足，Drop Cache不会增加静态大页，未执行；请在host侧配置或扩充HugePages后复测。"
        else:
            action["message"] = "内存检查未形成可执行Drop Cache的A3容量证据，未执行；请先修复检测能力后复测。"
        return record, action
    if os.geteuid() != 0:
        action.update(status="FAILED", message="Drop Cache 需要容器内 root 权限，未执行；请调整权限后复测，无法处理时排空业务并重启 host。")
        return record, action

    sync_rc, _sync_out, sync_err = run_cmd(["sync"], timeout=60)
    action["operation"]["sync"] = {"rc": sync_rc, "stderr": redact(sync_err)}
    if sync_rc != 0:
        action.update(status="FAILED", message=f"sync 执行失败，未执行 Drop Cache：{redact(sync_err)}；请修复后复测，无法处理时排空业务并重启 host。")
        return record, action
    try:
        Path("/proc/sys/vm/drop_caches").write_text("3\n", encoding="ascii")
    except OSError as exc:
        action.update(status="FAILED", message=f"无法写入 /proc/sys/vm/drop_caches，未完成修复：{exc}；请调整容器权限后复测，无法处理时排空业务并重启 host。")
        return record, action

    # 修复后的扫描结果替换原场景结果，动作记录同时保留前后证据。
    after_probe = probe_memory_capacity(context.hardware, context.managed_memory_mb)
    after_record = evaluate_memory_scan(rule, {"memory_scan": after_probe})
    action["after_evidence"] = after_probe
    if after_record["status"] == "PASS":
        action.update(status="SUCCESS", message=f"Drop Cache 后全局容量复测通过，匹配粒度：{after_probe.get('matched_granularity_mb')}MB。")
    elif after_probe.get("failure_kind") == "capacity":
        action.update(status="NO_EFFECT", message="Drop Cache 已执行，但A3 1GB/2MB粒度复测的全局可用容量仍未达到目标；请排空业务并重启host后复测。")
    else:
        action.update(status="FAILED", message="Drop Cache 已执行，但复测未取得有效容量证据；请先修复扫描能力，无法处理时排空业务并重启 host。")
    return after_record, action


def execute_fix(catalog: Dict[str, Any], context: CheckContext, check_results: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """执行已授权的本地修复并返回最终场景结果和动作记录。"""
    rules = {rule["id"]: rule for rule in catalog["rules"]}
    final_results = list(check_results)
    actions: List[Dict[str, Any]] = []
    progress = context.progress or ProgressReporter(False)
    for index, record in enumerate(check_results):
        if record["status"] not in ("BLOCK", "MANUAL_REQUIRED", "WARN"):
            continue
        # 当前仅有明确支持的 remediation 执行实际动作，其余统一记录为 MANUAL。
        remediation = record["remediation"]
        with progress.stage(f"修复处理 {record['id']}"):
            if remediation["type"] == "drop_caches_then_rescan":
                final_results[index], action = fix_memory_with_drop_caches(rules[record["id"]], context, record)
                actions.append(action)
            else:
                actions.append({"id": record["id"], "type": remediation["type"], "status": "MANUAL", "message": remediation["description"]})
    return final_results, actions


def build_repair_summary(requested: bool, actions: List[Dict[str, Any]], before_summary: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    statuses = ("SUCCESS", "NO_EFFECT", "FAILED", "SKIPPED", "MANUAL")
    return {
        "requested": requested,
        "before_summary": before_summary if requested else None,
        "action_count": len(actions),
        "status_counts": {status: sum(1 for action in actions if action["status"] == status) for status in statuses},
        "actions": actions,
    }


def result_exit_code(check_results: List[Dict[str, Any]]) -> int:
    if any(is_blocking_result(result) for result in check_results):
        return 20
    if any(result["status"] in ("WARN", "UNKNOWN") for result in check_results):
        return 10
    return 0


def build_summary(check_results: List[Dict[str, Any]], exit_code: int) -> Dict[str, Any]:
    """根据场景结果生成总体状态、计数和阻塞项摘要。"""
    blockers = [result for result in check_results if is_blocking_result(result)]
    automatic_blockers = [result for result in blockers if result["status"] == "BLOCK"]
    warnings = [result for result in check_results if result["status"] == "WARN"]
    return {
        "overall_status": "BLOCK" if exit_code == 20 else ("WARN" if exit_code == 10 else "PASS"),
        "blocking_count": len(blockers),
        "automatic_block_count": len(automatic_blockers),
        "blocking_not_executed_count": sum(1 for result in blockers if result["status"] == "NOT_EXECUTED"),
        "warning_count": len(warnings),
        "pass_count": sum(1 for result in check_results if result["status"] == "PASS"),
        "not_applicable_count": sum(1 for result in check_results if result["status"] == "NOT_APPLICABLE"),
        "not_executed_count": sum(1 for result in check_results if result["status"] == "NOT_EXECUTED"),
        "manual_required_count": sum(1 for result in check_results if result["status"] == "MANUAL_REQUIRED"),
        "blockers": [{"id": result["id"], "problem": result["problem"], "detail": result["detail"]} for result in blockers],
        "warnings": [{"id": result["id"], "problem": result["problem"], "detail": result["detail"]} for result in warnings],
    }


def format_argument_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_text(result: Dict[str, Any], canonical_result_path: Optional[Path] = None) -> str:
    """将结构化检测结果渲染为面向使用者的 TEXT 报告。"""
    statuses = ("BLOCK", "MANUAL_REQUIRED", "WARN", "PASS", "UNKNOWN", "NOT_EXECUTED", "NOT_APPLICABLE")
    counts = {status: sum(1 for record in result["check_results"] if record["status"] == status) for status in statuses}
    summary = result["summary"]
    arguments = result["invocation"]["arguments"]
    repair = result["repair"]
    # 报告头部先展示时间和本次最终生效参数。
    lines = [
        f"kvpool 环境检测报告 v{result['tool_version']} | run_id={result['run_id']}",
        "=" * 72,
        f"检测时间: {result['timestamp_iso']}",
        "运行参数:",
        *(f"- {key}: {format_argument_value(value)}" for key, value in arguments.items()),
        "",
        f"最终结论: {summary['overall_status']} | 阻塞={summary['blocking_count']}（自动检测={summary['automatic_block_count']}，人工确认={summary['manual_required_count']}，未执行={summary['blocking_not_executed_count']}） 警告={summary['warning_count']} 通过={summary['pass_count']} 不适用={summary['not_applicable_count']}",
        "状态统计: " + ", ".join(f"{key}={value}" for key, value in counts.items()),
    ]
    if repair["requested"]:
        repair_counts = repair["status_counts"]
        lines.append(
            "修复结果: "
            + ", ".join(f"{status}={repair_counts[status]}" for status in ("SUCCESS", "NO_EFFECT", "FAILED", "SKIPPED", "MANUAL"))
        )
        if repair["actions"]:
            lines.extend(["", "修复执行结果："])
            lines.extend(f"- {item['id']} {item['status']}: {item['message']}" for item in repair["actions"])
    # 汇总建议只展示尚未执行修复的阻塞项和警告，避免与修复结果重复。
    blockers = [record for record in result["check_results"] if is_blocking_result(record)]
    warnings = [record for record in result["check_results"] if record["status"] == "WARN"]
    if blockers and not repair["requested"]:
        lines.extend(["", "阻塞项处理建议："])
        lines.extend(f"- {record['id']}: {record['remediation']['description']}" for record in blockers)
    if warnings and not repair["requested"]:
        lines.extend(["", "建议确认:"])
        lines.extend(f"- {record['id']}: {record['remediation']['description']}" for record in warnings)
    for record in result["check_results"]:
        applicability = record["applicability"]
        conclusions = {
            "PASS": "未发现该问题",
            "BLOCK": "已发现该问题",
            "WARN": "发现风险，需要确认",
            "MANUAL_REQUIRED": "需要人工确认",
            "NOT_EXECUTED": "当前环境未执行",
            "NOT_APPLICABLE": "当前部署模式不适用",
            "UNKNOWN": "无法确认",
        }
        lines.extend(["", f"[{record['status']}] {record['id']}", f"问题场景: {record['problem']}", f"结论: {conclusions.get(record['status'], '无法确认')}"])
        positioning = record.get("positioning")
        if positioning:
            lines.extend([
                f"检测层级: {positioning['layer']}",
                f"检测对象: {positioning['target']}",
                f"覆盖范围: {positioning['coverage']}",
                f"不包含: {'；'.join(positioning['excludes'])}",
            ])
        if record["status"] != "PASS":
            lines.append(f"影响: {record['impact']}")
        lines.extend([
            f"详情: {record['detail']}",
            f"检测证据: {record['evidence_method']}",
            f"适用硬件: {','.join(applicability['hardware'])} | 适用后端: {','.join(applicability['backends'])}",
            f"当前是否阻塞: {'是' if is_blocking_result(record) else '否'}",
        ])
    references = result.get("reference_documents", [])
    if references:
        lines.extend(["", "参考文档："])
        lines.extend(f"- {item['title']}：{item['url']}" for item in references)
    if canonical_result_path is None:
        lines.extend(["", "输出说明: 当前仅回显检查报告；使用 --output-dir 可同时生成完整结果（JSON）和检查报告（TEXT）。"])
    else:
        lines.extend(["", f"完整结果（JSON）: {canonical_result_path}"])
    return "\n".join(lines) + "\n"


def write_output_bundle(output_dir: Path, result: Dict[str, Any]) -> Tuple[Path, Path]:
    """使用同一 run_id 写入 JSON 完整结果和 TEXT 检查报告。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir.resolve()
    prefix = f"kvpool_envcheck_{result['run_id']}"
    result_path = output_dir / f"{prefix}.result.json"
    report_path = output_dir / f"{prefix}.report.txt"
    if result_path.exists() or report_path.exists():
        raise OSError(f"输出文件已存在: {prefix}")

    json_tmp = output_dir / f".{result_path.name}.tmp"
    report_tmp = output_dir / f".{report_path.name}.tmp"
    result_committed = False
    try:
        write_utf8(json_tmp, json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        write_utf8(report_tmp, render_text(result, result_path))
        os.replace(json_tmp, result_path)
        result_committed = True
        os.replace(report_tmp, report_path)
    except Exception:
        if result_committed:
            result_path.unlink(missing_ok=True)
        raise
    finally:
        json_tmp.unlink(missing_ok=True)
        report_tmp.unlink(missing_ok=True)
    return result_path, report_path


def render_completion(result: Dict[str, Any], result_path: Path, report_path: Path) -> str:
    return "\n".join([
        "检测完成",
        f"最终结论: {result['summary']['overall_status']}",
        f"run_id: {result['run_id']}",
        f"完整结果（JSON）: {result_path}",
        f"检查报告（TEXT）: {report_path}",
    ]) + "\n"


def panorama(catalog: Dict[str, Any]) -> str:
    lines = ["| 问题ID | 问题 | 检测定位 | 影响 | 检测证据 | 判定规则 | 修复方法 | 是否阻塞 | 适用硬件 | 适用后端 | 适用链路 | 适用部署 | 运行位置 | 实现状态 |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for rule in catalog["rules"]:
        params = json.dumps(rule["parameters"], ensure_ascii=False, separators=(",", ":"))
        positioning = rule.get("positioning")
        position_text = "-" if not positioning else f"{positioning['layer']}；{positioning['target']}；{positioning['coverage']}；不包含：{'、'.join(positioning['excludes'])}"
        lines.append(f"| {rule['id']} | {rule['problem']} | {position_text} | {rule['impact']} | {rule['evidence_method']} | `{rule['evaluator']}` `{params}` | {rule['remediation']['description']} | {'是' if rule['blocking'] else '否'} | {','.join(rule['hardware'])} | {','.join(rule['backends'])} | {','.join(rule.get('link_types', ['all']))} | {','.join(rule.get('deployment_modes', ['all']))} | {rule['scope']} | 已实现 |")
    return "\n".join(lines)


def write_panorama(path: Path, catalog: Dict[str, Any]) -> None:
    content = read_utf8(path) if path.exists() else "# kvpool 问题检测全景\n\n"
    begin = "<!-- BEGIN GENERATED RULE PANORAMA -->"
    end = "<!-- END GENERATED RULE PANORAMA -->"
    generated = begin + "\n\n" + panorama(catalog) + "\n\n" + end
    if begin in content and end in content:
        content = content.split(begin, 1)[0] + generated + content.split(end, 1)[1]
    else:
        content = content.rstrip() + "\n\n" + generated + "\n"
    write_utf8(path, content)


def load_catalog(path: Path) -> Dict[str, Any]:
    """读取并校验 rules.json，返回可用于检测的规则目录。"""
    try:
        catalog = json.loads(read_utf8(path))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"无法读取规则目录: {exc}")
    validate_catalog(catalog)
    return catalog


def build_parser(catalog_data: Dict[str, Any]) -> argparse.ArgumentParser:
    """根据规则目录构造检测、输出、修复和规则管理参数。"""
    hardware_metavar = "{" + ",".join(catalog_data["supported_hardware"]) + "}"
    backend_metavar = "{" + ",".join(catalog_data["supported_backends"]) + "}"
    link_type_metavar = "{" + ",".join(catalog_data["supported_link_types"]) + "}"
    deployment_mode_metavar = "{" + ",".join(catalog_data["supported_deployment_modes"]) + "}"
    parser = argparse.ArgumentParser(
        description=(
            "vLLM-Ascend kvpool 离线部署环境检测 v14.1.1\n"
            "仅支持在 Docker 容器内运行；检测过程不联网，默认不修改环境。"
        ),
        epilog=(
            "示例：\n"
            "  直接回显检查报告：\n"
            "    python3 kvpool_envcheck.py --hardware A3 --backend memcache --managed-memory-mb 32768 --deployment-mode multi-node --link-type hccs\n\n"
            "  同时生成完整结果（JSON）和检查报告（TEXT）：\n"
            "    python3 kvpool_envcheck.py --hardware A3 --backend memcache --managed-memory-mb 32768 --deployment-mode multi-node --link-type hccs --output-dir ./results\n\n"
            "  授权并执行支持的本地修复：\n"
            "    python3 kvpool_envcheck.py --hardware A3 --backend memcache --managed-memory-mb 32768 --deployment-mode multi-node --link-type hccs --fix --output-dir ./results\n\n"
            "  修改 rules.json 后校验并同步设计文档：\n"
            "    python3 kvpool_envcheck.py --validate-catalog\n"
            "    python3 kvpool_envcheck.py --sync-panorama DESIGN.md\n\n"
            "退出码：0=通过  10=存在警告  20=存在阻塞项  2=输入、规则或输出错误"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    general = parser.add_argument_group("通用参数")
    general.add_argument("-h", "--help", action="help", help="显示帮助并退出")
    general.add_argument("--catalog", type=Path, metavar="FILE", default=DEFAULT_CATALOG, help="规则文件（默认：工具目录下的 rules.json）")

    detection = parser.add_argument_group("检测参数（检测模式必填）")
    detection.add_argument("--hardware", metavar=hardware_metavar, help="硬件平台；支持范围来自规则文件，且必须与当前环境识别结果一致")
    detection.add_argument("--backend", metavar=backend_metavar, help="KV Pool 后端；支持范围来自规则文件")
    detection.add_argument("--managed-memory-mb", type=int, metavar="MB", help="后端纳管内存总量，单位 MB，必须大于 0（示例：32768）")
    detection.add_argument("--deployment-mode", metavar=deployment_mode_metavar, help="部署规模：single-node 或 multi-node；影响KERNEL-001判定")
    detection.add_argument("--link-type", metavar=link_type_metavar, help="A3后端实际通信链路：roce 或 hccs；A2只能使用roce")

    ssd = parser.add_argument_group("SSD Offload（可选）")
    ssd.add_argument("--ssd-offload", action="store_true", help="启用 SSD Offload 依赖检查")
    ssd.add_argument("--ssd-path", metavar="PATH", help="SSD 路径；只能与 --ssd-offload 同时使用")

    output = parser.add_argument_group("输出参数（可选）")
    output.add_argument("--output-dir", type=Path, metavar="DIR", help="同时保存完整结果（JSON）和检查报告（TEXT）的目录；不指定时仅回显检查报告")
    output.add_argument("--progress", choices=("auto", "always", "never"), default="auto", help="实时进度：auto=前台终端显示（默认），always=始终显示，never=关闭")

    repair = parser.add_argument_group("修复流程（可选）")
    repair.add_argument("--fix", action="store_true", help="授权并执行支持的本地修复；其余修复动作标记为 MANUAL")

    catalog = parser.add_argument_group("规则管理（无需检测参数）")
    catalog.add_argument("--validate-catalog", action="store_true", help="校验规则文件后退出")
    catalog.add_argument("--list-rules", action="store_true", help="列出全部问题场景后退出")
    catalog.add_argument("--describe-rule", metavar="ID", help="输出指定问题场景的完整规则")
    catalog.add_argument("--sync-panorama", type=Path, metavar="DESIGN_FILE", help="修改 rules.json 后，将规则全景同步到设计文档的生成区")
    return parser


def preparse_catalog_path(argv: List[str]) -> Path:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    args, _unknown = parser.parse_known_args(argv)
    return args.catalog


def load_cli_catalog(argv: List[str]) -> Tuple[Dict[str, Any], argparse.ArgumentParser]:
    """读取用户指定的规则目录，并构造使用该目录的完整 parser。"""
    catalog_path = preparse_catalog_path(argv)
    catalog = load_catalog(catalog_path)
    return catalog, build_parser(catalog)


def run_catalog_command(args: argparse.Namespace, catalog: Dict[str, Any]) -> Optional[int]:
    """执行规则管理命令；未请求管理命令时返回 None。"""
    if args.validate_catalog:
        print(f"catalog valid: schema={catalog['schema_version']} rules={len(catalog['rules'])}")
        return 0
    if args.list_rules:
        for rule in catalog["rules"]:
            print(f"{rule['id']}\t{rule['problem']}\t{'BLOCK' if rule['blocking'] else 'WARN/PASS'}")
        return 0
    if args.describe_rule:
        rule = next((item for item in catalog["rules"] if item["id"] == args.describe_rule), None)
        if rule is None:
            raise InputError(f"未知问题 ID: {args.describe_rule}")
        print(json.dumps(rule, ensure_ascii=False, indent=2))
        return 0
    if args.sync_panorama:
        write_panorama(args.sync_panorama, catalog)
        print(f"规则全景已同步: {args.sync_panorama}")
        return 0
    return None


def main(argv: Optional[List[str]] = None) -> int:
    """解析命令行参数并执行规则管理或环境检测流程。"""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        # 读取规则目录并据此构造支持范围动态变化的命令行解析器。
        catalog, parser = load_cli_catalog(raw_argv)
        args = parser.parse_args(raw_argv)

        # 规则查询、校验和文档同步命令到此结束，不进入环境检测流程。
        catalog_exit_code = run_catalog_command(args, catalog)
        if catalog_exit_code is not None:
            return catalog_exit_code

        # 校验运行位置、必填参数、功能参数和硬件型号一致性。
        progress = ProgressReporter.from_mode(args.progress)
        effective_progress = "always" if progress.enabled else "never"
        with progress.stage("输入与硬件校验"):
            if not args.hardware or not args.backend or not args.deployment_mode or not args.link_type:
                raise InputError("检测模式必须同时提供 --hardware、--backend、--deployment-mode 和 --link-type")
            if not is_docker_runtime():
                raise InputError("仅支持在 Docker 容器内运行")
            if not args.managed_memory_mb or args.managed_memory_mb <= 0:
                raise InputError("检测模式必须提供大于 0 的 --managed-memory-mb")
            if args.ssd_path and not args.ssd_offload:
                raise InputError("--ssd-path 只能与 --ssd-offload 同时使用")
            hardware, backend, link_type, deployment_mode, _hardware_identification = validate_inputs(catalog, args.hardware, args.backend, args.link_type, args.deployment_mode)

        # 执行适用场景的探测并形成修复前汇总。
        context = CheckContext(hardware=hardware, backend=backend, managed_memory_mb=args.managed_memory_mb, deployment_mode=deployment_mode, link_type=link_type, ssd_offload=args.ssd_offload, ssd_path=args.ssd_path, progress=progress)
        check_results = collect_check_results(catalog, context)
        before_exit_code = result_exit_code(check_results)
        before_summary = build_summary(check_results, before_exit_code)

        # 只有显式 --fix 时才执行已授权的本地修复，并以复测结果作为最终结果。
        if args.fix:
            check_results, actions = execute_fix(catalog, context, check_results)
        else:
            actions = []

        # 构建包含输入、汇总、场景结果、修复记录和参考资料的一次性结果模型。
        exit_code = result_exit_code(check_results)
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp = int(now.timestamp())
        run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(4)}"
        invocation = {
            "arguments": {
                "hardware": hardware,
                "backend": backend,
                "managed_memory_mb": args.managed_memory_mb,
                "deployment_mode": deployment_mode,
                "link_type": link_type,
                "ssd_offload": args.ssd_offload,
                "ssd_path": args.ssd_path,
                "fix": args.fix,
                "output_dir": str(args.output_dir.resolve()) if args.output_dir else None,
                "catalog": str(args.catalog.resolve()),
                "progress": effective_progress,
            }
        }
        result = {"tool_version": TOOL_VERSION, "result_schema_version": RESULT_SCHEMA_VERSION, "run_id": run_id, "timestamp": timestamp, "timestamp_iso": now.isoformat(), "invocation": invocation, "summary": build_summary(check_results, exit_code), "repair": build_repair_summary(args.fix, actions, before_summary), "check_results": check_results, "reference_documents": REFERENCE_DOCUMENTS, "exit_code": exit_code}

        # 有输出目录时同时落盘 JSON/TEXT，否则只回显 TEXT 报告。
        if args.output_dir:
            result_path, report_path = write_output_bundle(args.output_dir, result)
            sys.stdout.write(render_completion(result, result_path, report_path))
        else:
            sys.stdout.write(render_text(result))
        return exit_code
    except (CatalogError, InputError, OSError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("检测已由用户中断", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
