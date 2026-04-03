"""
UDS 0x31 RoutineControl 渗透测试脚本
被测件诊断请求ID: 0x77E
被测件诊断响应ID: 0x7BE
接入方式: Windows 通过 SSH 连接 Kali，调用 /home/kali/tool/can-canfd/tool (PCAN)

依赖: pip install paramiko

使用方法:
  python uds_31_test.py
  python uds_31_test.py --start 0x0000 --end 0xFFFF
  python uds_31_test.py --start 0xF000 --end 0xFFFF  # 只扫描OEM段
"""

import threading
import time
import datetime
import re
import argparse
import os

try:
    import paramiko
except ImportError:
    print("[-] 缺少 paramiko，请先执行: pip install paramiko")
    raise

# ============ 配置项 ============
SSH_HOST    = "172.16.96.129"
SSH_PORT    = 22
SSH_USER    = "kali"
SSH_PASS    = "kali"

TOOL_PATH   = "/home/kali/tool/can-canfd/tool"
REQ_ID      = "77E"
RESP_ID     = "7BE"
CANFD_ARGS  = f"set -s {REQ_ID} -t {RESP_ID} --canfd"

TIMEOUT_PER_REQ = 0.08  # 单条请求超时(秒)
NUM_THREADS     = 20    # 并行 SSH 会话数

# UDS 否定响应码
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# 已知高危 Routine ID
HIGH_RISK_IDS = {
    0xFF00: "EraseMemory",
    0xFF01: "CheckProgrammingDependencies",
    0x0202: "CheckMemory",
    0x0203: "StopFaultDetection",
    0x0204: "CheckProgrammingPreconditions",
    0xF000: "OEM_Custom_F000",
    0xFF02: "EraseFlash",
    0x0205: "EnableDiagnosticSessionControl",
}


class ToolSession:
    """通过 SSH 连接 Kali，管理与 can-canfd/tool 的交互式会话"""

    def __init__(self):
        self.ssh = None
        self.channel = None
        self.output_buf = ""
        self.output_lines = []
        self.lock = threading.Lock()
        self._reader_thread = None

    def start(self, thread_id=0):
        print(f"[线程{thread_id}] SSH 连接 Kali: {SSH_USER}@{SSH_HOST}:{SSH_PORT}")
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER,
                         password=SSH_PASS, timeout=10)
        print(f"[线程{thread_id}] SSH 连接成功，启动工具...")

        # 开启交互式 shell
        self.channel = self.ssh.invoke_shell(width=220, height=50)
        self.channel.settimeout(0.1)

        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()
        time.sleep(1.0)

        # 启动工具
        self._send_cmd(TOOL_PATH)
        time.sleep(1.5)
        with self.lock:
            self.output_lines.clear()

    def _read_output(self):
        """持续从 SSH channel 读取数据，按行分割存入 output_lines"""
        buf = ""
        while True:
            try:
                chunk = self.channel.recv(4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip("\r")
                    if line.strip():
                        with self.lock:
                            self.output_lines.append(line)
            except Exception:
                time.sleep(0.02)

    def _send_cmd(self, cmd):
        self.channel.send(cmd + "\n")

    def _collect_response(self, timeout=TIMEOUT_PER_REQ):
        """等待并收集响应行，收到 Receive 行后提前返回"""
        deadline = time.time() + timeout
        collected = []
        last_len = 0
        while time.time() < deadline:
            time.sleep(0.05)
            with self.lock:
                new_lines = self.output_lines[last_len:]
                last_len = len(self.output_lines)
            collected.extend(new_lines)
            if any("Receive" in l for l in new_lines):
                time.sleep(0.05)
                with self.lock:
                    collected.extend(self.output_lines[last_len:])
                break
        return collected

    def configure(self):
        """设置 CAN 参数并建立连接"""
        self._send_cmd(CANFD_ARGS)
        time.sleep(0.5)
        self._send_cmd("connect")
        time.sleep(1.5)
        with self.lock:
            self.output_lines.clear()

    def send_and_recv(self, hex_data, timeout=TIMEOUT_PER_REQ):
        """发送一条 send 命令，返回响应行列表"""
        with self.lock:
            self.output_lines.clear()
        self._send_cmd(f"send {hex_data}")
        return self._collect_response(timeout)

    def close(self):
        try:
            self._send_cmd("exit")
            time.sleep(0.3)
        except Exception:
            pass
        if self.channel:
            self.channel.close()
        if self.ssh:
            self.ssh.close()
        print("[*] SSH 连接已关闭")


# ============ 响应解析 ============

def parse_lines(lines, routine_id):
    """
    从输出行中提取响应结果
    返回: (resp_type, nrc_code, raw_resp)
      resp_type: 'positive' | 'negative' | 'timeout' | 'no_response'
    """
    recv_line = None
    for line in lines:
        if "Receive" in line and "7BE" in line.upper():
            recv_line = line
            break

    if recv_line is None:
        return "timeout", None, None

    # 提取十六进制字节
    hex_match = re.findall(r'\b([0-9A-Fa-f]{2})\b', recv_line.split(":")[-1])
    if not hex_match:
        return "timeout", None, None

    resp_bytes = [int(b, 16) for b in hex_match]
    raw = " ".join(hex_match).upper()

    if len(resp_bytes) == 0:
        return "timeout", None, raw

    if resp_bytes[0] == 0x71:
        return "positive", None, raw

    if resp_bytes[0] == 0x7F:
        nrc_code = resp_bytes[2] if len(resp_bytes) >= 3 else 0
        return "negative", nrc_code, raw

    return "no_response", None, raw


# ============ 主测试流程 ============

def switch_session(session, session_id=0x03):
    """切换诊断会话"""
    print(f"\n[*] 切换到诊断会话 0x{session_id:02X}...")
    lines = session.send_and_recv(f"10{session_id:02X}", timeout=2.0)
    for line in lines:
        print(f"    {line}")
    for line in lines:
        if "Receive" in line and "50" in line:
            print(f"[+] 会话切换成功")
            return True
    print(f"[-] 会话切换失败或无响应")
    return False



def _worker(thread_id, id_list, results, results_lock, progress, progress_lock):
    """单条发送模式：每次发送一条请求"""
    session = ToolSession()
    try:
        session.start(thread_id)
        session.configure()
        session.send_and_recv("1003", timeout=1.0)
        time.sleep(0.3)

        for idx, rid in enumerate(id_list):
            hi = (rid >> 8) & 0xFF
            lo = rid & 0xFF
            req_hex = f"3101{hi:02X}{lo:02X}"
            lines = session.send_and_recv(req_hex, timeout=TIMEOUT_PER_REQ)
            resp_type, nrc_code, raw = parse_lines(lines, rid)

            with results_lock:
                risk_tag = f" ★高危:{HIGH_RISK_IDS[rid]}" if rid in HIGH_RISK_IDS else ""
                if resp_type == "positive":
                    results["positive"].append((rid, raw))
                    print(f"  [!!!] 0x{rid:04X}{risk_tag} → 肯定响应!")
                    print(f"        请求: 31 01 {hi:02X} {lo:02X}")
                    print(f"        响应: {raw}")
                elif resp_type == "negative":
                    nrc_name = NRC.get(nrc_code, f"0x{nrc_code:02X}")
                    if nrc_code == 0x22:
                        results["conditions_not_correct"].append((rid, nrc_code, raw))
                        print(f"  [!]  0x{rid:04X}{risk_tag} → conditionsNotCorrect")
                    elif nrc_code == 0x33:
                        results["security_denied"].append((rid, nrc_code, raw))
                        print(f"  [!]  0x{rid:04X}{risk_tag} → securityAccessDenied")
                    elif nrc_code == 0x31:
                        results["out_of_range"].append((rid, nrc_code, raw))
                        if rid in HIGH_RISK_IDS:
                            print(f"       0x{rid:04X}{risk_tag} → requestOutOfRange")
                    else:
                        results["other_negative"].append((rid, nrc_code, raw))
                        if rid in HIGH_RISK_IDS:
                            print(f"       0x{rid:04X} → NRC {nrc_name}")
                else:
                    results["timeout"].append(rid)

            with progress_lock:
                progress[0] += 1

            # 每 500 个发一次 testerPresent 保活
            if (idx + 1) % 500 == 0:
                session.send_and_recv("3E00", timeout=0.3)

    except Exception as e:
        print(f"  [线程{thread_id}] 异常: {e}")
    finally:
        session.close()


def scan_routine_ids(start_id=0x0000, end_id=0xFFFF, num_threads=4):
    """
    多线程遍历 Routine ID，发送 31 01 XX XX
    返回分类结果字典
    """
    results = {
        "positive": [],
        "conditions_not_correct": [],
        "security_denied": [],
        "out_of_range": [],
        "other_negative": [],
        "timeout": [],
    }
    results_lock = threading.Lock()
    progress = [0]
    progress_lock = threading.Lock()

    all_ids = list(range(start_id, end_id + 1))
    total = len(all_ids)

    # 按线程数均分 ID 列表
    chunks = [all_ids[i::num_threads] for i in range(num_threads)]

    est_min = total * TIMEOUT_PER_REQ / num_threads / 60
    print(f"\n[*] 开始遍历 Routine ID: 0x{start_id:04X} ~ 0x{end_id:04X}，共 {total} 个")
    print(f"    线程数: {num_threads}  预计耗时: {est_min:.1f} 分钟\n")
    print(f"[*] 正在初始化 {num_threads} 个 SSH 会话，请稍候...")

    threads = []
    for i, chunk in enumerate(chunks):
        t = threading.Thread(
            target=_worker,
            args=(i, chunk, results, results_lock, progress, progress_lock),
            daemon=True,
        )
        threads.append(t)
        t.start()
        time.sleep(0.5)  # 错开各线程启动，避免同时建立 SSH

    # 进度监控主循环
    start_time = time.time()
    while any(t.is_alive() for t in threads):
        time.sleep(10)
        with progress_lock:
            done = progress[0]
        elapsed = time.time() - start_time
        speed = done / elapsed if elapsed > 0 else 0
        remain = (total - done) / speed / 60 if speed > 0 else 0
        print(f"  --- 进度: {done}/{total} ({done/total*100:.1f}%)  "
              f"速度: {speed:.1f}/s  剩余: {remain:.1f}分钟 ---")

    for t in threads:
        t.join()

    return results


def deep_test_positive(session, positive_ids):
    """对肯定响应的 ID 进行深度测试"""
    if not positive_ids:
        return []

    print(f"\n[*] 对 {len(positive_ids)} 个肯定响应 ID 进行深度测试...")
    deep_results = []

    for rid, _ in positive_ids:
        hi = (rid >> 8) & 0xFF
        lo = rid & 0xFF
        risk_tag = HIGH_RISK_IDS.get(rid, "")
        print(f"\n  [*] 深度测试 0x{rid:04X} {risk_tag}")

        # stopRoutine
        lines = session.send_and_recv(f"3102{hi:02X}{lo:02X}", timeout=1.5)
        _, _, raw_stop = parse_lines(lines, rid)
        print(f"      stopRoutine (3102):           {raw_stop or '无响应'}")

        # requestRoutineResults
        lines = session.send_and_recv(f"3103{hi:02X}{lo:02X}", timeout=1.5)
        _, _, raw_result = parse_lines(lines, rid)
        print(f"      requestRoutineResults (3103): {raw_result or '无响应'}")

        deep_results.append({
            "id": rid,
            "risk": risk_tag,
            "stop_resp": raw_stop,
            "result_resp": raw_result,
        })
        time.sleep(0.1)

    return deep_results


def gen_report(results, deep_results, start_id, end_id):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(report_dir, f"uds_31_report_{now}.txt")

    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("UDS 0x31 RoutineControl 渗透测试报告\n")
        f.write(f"测试时间: {now}\n")
        f.write(f"诊断请求ID: 0x{REQ_ID}  响应ID: 0x{RESP_ID}\n")
        f.write(f"扫描范围: 0x{start_id:04X} ~ 0x{end_id:04X}\n")
        f.write(f"接入方式: Kali PCAN ({TOOL_PATH})\n")
        f.write("=" * 60 + "\n\n")

        # 汇总
        f.write("=== 一、扫描结果汇总 ===\n")
        f.write(f"  肯定响应 (71):              {len(results['positive'])} 个\n")
        f.write(f"  conditionsNotCorrect (22):  {len(results['conditions_not_correct'])} 个\n")
        f.write(f"  securityAccessDenied (33):  {len(results['security_denied'])} 个\n")
        f.write(f"  requestOutOfRange (31):     {len(results['out_of_range'])} 个\n")
        f.write(f"  其他否定响应:               {len(results['other_negative'])} 个\n")
        f.write(f"  超时/无响应:                {len(results['timeout'])} 个\n\n")

        # 肯定响应详情
        f.write("=== 二、肯定响应 ID 列表（高危）===\n")
        if results["positive"]:
            for rid, raw in results["positive"]:
                risk = HIGH_RISK_IDS.get(rid, "")
                f.write(f"  0x{rid:04X}  {risk}\n")
                f.write(f"    响应: {raw}\n")
        else:
            f.write("  无\n")

        # conditionsNotCorrect（服务存在但条件不满足）
        f.write("\n=== 三、服务存在但条件不满足 (NRC 0x22) ===\n")
        if results["conditions_not_correct"]:
            for rid, nrc, raw in results["conditions_not_correct"]:
                risk = HIGH_RISK_IDS.get(rid, "")
                f.write(f"  0x{rid:04X}  {risk}  → {raw}\n")
        else:
            f.write("  无\n")

        # 需要安全访问
        f.write("\n=== 四、需要安全访问解锁 (NRC 0x33) ===\n")
        if results["security_denied"]:
            for rid, nrc, raw in results["security_denied"]:
                risk = HIGH_RISK_IDS.get(rid, "")
                f.write(f"  0x{rid:04X}  {risk}  → {raw}\n")
        else:
            f.write("  无\n")

        # 深度测试结果
        if deep_results:
            f.write("\n=== 五、肯定响应 ID 深度测试 ===\n")
            for item in deep_results:
                f.write(f"\n  Routine ID: 0x{item['id']:04X}  {item['risk']}\n")
                f.write(f"    stopRoutine (3102):           {item['stop_resp'] or '无响应'}\n")
                f.write(f"    requestRoutineResults (3103): {item['result_resp'] or '无响应'}\n")

        # 风险评估
        f.write("\n=== 六、安全风险评估 ===\n")
        positive_count = len(results["positive"])
        if positive_count > 0:
            f.write(f"  【高危】发现 {positive_count} 个 Routine ID 可被无授权直接启动\n")
            for rid, _ in results["positive"]:
                risk = HIGH_RISK_IDS.get(rid, "未知功能")
                f.write(f"    - 0x{rid:04X}: {risk}\n")
            f.write("  建议: 对所有 0x31 服务调用增加安全访问 (0x27) 前置验证\n")
        elif results["conditions_not_correct"] or results["security_denied"]:
            f.write("  【中危】存在受保护的 Routine ID，需进一步验证安全机制强度\n")
        else:
            f.write("  【低危】未发现可直接调用的 Routine ID\n")

    return path


def main():
    parser = argparse.ArgumentParser(description="UDS 0x31 RoutineControl 渗透测试")
    parser.add_argument("--start",   type=lambda x: int(x, 16), default=0x0000,
                        help="起始 Routine ID (十六进制, 默认 0x0000)")
    parser.add_argument("--end",     type=lambda x: int(x, 16), default=0xFFFF,
                        help="结束 Routine ID (十六进制, 默认 0xFFFF)")
    parser.add_argument("--threads", type=int, default=4,
                        help="并行线程数 (默认 4，每线程独立 SSH 会话)")
    args = parser.parse_args()

    print("=" * 60)
    print("UDS 0x31 RoutineControl 渗透测试")
    print(f"请求ID: 0x{REQ_ID}  响应ID: 0x{RESP_ID}")
    print(f"扫描范围: 0x{args.start:04X} ~ 0x{args.end:04X}")
    print(f"并行线程: {args.threads}")
    print("=" * 60)

    try:
        # 多线程遍历扫描
        results = scan_routine_ids(args.start, args.end, args.threads)

        # 深度测试肯定响应的 ID（单线程）
        if results["positive"]:
            session = ToolSession()
            session.start()
            session.configure()
            session.send_and_recv("1003", timeout=1.0)
            deep_results = deep_test_positive(session, results["positive"])
            session.close()
        else:
            deep_results = []

        # 生成报告
        report_path = gen_report(results, deep_results, args.start, args.end)
        print(f"\n[+] 测试报告已保存: {report_path}")

        # 打印汇总
        print("\n" + "=" * 40)
        print("扫描结果汇总:")
        print(f"  肯定响应:              {len(results['positive'])} 个")
        print(f"  conditionsNotCorrect:  {len(results['conditions_not_correct'])} 个")
        print(f"  securityAccessDenied:  {len(results['security_denied'])} 个")
        print(f"  requestOutOfRange:     {len(results['out_of_range'])} 个")
        print(f"  超时/无响应:           {len(results['timeout'])} 个")

        if results["positive"]:
            print(f"\n  [!!!] 发现 {len(results['positive'])} 个可直接调用的 Routine ID!")
            for rid, raw in results["positive"]:
                print(f"        0x{rid:04X} → {raw}")

    except KeyboardInterrupt:
        print("\n[!] 用户中断测试")


if __name__ == "__main__":
    main()
