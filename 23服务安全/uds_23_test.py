"""
UDS 0x23 ReadMemoryByAddress 渗透测试脚本
接入方式: CANoe 12 CAN 总线
诊断请求 ID: 0x741
诊断响应 ID: 0x749

【使用前必须完成的 CANoe 配置】
1. 打开 CANoe 12，加载本目录下的 Configuration1.cfg
2. 在 Hardware 配置中，将 CAN Channel 1 绑定到实际硬件接口
   (如 Vector VN1610/VN1630 等)，波特率设置为车机 CAN 总线波特率
3. 点击 Start Measurement (绿色三角) 启动测量
4. 确认 CANoe Trace 窗口能看到 CAN 报文后，再运行本脚本
"""

import win32com.client
import time
import datetime
import sys

# ============ 配置项 ============
REQ_ID   = 0x741   # 诊断请求 CAN ID
RESP_ID  = 0x749   # 诊断响应 CAN ID
TIMEOUT  = 2.0     # 等待响应超时(秒)

# UDS 否定响应码
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# ============ CANoe 通信 ============

def get_canoe_app():
    try:
        app = win32com.client.Dispatch("CANoe.Application")
        print(f"[+] CANoe 连接成功: {app.Version}")
        return app
    except Exception as e:
        print(f"[-] CANoe 连接失败: {e}")
        sys.exit(1)


def check_measurement(app):
    if not app.Measurement.Running:
        print("[!] CANoe Measurement 未运行，尝试启动...")
        app.Measurement.Start()
        time.sleep(3)
        if not app.Measurement.Running:
            print("[-] Measurement 启动失败，请手动在 CANoe 界面点击 Start")
            sys.exit(1)
    print("[+] Measurement 运行中")


def send_uds_raw(app, req_id, resp_id, data, timeout=2.0):
    """
    通过 CANoe GeneralDiagnostics COM 接口发送原始 UDS 请求
    返回响应字节列表，超时返回 None
    """
    try:
        # 方式1: 使用 CANoe Diagnostics COM 接口
        diag = app.Networks.Item(1).Devices.Item(1)
        req = diag.CreateRequest("RawRequest")
        for i, b in enumerate(data):
            req.SetByteParam(i, b)
        req.Send()
        start = time.time()
        while time.time() - start < timeout:
            if not req.Pending:
                break
            time.sleep(0.05)
        resp = [req.GetByteParam(i) for i in range(req.ResponseLength)]
        return resp if resp else None
    except Exception:
        pass

    try:
        # 方式2: 使用 CAPL 环境变量触发发送（需要 CANoe 配置支持）
        env = app.Environment
        # 设置发送数据到系统变量
        env.GetVariable("UDS_ReqData").Value = data
        env.GetVariable("UDS_ReqId").Value = req_id
        env.GetVariable("UDS_Send").Value = 1
        time.sleep(timeout)
        resp_data = env.GetVariable("UDS_RespData").Value
        return list(resp_data) if resp_data else None
    except Exception:
        pass

    return {"error": "CANoe 通信接口不可用，请确认配置"}


def parse_response(resp):
    if resp is None:
        return "无响应 (timeout)"
    if isinstance(resp, dict):
        return f"接口错误: {resp.get('error')}"
    if len(resp) == 0:
        return "空响应"
    if resp[0] == 0x7F:
        nrc_code = resp[2] if len(resp) >= 3 else 0
        return f"否定响应 NRC=0x{nrc_code:02X} ({NRC.get(nrc_code, 'unknown')})"
    # 0x23 正响应 = 0x63
    if resp[0] == 0x63:
        return f"正响应(成功) 数据={bytes(resp[1:]).hex().upper()}"
    return f"响应={bytes(resp).hex().upper()}"


# ============ 测试函数 ============

def scan_sessions(app):
    """扫描支持的诊断会话"""
    print("\n[*] === 扫描诊断会话 (0x10) ===")
    sessions = {
        0x01: "defaultSession",
        0x02: "programmingSession",
        0x03: "extendedDiagnosticSession",
    }
    supported = []
    for sid, name in sessions.items():
        resp = send_uds_raw(app, REQ_ID, RESP_ID, [0x10, sid], TIMEOUT)
        result = parse_response(resp)
        status = "支持" if resp and isinstance(resp, list) and resp[0] == 0x50 else "不支持/无响应"
        print(f"  0x{sid:02X} {name}: {result} -> {status}")
        if status == "支持":
            supported.append(sid)
    return supported


def test_service_23(app):
    """测试 0x23 ReadMemoryByAddress 服务支持性"""
    print("\n[*] === 测试 0x23 ReadMemoryByAddress 服务 ===")
    # addressAndLengthFormatIdentifier:
    #   高4位 = memorySize 字节数, 低4位 = memoryAddress 字节数
    # 0x14 = 1字节长度 + 4字节地址
    # 0x24 = 2字节长度 + 4字节地址
    test_cases = [
        ([0x23, 0x14, 0x00, 0x00, 0x00, 0x00, 0x04], "格式0x14 addr=0x00000000 len=4"),
        ([0x23, 0x14, 0x00, 0x00, 0x10, 0x00, 0x10], "格式0x14 addr=0x00001000 len=16"),
        ([0x23, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04], "格式0x24 addr=0x00000000 len=4"),
    ]
    results = []
    for payload, desc in test_cases:
        resp = send_uds_raw(app, REQ_ID, RESP_ID, payload, TIMEOUT)
        result = parse_response(resp)
        print(f"  请求: {bytes(payload).hex().upper()}  ({desc})")
        print(f"  响应: {result}")
        results.append((desc, payload, resp, result))
    return results


def scan_memory(app):
    """扫描常见内存地址"""
    print("\n[*] === 内存地址扫描 (0x23) ===")
    # 先切换到 extendedDiagnosticSession
    print("  [*] 切换到 extendedDiagnosticSession...")
    resp = send_uds_raw(app, REQ_ID, RESP_ID, [0x10, 0x03], TIMEOUT)
    print(f"  会话切换: {parse_response(resp)}")
    time.sleep(0.1)

    test_addrs = [
        (0x00000000, 0x10, "NULL地址"),
        (0x00001000, 0x10, "低内存"),
        (0x08000000, 0x10, "Flash起始(常见MCU)"),
        (0x20000000, 0x10, "RAM起始(常见MCU)"),
        (0x40000000, 0x10, "外设寄存器"),
        (0xFFFF0000, 0x04, "高地址"),
    ]
    results = []
    for addr, length, desc in test_addrs:
        # 构造 0x23 请求: [0x23, 0x14, addr(4字节大端), length]
        addr_bytes = list(addr.to_bytes(4, 'big'))
        payload = [0x23, 0x14] + addr_bytes + [length]
        resp = send_uds_raw(app, REQ_ID, RESP_ID, payload, TIMEOUT)
        result = parse_response(resp)
        print(f"  0x{addr:08X} ({desc}): {result}")
        results.append((addr, desc, length, payload, resp, result))
        time.sleep(0.05)
    return results


def gen_report(session_results, service23_results, memory_results, nmap_cmd=""):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = f"d:\\1.LZW-2025测试项目\\2025-其他工作事项\\8.claude\\23服务安全\\uds_23_report_{now}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("UDS 0x23 ReadMemoryByAddress 渗透测试报告\n")
        f.write(f"测试时间: {now}\n")
        f.write(f"诊断请求ID: 0x{REQ_ID:03X}  响应ID: 0x{RESP_ID:03X}\n")
        f.write("接入方式: CANoe 12 CAN 总线\n")
        f.write("=" * 50 + "\n\n")

        f.write("=== 一、诊断会话扫描 ===\n")
        for line in session_results:
            f.write(f"  {line}\n")

        f.write("\n=== 二、0x23 服务支持性测试 ===\n")
        for desc, payload, resp, result in service23_results:
            f.write(f"  请求: {bytes(payload).hex().upper()}  ({desc})\n")
            f.write(f"  响应: {result}\n\n")

        f.write("\n=== 三、内存地址读取测试 ===\n")
        for addr, desc, length, payload, resp, result in memory_results:
            f.write(f"  地址 0x{addr:08X} 长度 0x{length:02X} ({desc})\n")
            f.write(f"  请求: {bytes(payload).hex().upper()}\n")
            f.write(f"  响应: {result}\n\n")

        f.write("\n=== 四、安全风险评估 ===\n")
        readable = [r for r in memory_results
                    if r[4] and isinstance(r[4], list) and r[4][0] == 0x63]
        if readable:
            f.write("  【高危】以下地址可被未授权读取:\n")
            for addr, desc, length, payload, resp, result in readable:
                f.write(f"    0x{addr:08X} ({desc}): {result}\n")
            f.write("\n  建议: 对 0x23 服务增加安全访问(0x27)前置验证\n")
        else:
            f.write("  未发现可直接读取的内存地址\n")
            f.write("  (可能原因: 需要先通过安全访问 0x27 解锁，或服务不支持)\n")

    return path


def main():
    print("=" * 50)
    print("UDS 0x23 ReadMemoryByAddress 渗透测试")
    print(f"请求ID: 0x{REQ_ID:03X}  响应ID: 0x{RESP_ID:03X}")
    print("=" * 50)

    app = get_canoe_app()
    check_measurement(app)

    session_log = []

    # 1. 扫描会话
    supported = scan_sessions(app)
    session_log.append(f"支持的会话: {[hex(s) for s in supported]}")

    # 2. 测试 0x23 服务
    service23_results = test_service_23(app)

    # 3. 扫描内存地址
    memory_results = scan_memory(app)

    # 4. 生成报告
    report_path = gen_report(session_log, service23_results, memory_results)
    print(f"\n[+] 测试报告已保存: {report_path}")

    # 5. 汇总
    readable = [r for r in memory_results
                if r[4] and isinstance(r[4], list) and r[4][0] == 0x63]
    if readable:
        print(f"[!] 发现 {len(readable)} 个可读内存地址，存在安全风险！")
    else:
        print("[*] 未发现可直接读取的内存地址")


if __name__ == "__main__":
    main()
