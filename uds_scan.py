"""
UDS 0x23 (ReadMemoryByAddress) 渗透测试脚本
诊断请求 ID: 0x741
诊断响应 ID: 0x749
"""
import win32com.client
import time
import datetime

REQ_ID = 0x741
RESP_ID = 0x749

# UDS 否定响应码
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


def connect_canoe():
    app = win32com.client.Dispatch("CANoe.Application")
    bus = app.Networks.Item(1).Devices.Item(1).Channels.Item(1)
    return app, bus


def send_uds(measurement, req_id, data_bytes, timeout=2.0):
    """通过 CANoe Measurement 发送 CAN 帧并等待响应"""
    # 使用 CANoe CAPL 接口发送
    env = measurement.Environment
    # 构造 CAN 报文
    msg = win32com.client.Dispatch("CANoe.CANMessage")
    msg.ID = req_id
    msg.DLC = len(data_bytes)
    for i, b in enumerate(data_bytes):
        msg.Data(i, b)
    measurement.SendCANMessage(msg)
    time.sleep(timeout)
    return None


def send_raw(app, req_id, data_bytes, timeout=1.5):
    """通过 CANoe DiagRequest 发送 UDS 请求"""
    try:
        diag = app.Networks.Item(1).Devices.Item(1)
        req = diag.CreateRequest("RawRequest")
        req.Pending = True
        # 设置原始字节
        for i, b in enumerate(data_bytes):
            req.SetByteParam(i, b)
        req.Send()
        start = time.time()
        while time.time() - start < timeout:
            if not req.Pending:
                break
            time.sleep(0.05)
        resp = []
        for i in range(req.ResponseLength):
            resp.append(req.GetByteParam(i))
        return resp
    except Exception as e:
        return None


def canoe_send_recv(app, req_id, resp_id, data_bytes, timeout=2.0):
    """
    通过 CANoe COM GeneralDiagnostics 发送原始 UDS 帧
    """
    try:
        diag = app.GeneralDiagnostics
        resp = diag.SendRequest(req_id, resp_id, data_bytes, timeout)
        return list(resp) if resp else None
    except Exception:
        pass

    # fallback: 使用 CANoe.Measurement 的 SendMessage
    try:
        meas = app.Measurement
        result = meas.SendDiagRequest(req_id, resp_id, list(data_bytes), timeout)
        return result
    except Exception as e:
        return {"error": str(e)}


def parse_response(resp):
    if resp is None:
        return "无响应 (timeout)"
    if isinstance(resp, dict):
        return f"错误: {resp.get('error')}"
    if len(resp) == 0:
        return "空响应"
    if resp[0] == 0x7F:
        nrc_code = resp[2] if len(resp) >= 3 else 0
        return f"否定响应 NRC=0x{nrc_code:02X} ({NRC.get(nrc_code, 'unknown')})"
    if resp[0] == 0x63:  # 0x23 + 0x40
        return f"正响应 数据={bytes(resp[1:]).hex()}"
    return f"响应={bytes(resp).hex()}"


def scan_sessions(app):
    """扫描支持的会话模式 (0x10 服务)"""
    print("\n[*] 扫描支持的诊断会话...")
    sessions = {
        0x01: "defaultSession",
        0x02: "programmingSession",
        0x03: "extendedDiagnosticSession",
        0x04: "safetySystemDiagnosticSession",
    }
    supported = []
    for sid, name in sessions.items():
        resp = canoe_send_recv(app, REQ_ID, RESP_ID, [0x10, sid])
        result = parse_response(resp)
        print(f"  Session 0x{sid:02X} ({name}): {result}")
        if resp and isinstance(resp, list) and resp[0] == 0x50:
            supported.append(sid)
    return supported


def scan_service_23(app):
    """测试 0x23 ReadMemoryByAddress 服务是否支持"""
    print("\n[*] 测试 0x23 ReadMemoryByAddress 服务...")
    # addressAndLengthFormatIdentifier: 0x14 = 1字节长度 + 4字节地址
    # 先用地址 0x00000000 测试
    test_cases = [
        ([0x23, 0x14, 0x00, 0x00, 0x00, 0x00, 0x04], "addr=0x00000000 len=4"),
        ([0x23, 0x14, 0x00, 0x00, 0x10, 0x00, 0x04], "addr=0x00001000 len=4"),
        ([0x23, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04], "addr=0x00000000 len=4 (2+4格式)"),
    ]
    results = []
    for payload, desc in test_cases:
        resp = canoe_send_recv(app, REQ_ID, RESP_ID, payload)
        result = parse_response(resp)
        print(f"  {desc}: {result}")
        results.append((desc, payload, resp, result))
    return results


def read_memory_by_address(app, address, length, addr_len=4):
    """
    0x23 ReadMemoryByAddress
    addressAndLengthFormatIdentifier: 高4位=memorySize字节数, 低4位=address字节数
    """
    fmt = (1 << 4) | addr_len  # 1字节长度 + addr_len字节地址
    addr_bytes = address.to_bytes(addr_len, 'big')
    payload = [0x23, fmt] + list(addr_bytes) + [length]
    resp = canoe_send_recv(app, REQ_ID, RESP_ID, payload)
    return resp, parse_response(resp)


def scan_memory_ranges(app):
    """扫描常见内存地址范围"""
    print("\n[*] 扫描内存地址范围 (0x23 ReadMemoryByAddress)...")
    test_addrs = [
        (0x00000000, "NULL地址"),
        (0x00001000, "低内存"),
        (0x00010000, "低内存2"),
        (0x08000000, "Flash起始(常见)"),
        (0x20000000, "RAM起始(常见)"),
        (0x40000000, "外设寄存器(常见)"),
        (0xFFFF0000, "高地址"),
        (0xFFFFFFF0, "最高地址"),
    ]
    results = []
    for addr, desc in test_addrs:
        resp, result = read_memory_by_address(app, addr, 0x10)
        print(f"  0x{addr:08X} ({desc}): {result}")
        results.append((addr, desc, resp, result))
        time.sleep(0.1)
    return results


def gen_report(session_results, service23_results, memory_results):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = f"d:\\1.LZW-2025测试项目\\2025-其他工作事项\\8.claude\\uds_23_report_{now}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("========================================\n")
        f.write("UDS 0x23 ReadMemoryByAddress 渗透测试报告\n")
        f.write(f"测试时间: {now}\n")
        f.write(f"诊断请求ID: 0x{REQ_ID:03X}  响应ID: 0x{RESP_ID:03X}\n")
        f.write("接入方式: CANoe CAN总线\n")
        f.write("========================================\n\n")

        f.write("=== 一、诊断会话扫描 ===\n")
        for line in session_results:
            f.write(f"  {line}\n")

        f.write("\n=== 二、0x23 服务支持性测试 ===\n")
        for desc, payload, resp, result in service23_results:
            f.write(f"  请求: {bytes(payload).hex()}  ({desc})\n")
            f.write(f"  响应: {result}\n\n")

        f.write("\n=== 三、内存地址读取测试 ===\n")
        for addr, desc, resp, result in memory_results:
            f.write(f"  地址 0x{addr:08X} ({desc}): {result}\n")

        f.write("\n=== 四、安全风险评估 ===\n")
        readable = [r for r in memory_results if r[2] and isinstance(r[2], list) and r[2][0] == 0x63]
        if readable:
            f.write("  【高危】以下地址可被未授权读取:\n")
            for addr, desc, resp, result in readable:
                f.write(f"    0x{addr:08X} ({desc}): {result}\n")
        else:
            f.write("  未发现可直接读取的内存地址\n")
    return path


def main():
    print("[*] 连接 CANoe...")
    try:
        app = win32com.client.Dispatch("CANoe.Application")
        print(f"[*] CANoe 版本: {app.Version}")
    except Exception as e:
        print(f"[-] CANoe 连接失败: {e}")
        return

    session_log = []
    print("\n[*] 开始 UDS 0x23 渗透测试")
    print(f"    请求ID: 0x{REQ_ID:03X}  响应ID: 0x{RESP_ID:03X}")

    # 1. 扫描会话
    supported_sessions = scan_sessions(app)
    session_log.append(f"支持的会话: {[hex(s) for s in supported_sessions]}")

    # 2. 测试 0x23 服务
    service23_results = scan_service_23(app)

    # 3. 扫描内存地址
    memory_results = scan_memory_ranges(app)

    # 4. 生成报告
    report_path = gen_report(session_log, service23_results, memory_results)
    print(f"\n[*] 测试报告已保存: {report_path}")


if __name__ == "__main__":
    main()
