import socket
import datetime
import sys
import subprocess
import re

NMAP_OPTIONS = "-sS -sV -Pn -T4 -p 1-65535"


def local_run_nmap(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    return result.stdout, result.stderr


def parse_nmap(raw):
    results = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "PORT" in line or "Nmap scan report" in line:
            continue
        parts = line.split()
        if len(parts) >= 3 and "/" in parts[0]:
            port_proto = parts[0]
            state = parts[1]
            service = parts[2]
            try:
                port = int(port_proto.split("/")[0])
            except:
                continue
            results[port] = {"state": state, "service": service, "info": " ".join(parts[3:])}
    return results


def check_port_security(ip, port):
    info = {}
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(5)
    try:
        conn.connect((ip, port))
        info["connect"] = True
        if port == 22:
            try:
                banner = conn.recv(128).decode(errors="ignore").strip()
                info["banner"] = banner
                info["suggest"] = "SSH banner: %s" % banner
            except:
                info["banner"] = ""
                info["suggest"] = "SSH可能被允许，需验证认证和键策略"
        elif port in (80, 8080):
            conn.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            resp = conn.recv(512).decode(errors="ignore")
            info["banner"] = resp.splitlines()[0] if resp else ""
            if resp.startswith("HTTP/1"):
                info["suggest"] = "HTTP 服务探测成功，请检查是否含弱口令/目录泄漏"
        elif port == 3306:
            resp = conn.recv(128).decode(errors="ignore")
            info["banner"] = resp.strip()
            info["suggest"] = "MySQL 可能暴露，请检查授权/密码策略"
        elif port == 6379:
            conn.sendall(b"INFO\r\n")
            resp = conn.recv(512).decode(errors="ignore")
            info["banner"] = resp.strip().splitlines()[0] if resp else ""
            info["suggest"] = "Redis 无认证访问风险高"
        else:
            info["banner"] = ""
            info["suggest"] = "需要手工判定安全机制"
    except socket.timeout:
        info["connect"] = False
        info["suggest"] = "连接超时"
    except Exception as ex:
        info["connect"] = False
        info["error"] = str(ex)
    finally:
        conn.close()
    return info


def gen_report(target_ip, nmap_raw, nmap_results, checks, nmap_cmd, ssid):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = f"scan_report_{target_ip.replace('.', '_')}_{now}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"目标IP: {target_ip}\n")
        f.write(f"脚本时间: {now}\n")
        f.write(f"扫描方式: 本机直接执行 nmap\n")
        f.write(f"WiFi名称: {ssid if ssid else '未知'}\n")
        f.write(f"执行指令: {nmap_cmd}\n")
        f.write("=== Nmap 原始输出 ===\n")
        f.write(nmap_raw + "\n\n")
        f.write("=== 端口扫描结果 ===\n")
        for port in sorted(nmap_results.keys()):
            lr = nmap_results[port]
            f.write(f"- {port}: {lr['state']}, 服务={lr['service']}, info={lr.get('info','')}\n")
        f.write("\n=== 危险端口连接及安全机制判断 ===\n")
        for port, c in checks.items():
            f.write(f"端口 {port}:\n")
            f.write(f"  连接指令: socket.connect(('{target_ip}', {port}))\n")
            f.write(f"  连接: {'成功' if c.get('connect') else '失败'}\n")
            if c.get("banner") is not None:
                f.write(f"  Banner/应答: {c.get('banner')}\n")
            if c.get("error"):
                f.write(f"  错误: {c.get('error')}\n")
            f.write(f"  安全建议: {c.get('suggest')}\n")
            f.write("\n")
    return path


def get_wifi_info():
    """获取当前连接的 WiFi 名称和网关 IP"""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, encoding="gbk", errors="ignore"
        )
        ssid = ""
        for line in result.stdout.splitlines():
            if re.search(r"^\s+SSID\s*:", line) and "BSSID" not in line:
                ssid = line.split(":", 1)[1].strip()
                break

        # 获取默认网关
        route_result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, encoding="gbk", errors="ignore"
        )
        gateway = ""
        for line in route_result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gateway = parts[2]
                break

        return ssid, gateway
    except Exception:
        return "", ""


def main():
    # 显示当前 WiFi 信息
    print("=== 当前 WiFi 连接信息 ===")
    ssid, gateway = get_wifi_info()
    if ssid:
        print(f"  WiFi 名称: {ssid}")
    else:
        print("  WiFi 名称: 未检测到（可能未连接 WiFi）")
    if gateway:
        print(f"  网关 IP  : {gateway}")
    else:
        print("  网关 IP  : 未检测到")
    print()

    # 询问是否对网关 IP 进行扫描
    target_ip = ""
    if gateway:
        confirm = input(f"是否对当前网关 IP [{gateway}] 进行端口扫描？(y/n): ").strip().lower()
        if confirm == "y":
            target_ip = gateway

    if not target_ip:
        target_ip = input("请输入待扫描目标IP: ").strip()
    if not target_ip:
        print("IP 不能为空")
        sys.exit(1)
    nmap_cmd = f"nmap {NMAP_OPTIONS} {target_ip}"
    print("[*] 本机执行 Nmap 扫描，全端口扫描耗时较长，请耐心等待...")
    out, err = local_run_nmap(nmap_cmd.split())
    if err:
        print("nmap stderr:", err)
    print("[*] Nmap 扫描完成，解析结果...")
    nmap_results = parse_nmap(out)
    print("\n=== 端口扫描结果 ===")
    if nmap_results:
        for port in sorted(nmap_results.keys()):
            lr = nmap_results[port]
            print(f"  {port}: {lr['state']}, 服务={lr['service']}, info={lr.get('info','')}")
    else:
        print("  未发现任何开放端口")
    print()
    dangerous_open = [p for p, v in nmap_results.items() if v["state"] == "open"]
    HIGH_RISK_PORTS = {21, 22, 23, 80, 111, 3306, 5555, 6379, 8080}
    checks = {}
    for p in dangerous_open:
        print(f"[*] 对 {target_ip}:{p} 进行连接与安全机制初判...")
        checks[p] = check_port_security(target_ip, p)
    report_file = gen_report(target_ip, out, nmap_results, checks, nmap_cmd, ssid)
    print("扫描报告已写入:", report_file)
    high_risk_open = [p for p in dangerous_open if p in HIGH_RISK_PORTS]
    if high_risk_open:
        print("发现高危端口:", high_risk_open)
    else:
        print("未开放高危端口")
    print("完成。")


if __name__ == "__main__":
    main()
