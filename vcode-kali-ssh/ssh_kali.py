#!/usr/bin/env python3
"""
SSH连接Kali Linux并执行命令
依赖: pip install paramiko
"""

import paramiko
import sys


def ssh_exec(host, username, password, command, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=username, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command(command)

        out = stdout.read().decode()
        err = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()

        if out:
            print(out, end="")
        if err:
            print(err, end="", file=sys.stderr)

        return exit_code
    finally:
        client.close()


def interactive_shell(host, username, password, port=22):
    """交互式会话，循环执行命令"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=username, password=password, timeout=10)
        print(f"已连接到 {host}")

        while True:
            cmd = input("$ ").strip()
            if cmd in ("exit", "quit", "q"):
                break
            if not cmd:
                continue

            stdin, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode()
            err = stderr.read().decode()

            if out:
                print(out, end="")
            if err:
                print(err, end="", file=sys.stderr)
    finally:
        client.close()
        print("连接已关闭")


if __name__ == "__main__":
    HOST = "172.16.96.129"
    USER = "kali"
    PASS = "kali"

    if len(sys.argv) > 1:
        # 命令行传入命令: python ssh_kali.py "whoami"
        cmd = " ".join(sys.argv[1:])
        code = ssh_exec(HOST, USER, PASS, cmd)
        sys.exit(code)
    else:
        # 无参数则进入交互模式
        interactive_shell(HOST, USER, PASS)
