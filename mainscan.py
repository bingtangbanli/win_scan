import psutil
import threading
import time 
import os
import re
import winreg
import wmi
import glob
from win32com.client import GetActiveObject
from datetime import datetime, timedelta
import win32evtlog
import win32security
from typing import List, Dict

# ==================== win_servers_check常量 ====================
SUSPICIOUS_PATHS = ['temp', 'appdata', 'downloads', 'roaming']
MALWARE_KEYWORDS = ['update', 'service', 'runtime', 'driver', 'helper']
SYSTEM_PROCESSES = ['svchost.exe', 'lsass.exe', 'services.exe']

# ==================== detected_files常量 ====================
APP_PATHS = [
    ("Chrome/Edge浏览器", [os.path.join(os.path.expanduser("~"), "Downloads"),
                        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Google", "Chrome", "User Data", "*", "Downloads")]),
    ("Firefox浏览器", [os.path.join(os.path.expanduser("~"), "Downloads"),
                     os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "*", "downloads")]),
    ("微信聊天工具", [os.path.join(os.path.expanduser("~"), "Documents", "WeChat Files", "*", "FileStorage", "File")]),
    ("企业微信聊天工具", [os.path.join(os.path.expanduser("~"), "Documents", "WXWork", "*", "Cache", "File")]),
    ("钉钉聊天工具", [os.path.join(os.path.expanduser("~"), "DingDing", "Download"),
                    os.path.join(os.path.expanduser("~"), "Documents", "DingDing", "Download")]),
    ("QQ聊天工具", [os.path.join(os.path.expanduser("~"), "Documents", "Tencent Files", "*", "FileRecv")])
]
TARGET_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tar.gz", ".exe", ".msi", ".com", ".bat", ".cmd", ".scr", ".hta"}

# ==================== win_servers_check核心函数 ====================
def get_listening_ports() -> List[Dict]:
    """获取前100个监听端口及对应进程"""
    ports = []
    for conn in psutil.net_connections('tcp'):
        if conn.status == 'LISTEN' and conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                ports.append({
                    'port': conn.laddr.port,
                    'pid': conn.pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'cmdline': ' '.join(proc.cmdline()),
                    'status': proc.status()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    return ports[:100]

def get_outbound_connections() -> List[Dict]:
    """获取进程主动外联的远程地址（前100条）"""
    connections = []
    for conn in psutil.net_connections('tcp'):
        if conn.status in ['ESTABLISHED', 'SYN_SENT', 'SYN_RECV'] and conn.raddr and conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                connections.append({
                    'pid': conn.pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'local_ip': conn.laddr.ip,
                    'local_port': conn.laddr.port
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    return connections[:100]

def get_windows_services() -> List[Dict]:
    """获取运行中服务及对应的文件路径（使用psutil更稳定）"""
    services = []
    for service in psutil.win_service_iter():
        try:
            s = psutil.win_service_get(service.name())
            if s.status() != 'running':
                continue
            binary_path = re.sub(r'^"|"$', '', s.binpath())
            services.append({
                'name': service.name(),
                'display': service.display_name(),
                'state': s.status(),
                'binary_path': binary_path
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return services[:100]

def is_suspicious(process: Dict) -> str:
    """改进的可疑检测逻辑（兼容进程和服务路径检测）"""
    flags = []
    target_path = process.get('exe') or process.get('binary_path')
    if target_path and any(path in target_path.lower() for path in SUSPICIOUS_PATHS):
        flags.append("可疑路径")
    target_name = process.get('name') or process.get('display')
    if target_name and any(kw in target_name.lower() for kw in MALWARE_KEYWORDS):
        flags.append("恶意关键词")
    if 'exe' in process and process['name'] in SYSTEM_PROCESSES:
        system_exe_path = f"C:\\Windows\\System32\\{process['name']}"
        if process['exe'].lower() != system_exe_path.lower():
            flags.append(f"伪装系统进程（应为{system_exe_path}）")
    return ' | '.join(flags) if flags else '正常'

def generate_security_report() -> str:
    """生成综合安全审计报告"""
    report = [
        "Windows安全审计报告",
        f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        "[1] 监听端口与进程分析（前100个）:"
    ]
    
    ports = get_listening_ports()
    if not ports:
        report.append("  无监听的TCP端口")
    else:
        for p in ports:
            suspicious = is_suspicious(p)
            line = f"  端口 {p['port']:4d} | PID {p['pid']:6d} | 进程 {p['name']}"
            if suspicious != '正常':
                line += f"  [!可疑：{suspicious}]"
            report.append(line)
    
    report.append("\n[2] 进程外联地址分析（前100条）:")
    outbound_conns = get_outbound_connections()
    if not outbound_conns:
        report.append("  无主动外联的TCP连接")
    else:
        for conn in outbound_conns:
            line = (
                f"  进程 {conn['name']} (PID {conn['pid']}) | "
                f"目标地址：{conn['remote_ip']}:{conn['remote_port']} | "
                f"本地地址：{conn['local_ip']}:{conn['local_port']}"
            )
            if (suspicious := is_suspicious(conn)) != '正常':
                line += f"  [!可疑：{suspicious}]"
            report.append(line)
    
    report.append("\n[3] 运行中服务与文件路径（前100个）:")
    services = get_windows_services()
    if not services:
        report.append("  无运行中的服务")
    else:
        for s in services:
            line = (
                f"  服务 {s['name']} ({s['display']}) | 状态：{s['state']} | "
                f"文件位置：{s['binary_path']}"
            )
            if (suspicious := is_suspicious(s)) != '正常':
                line += f"  [!可疑：{suspicious}]"
            report.append(line)

    with open("servers_check_results.txt", "w", encoding="utf-8") as f:
        f.write('\n'.join(report))
    return "servers_check_results.txt"

# ==================== 核心工具函数 ====================
def sid_to_username(sid_str):
    """将SID字符串转换为用户名（支持本地/域账户）"""
    try:
        sid = win32security.ConvertStringSidToSid(sid_str)
        username, domain, _ = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{username}" if domain else username
    except Exception:
        return sid_str

def is_hex_identifier(text):
    """判断是否为十六进制标识符（如0xfa4846e）"""
    if text.startswith("0x"):
        try:
            int(text, 16)
            return True
        except ValueError:
            return False
    return False

def detect_rlo_filename(file_name: str) -> bool:
    """检测文件名是否包含RLO反转控制字符"""
    RLO_CHAR = "\u202E"
    return RLO_CHAR in file_name

def get_display_name(file_name: str) -> str:
    """获取RLO文件的实际显示名称（模拟资源管理器显示效果）"""
    return file_name.replace("\u202E", "▶")

# ====================  系统账户检测模块 ====================

def detect_windows_users():
    try:
        c = wmi.WMI()
    except Exception as e:
        return f"错误：无法连接WMI服务，可能缺少管理员权限：{str(e)}"

    try:
        users = c.Win32_UserAccount()
    except Exception as e:
        return f"错误：获取用户账户失败：{str(e)}"

    sid_count = {}
    for user in users:
        try:
            sid = getattr(user, "SID", "")
            if sid:
                sid_count[sid] = sid_count.get(sid, 0) + 1
        except AttributeError:
            continue

    result = []
    for user in users:
        try:
            name = getattr(user, "Name", "未知账户")
            domain = getattr(user, "Domain", "未知域")
            disabled = getattr(user, "Disabled", 1)
            sid = getattr(user, "SID", "无SID")

            user_info = {
                "账户名称": name,
                "所属域": domain,
                "是否启用": "是" if disabled == 0 else "否",
                "是否隐藏": "是" if name.endswith('$') else "否",
                "可能克隆账户": "是" if sid_count.get(sid, 0) > 1 else "否",
                "SID": sid
            }
            result.append(user_info)
        except Exception as e:
            result.append({"错误": f"解析账户时出错：{str(e)}"})

    report = ["Windows系统账户检测报告（仅账户信息）", f"检测时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"]
    for idx, user in enumerate(result, 1):
        report.append(f"账户 {idx}:")
        for key, value in user.items():
            report.append(f"  {key}: {value}")
        report.append("-" * 40)

    try:
        with open("check_user_result.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(report))
        print(f"Windows系统账户检测结果保存至：{os.path.abspath('check_user_result.txt')}")
    except Exception as e:
        return f"操作失败：{str(e)}"


# ==================== 近3个月远程登录日志检测模块 ====================
def get_check_remote_login(output_path='check_remote_login.txt'):
    now = datetime.now()
    three_months_ago = now - timedelta(days=90)
    time_range = f"{three_months_ago.strftime('%Y-%m-%d')}至{now.strftime('%Y-%m-%d')}"

    log_handle = None
    try:
        log_handle = win32evtlog.OpenEventLog(None, 'Security')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []
        event_ids = {4624: '成功', 4625: '失败'}

        while True:
            event_batch = win32evtlog.ReadEventLog(log_handle, flags, 0)
            if not event_batch:
                break

            for event in event_batch:
                if event.EventID not in event_ids:
                    continue

                event_time = event.TimeGenerated
                if event_time < three_months_ago:
                    break

                username = "未知"
                try:
                    if event.EventID == 4624:
                        logon_type = event.StringInserts[8]
                        if logon_type == '3':
                            target_username = event.StringInserts[5]
                            target_sid = event.StringInserts[4]
                            username = sid_to_username(target_sid) if target_sid else target_username
                    elif event.EventID == 4625:
                        target_username = event.StringInserts[4]
                        target_sid = event.StringInserts[3]
                        username = sid_to_username(target_sid) if target_sid else target_username

                    if is_hex_identifier(username):
                        username = f"未知进程ID（{username}）"
                except (IndexError, TypeError):
                    pass

                events.append({
                    '时间': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                    '账户名': username,
                    '结果': event_ids[event.EventID]
                })

        events.sort(key=lambda x: x['时间'], reverse=True)

        if events:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"远程登录日志记录（时间范围：{time_range}）\n")
                f.write("时间|账户名|结果\n")
                for log in events:
                    f.write(f"{log['时间']}+++++++++++{log['账户名']}+++++++++++{log['结果']}\n")
            print(f"成功记录 {len(events)} 条日志，保存至：{os.path.abspath(output_path)}")
        else:
            print("未找到符合条件的远程登录日志")

    except Exception as e:
        print(f"执行错误：{str(e)}")
    finally:
        if log_handle:
            win32evtlog.CloseEventLog(log_handle)

# ==================== 压缩文件检测模块 ====================
def collect_files_with_app() -> List[Dict]:
    """收集文件并关联检测来源的应用"""
    collected = []
    for app_name, path_patterns in APP_PATHS:
        for pattern in path_patterns:
            expanded_pattern = os.path.expanduser(pattern)
            matched_paths = glob.glob(expanded_pattern)
            for path in matched_paths:
                if not os.path.isdir(path):
                    continue
                for root, _, files in os.walk(path):
                    for file in files:
                        file_ext = os.path.splitext(file)[1].lower()
                        if file_ext in TARGET_EXTENSIONS:
                            file_path = os.path.join(root, file)
                            create_time = datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
                            has_rlo = detect_rlo_filename(file)
                            collected.append({
                                "time": create_time,
                                "name": file,
                                "display_name": get_display_name(file),
                                "path": file_path,
                                "app": app_name,
                                "is_rlo": has_rlo
                            })
    return collected

def generate_phishing_report(files: List[Dict]) -> str:
    """生成带软件来源和RLO标注的压缩文文件报告"""
    report = [
        "=== 压缩文件检测报告（含RLO反转文件名检测） ===",
        f"检测时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    ]

    if not files:
        report.append("  未检测到符合条件的文件")
        return "\n".join(report)

    app_groups = {}
    for file in files:
        if file["app"] not in app_groups:
            app_groups[file["app"]] = []
        app_groups[file["app"]].append(file)

    for app, app_files in app_groups.items():
        report.append(f"===== 来自 [{app}] 的检测结果 =====")
        if not app_files:
            report.append("  未检测到文件")
            continue
        for file in app_files:
            line = (
                f"时间：{file['time']} | 文件名（实际）：{file['name']} | "
                f"显示效果：{file['display_name']} | 路径：{file['path']}"
            )
            if file["is_rlo"]:
                line += "  *警告：包含RLO反转控制字符（可能伪装文件名）"
            report.append(line)
        report.append("")

    return "\n".join(report)

# ==================== 开机启动项检测模块 ====================
def get_registry_startups():
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    ]

    startup_items = []
    for hkey, subkey in registry_paths:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        startup_items.append({
                            "类型": "注册表启动项",
                            "名称": name,
                            "路径": value,
                            "作用域": "全局" if hkey == winreg.HKEY_LOCAL_MACHINE else "当前用户",
                            "触发类型": "每次启动" if "RunOnce" not in subkey else "仅运行一次"
                        })
                        index += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
        except PermissionError:
            startup_items.append({
                "类型": "注册表启动项",
                "名称": f"无法访问 {subkey}",
                "路径": "需要管理员权限",
                "作用域": "警告",
                "触发类型": "权限不足"
            })
    return startup_items

def get_service_startups():
    c = wmi.WMI()
    services = []
    for service in c.Win32_Service():
        if service.StartMode.lower() in ["auto", "delayedauto"]:
            services.append({
                "类型": "系统服务",
                "名称": service.Name,
                "显示名称": service.DisplayName,
                "启动路径": service.PathName,
                "启动类型": "自动" if service.StartMode == "Auto" else "延迟自动"
            })
    return services

def get_startup_folder_items():
    startup_folders = [
        (os.path.join(os.getenv("APPDATA"), r"Microsoft\Windows\Start Menu\Programs\Startup"), "当前用户"),
        (r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "所有用户")
    ]
    items = []
    for folder, scope in startup_folders:
        if not os.path.exists(folder):
            continue
        for file in glob.glob(os.path.join(folder, "*")):
            items.append({
                "类型": "启动文件夹项",
                "名称": os.path.basename(file),
                "路径": os.path.abspath(file),
                "文件类型": "快捷方式" if file.endswith(".lnk") else "可执行文件",
                "作用域": scope
            })
    return items

def get_scheduled_tasks():
    try:
        scheduler = GetActiveObject("Schedule.Service")
        scheduler.Connect()
        root_folder = scheduler.GetFolder("\\")
        tasks = root_folder.GetTasks(0)
    except Exception as e:
        return [{
            "类型": "计划任务",
            "名称": "任务计划访问失败",
            "路径": str(e),
            "触发类型": "错误",
            "描述": "无任务描述"
        }]

    result = []
    for task in tasks:
        definition = task.Definition
        triggers = [t for t in definition.Triggers if t.Type == 8]
        if not triggers:
            continue
        actions = [a.Path for a in definition.Actions if hasattr(a, "Path")]
        result.append({
            "类型": "计划任务",
            "名称": task.Name,
            "路径": "; ".join(actions) if actions else "无执行路径",
            "触发类型": "开机启动",
            "描述": definition.Description or "无任务描述"
        })
    return result

def get_winlogon_startups():
    winlogon_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "全局"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "当前用户")
    ]
    items = []
    for hkey, subkey, scope in winlogon_paths:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                for value_name in ["Userinit", "Shell", "AppSetup"]:
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                        items.append({
                            "类型": "Winlogon启动项",
                            "名称": value_name,
                            "路径": value,
                            "作用域": scope,
                            "说明": "用户登录时触发"
                        })
                    except FileNotFoundError:
                        continue
        except FileNotFoundError:
            continue
    return items

def get_wmi_event_subscriptions():
    c = wmi.WMI()
    subscriptions = []
    try:
        filters = list(c.__EventFilter())
        consumers = list(c.__EventConsumer())
        bindings = list(c.__FilterToConsumerBinding())

        for binding in bindings:
            filter_name = binding.Filter.split("'")[-2]
            consumer_name = binding.Consumer.split("'")[-2]

            filter_obj = next((f for f in filters if f.Name == filter_name), None)
            consumer_obj = next((c for c in consumers if c.Name == consumer_name), None)

            if filter_obj and consumer_obj and "Start" in filter_obj.Query:
                subscriptions.append({
                    "类型": "WMI事件订阅",
                    "过滤器查询": filter_obj.Query,
                    "消费者路径": getattr(consumer_obj, "CommandLineTemplate", str(consumer_obj)),
                    "说明": "系统启动时触发的隐蔽启动项"
                })
    except Exception as e:
        return [{
            "类型": "WMI事件订阅",
            "名称": "WMI查询失败",
            "路径": str(e),
            "说明": "无详细信息"
        }]
    return subscriptions

def save_startup_report(qidong_check_results, filename="启动项检测结果.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("       Windows开机启动项检测报告       \n")
        f.write("=" * 60 + "\n\n")

        for section_name, items in qidong_check_results.items():
            f.write(f"【{section_name}】\n")
            f.write("-" * 60 + "\n")
            if not items:
                f.write("未检测到相关启动项\n\n")
                continue

            for item in items:
                for key, value in item.items():
                    f.write(f"{key.ljust(12)}: {value}\n")
                f.write("-" * 60 + "\n")
            f.write("\n")

# ==================== 合并后主流程 ====================
def main():
    print("注意：请以管理员身份运行此脚本，否则部分功能（如系统账户检测、远程链接日志读取）可能无法使用！\n")

   
    print("\n第一步、近3个月远程登录日志检测...")
    get_check_remote_login()

    print("\n第二步、压缩以及可执行文件检测...")
    try:
        detected_files = collect_files_with_app()
        phishing_report = generate_phishing_report(detected_files)
        with open("check_file_result.txt", "w", encoding="utf-8") as f:
            f.write(phishing_report)
        print(f"文件检测结果已保存至：{os.path.abspath('check_file_result.txt')}")
    except Exception as e:
        print(f"文件检测错误：{str(e)}")

    print("\n第三步、开机启动项检测...")
    qidong_check_results = {
        "注册表启动项": get_registry_startups(),
        "系统服务启动项": get_service_startups(),
        "启动文件夹项": get_startup_folder_items(),
        "开机计划任务": get_scheduled_tasks(),
        "Winlogon登录启动项": get_winlogon_startups(),
        "WMI事件订阅项": get_wmi_event_subscriptions()
    }
    save_startup_report(qidong_check_results)
    print(f"开机启动项检测结果已保存到：{os.path.abspath('启动项检测结果.txt')}")

    # 运行win服务检测
    print("\n第四步、前100个win服务端口进程检测...")
    print("正在win服务端口进程检测...")
    try:
        security_report = generate_security_report()
        print(f"win服务端口进程结果已保存到：{os.path.abspath(security_report)}")
    except Exception as e:
        print(f"安全审计失败：{str(e)}")

    print("\n第五步、系统账户检测...若此项检测超过3秒，则检测失败，请手动关闭脚本")
    start_time = time.time()
    detect_success = False  # 标记检测是否成功

    try:
        # 执行系统账户检测（可能被禁止或超时）
        detect_windows_users()
        detect_success = True
    except Exception as e:
        print(f"系统账户检测失败：{str(e)}")
    finally:
        elapsed_time = time.time() - start_time

    # 判断超时或失败
    if elapsed_time >3 or not detect_success:
        print(f"提示：系统账户检测耗时{elapsed_time:.2f}秒（超过3秒或被禁止），已跳过此步骤")
    else:
        print(f"系统账户检测完成（耗时{elapsed_time:.2f}秒）")


    print("\n所有检查已完成。")

if __name__ == "__main__":
    main()
