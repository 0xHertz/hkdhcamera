import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ipaddress
import requests
from requests.auth import HTTPDigestAuth
import threading
import queue
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import traceback
import time

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class DahuaVersionAdapter:
    """大华设备版本适配器"""
    CONFIG_PROFILES = {
        ('3.0', '4.0'): {
            'api_path': '/cgi-bin/configManager.cgi?action=setConfig',
            'sip_path': '',
            'reboot_path': '/cgi-bin/magicBox.cgi?action=reboot',
        },
        ('2.0',): {
            'api_path': '/cgi-bin/configManager.cgi?action=setConfig',
            'sip_path': '',
            'reboot_path': '/cgi-bin/magicBox.cgi?action=reboot',
        }
    }

    @classmethod
    def get_config_profile(cls, version_str):
        """根据版本号获取配置模板"""
        try:
            major_version = version_str.split('.')[0]
            for versions, profile in cls.CONFIG_PROFILES.items():
                if any(v.startswith(major_version) for v in versions):
                    return profile
        except Exception:
            pass
        return cls.CONFIG_PROFILES[('3.0', '4.0')]  # 默认返回最新配置

class DahuaIPConfigurator:
    def __init__(self, parent=None):
        self.parent = parent or tk.Tk()
        if isinstance(self.parent, tk.Tk):
            self.parent.title("大华设备批量配置")
        self.log_queue = queue.Queue()
        self.create_widgets()
        self.parent.after(100, self.process_log_queue)

    def update_sip_domain(self, event):
        """Update SIP server domain based on the first 10 characters of SIP server ID."""
        sip_server_id = self.sip_server_id_entry.get()
        self.sip_server_domain_entry.delete(0, tk.END)
        self.sip_server_domain_entry.insert(0, sip_server_id[:10])

    def create_widgets(self):
        """创建界面组件"""
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.main_frame = main_frame

        # 左侧配置面板
        config_frame = ttk.Frame(main_frame)
        config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        # 旧IP列表
        old_ips_frame = ttk.LabelFrame(config_frame, text="旧IP列表（每行一个IP）")
        old_ips_frame.pack(fill=tk.X, pady=5)
        self.old_ips_text = tk.Text(old_ips_frame, height=12, width=30)
        self.old_ips_text.pack(fill=tk.X)

        # 认证信息
        auth_frame = ttk.LabelFrame(config_frame, text="认证信息")
        auth_frame.pack(fill=tk.X, pady=5)
        ttk.Label(auth_frame, text="用户名:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.username_entry = ttk.Entry(auth_frame)
        self.username_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)
        ttk.Label(auth_frame, text="密码:").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.password_entry = ttk.Entry(auth_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, sticky=tk.EW)
        auth_frame.columnconfigure(1, weight=1)

        # 新IP配置
        new_ip_frame = ttk.LabelFrame(config_frame, text="新IP配置")
        new_ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(new_ip_frame, text="起始IP:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.start_ip_entry = ttk.Entry(new_ip_frame)
        self.start_ip_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)
        ttk.Label(new_ip_frame, text="终止IP:").grid(row=0, column=2, padx=5, sticky=tk.W)
        self.end_ip_entry = ttk.Entry(new_ip_frame)
        self.end_ip_entry.grid(row=0, column=3, padx=5, sticky=tk.EW)
        ttk.Label(new_ip_frame, text="子网掩码:").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.subnet_mask_entry = ttk.Entry(new_ip_frame)
        self.subnet_mask_entry.grid(row=1, column=1, padx=5, sticky=tk.EW)
        ttk.Label(new_ip_frame, text="网关:").grid(row=1, column=2, padx=5, sticky=tk.W)
        self.gateway_entry = ttk.Entry(new_ip_frame)
        self.gateway_entry.grid(row=1, column=3, padx=5, sticky=tk.EW)
        new_ip_frame.columnconfigure(1, weight=1)
        new_ip_frame.columnconfigure(3, weight=1)

        # 平台接入配置
        platform_frame = ttk.LabelFrame(config_frame, text="平台接入配置 (GB28181) 不建议使用")
        platform_frame.pack(fill=tk.X, pady=5)
        ttk.Label(platform_frame, text="SIP服务器IP:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.sip_server_ip_entry = ttk.Entry(platform_frame)
        self.sip_server_ip_entry.insert(0, "10.124.64.141")  # Default value
        self.sip_server_ip_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="SIP服务器端口:").grid(row=0, column=2, padx=5, sticky=tk.W)
        self.sip_server_port_entry = ttk.Entry(platform_frame)
        self.sip_server_port_entry.insert(0, "3000")  # Default value
        self.sip_server_port_entry.grid(row=0, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="SIP服务器ID:").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.sip_server_id_entry = ttk.Entry(platform_frame)
        self.sip_server_id_entry.insert(0, "51010100002000000001")  # Default value
        self.sip_server_id_entry.grid(row=1, column=1, padx=5, sticky=tk.EW)
        self.sip_server_id_entry.bind("<KeyRelease>", self.update_sip_domain)
        ttk.Label(platform_frame, text="SIP服务器域:").grid(row=1, column=2, padx=5, sticky=tk.W)
        self.sip_server_domain_entry = ttk.Entry(platform_frame)
        self.sip_server_domain_entry.insert(0, "5101010000")
        self.sip_server_domain_entry.grid(row=1, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="设备ID起始位:").grid(row=2, column=0, padx=5, sticky=tk.W)
        self.device_id_entry = ttk.Entry(platform_frame)
        self.device_id_entry.grid(row=2, column=1, padx=5, sticky=tk.EW)
        # self.device_id_entry.bind("<KeyRelease>", self.update_sip_user_id)
        # ttk.Label(platform_frame, text="SIP用户ID:").grid(row=2, column=2, padx=5, sticky=tk.W)
        # self.sip_user_id_entry = ttk.Entry(platform_frame)
        # self.sip_user_id_entry.grid(row=2, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="用户密码:").grid(row=3, column=0, padx=5, sticky=tk.W)
        self.user_password_entry = ttk.Entry(platform_frame, show="*")
        self.user_password_entry.grid(row=3, column=1, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="本地端口:").grid(row=3, column=2, padx=5, sticky=tk.W)
        self.local_port_entry = ttk.Entry(platform_frame)
        self.local_port_entry.insert(0, "5060")  # Default value
        self.local_port_entry.grid(row=3, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="注册有效期:").grid(row=4, column=0, padx=5, sticky=tk.W)
        self.register_valid_entry = ttk.Entry(platform_frame)
        self.register_valid_entry.insert(0, "3600")  # Default value
        self.register_valid_entry.grid(row=4, column=1, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="心跳间隔:").grid(row=4, column=2, padx=5, sticky=tk.W)
        self.heartbeat_interval_entry = ttk.Entry(platform_frame)
        self.heartbeat_interval_entry.insert(0, "60")  # Default value
        self.heartbeat_interval_entry.grid(row=4, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="心跳超时:").grid(row=5, column=0, padx=5, sticky=tk.W)
        self.heartbeat_timeout_entry = ttk.Entry(platform_frame)
        self.heartbeat_timeout_entry.insert(0, "3")  # Default value
        self.heartbeat_timeout_entry.grid(row=5, column=1, padx=5, sticky=tk.EW)
        platform_frame.columnconfigure(1, weight=1)
        platform_frame.columnconfigure(3, weight=1)


        # 操作按钮
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.execute_btn = ttk.Button(btn_frame, text="开始执行", command=self.start_execution)
        self.execute_btn.pack(side=tk.LEFT, expand=True)

        self.reboot_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(btn_frame, text='配置后重启', variable=self.reboot_var).pack(side=tk.LEFT, padx=10)

        self.sip_config_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(btn_frame, text='启用SIP配置', variable=self.sip_config_var).pack(side=tk.LEFT, padx=10)

        # 右侧日志面板
        log_frame = ttk.LabelFrame(main_frame, text="操作日志")
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def process_log_queue(self):
        """处理日志队列"""
        while not self.log_queue.empty():
            try:
                msg = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
            except queue.Empty:
                break
        self.parent.after(100, self.process_log_queue)

    def log(self, message):
        """记录日志"""
        self.log_queue.put(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def validate_inputs(self):
        """验证输入有效性"""
        old_ips = self.old_ips_text.get("1.0", tk.END).strip().splitlines()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        start_ip = self.start_ip_entry.get().strip()
        end_ip = self.end_ip_entry.get().strip()
        subnet_mask = self.subnet_mask_entry.get().strip()
        gateway = self.gateway_entry.get().strip()

        # 基础验证
        if not all([old_ips, username, password, start_ip, end_ip, subnet_mask, gateway]):
            messagebox.showerror("错误", "所有字段必须填写！")
            return None

        # IP格式验证
        try:
            start_ip_obj = ipaddress.IPv4Address(start_ip)
            end_ip_obj = ipaddress.IPv4Address(end_ip)
            gateway_obj = ipaddress.IPv4Address(gateway)
            ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)
        except ValueError as e:
            messagebox.showerror("格式错误", f"IP地址格式无效: {str(e)}")
            return None

        # 生成新IP范围
        new_ips = []
        current_ip = start_ip_obj
        while current_ip <= end_ip_obj:
            new_ips.append(str(current_ip))
            current_ip = ipaddress.IPv4Address(int(current_ip) + 1)

        if len(old_ips) > len(new_ips):
            messagebox.showerror("范围错误", "新IP范围不足以覆盖所有旧IP")
            return None

        # 验证网关有效性
        try:
            network = ipaddress.IPv4Network(f"{new_ips[0]}/{subnet_mask}", strict=False)
            if gateway_obj not in network:
                messagebox.showerror("网络错误", "网关地址不在新IP所属子网内")
                return None
        except ValueError as e:
            messagebox.showerror("子网错误", f"IP/掩码组合无效: {str(e)}")
            return None

        # 验证平台接入配置
        sip_server_ip = self.sip_server_ip_entry.get().strip()
        sip_server_port = self.sip_server_port_entry.get().strip()
        device_id = self.device_id_entry.get().strip()

        # 生成新的device_id
        new_device_ids = []
        base_device_id = device_id
        if self.sip_config_var.get():
            fixed_prefix = base_device_id[:13]
            current_suffix = int(base_device_id[13:])
            while len(new_device_ids) < len(old_ips):
                new_device_id = f"{fixed_prefix}{current_suffix:07d}"
                new_device_ids.append(new_device_id)
                current_suffix += 1
        else:
            new_device_ids = [base_device_id] * len(old_ips)


        local_port = self.local_port_entry.get().strip()
        register_valid = self.register_valid_entry.get().strip()
        heartbeat_interval = self.heartbeat_interval_entry.get().strip()
        heartbeat_timeout = self.heartbeat_timeout_entry.get().strip()

        sip_server_domain = self.sip_server_domain_entry.get().strip()
        user_password = self.user_password_entry.get().strip()

        if self.sip_config_var.get():
            if not all([sip_server_ip, sip_server_port, device_id, local_port, register_valid, heartbeat_interval, heartbeat_timeout, sip_server_domain, user_password, self.sip_server_id_entry.get().strip(), ]):
                messagebox.showerror("错误", "平台接入配置字段必须填写！")
                return None

            try:
                ipaddress.IPv4Address(sip_server_ip)
                if not sip_server_port.isdigit() or not (0 < int(sip_server_port) <= 65535):
                    raise ValueError("端口号无效")
                if not local_port.isdigit() or not (0 < int(local_port) <= 65535):
                    raise ValueError("本地端口号无效")
                if not register_valid.isdigit() or int(register_valid) <= 0:
                    raise ValueError("注册有效期无效")
                if not heartbeat_interval.isdigit() or int(heartbeat_interval) <= 0:
                    raise ValueError("心跳间隔无效")
                if not heartbeat_timeout.isdigit() or int(heartbeat_timeout) <= 0:
                    raise ValueError("心跳超时无效")
            except ValueError as e:
                messagebox.showerror("格式错误", f"平台接入配置格式无效: {str(e)}")
                return None

            if not sip_server_domain:
                messagebox.showerror("错误", "SIP服务器域不能为空！")
                return None
            if not user_password:
                messagebox.showerror("错误", "用户密码不能为空！")
                return None

        return {
            'old_ips': old_ips,
            'new_ips': new_ips,
            'username': username,
            'password': password,
            'subnet_mask': subnet_mask,
            'gateway': gateway,
            'sip_server_ip': sip_server_ip,
            'sip_server_port': sip_server_port,
            'device_id': device_id,
            'new_device_ids': new_device_ids,
            'local_port': local_port,
            'register_valid': register_valid,
            'heartbeat_interval': heartbeat_interval,
            'heartbeat_timeout': heartbeat_timeout,
            'sip_server_domain': sip_server_domain,
            'user_password': user_password,
            'sip_server_id': self.sip_server_id_entry.get().strip()
        }

    def start_execution(self):
        """启动配置线程"""
        if params := self.validate_inputs():
            self.execute_btn.config(state=tk.DISABLED)
            threading.Thread(
                target=self.configure_devices,
                args=(params,),
                daemon=True
            ).start()

    def get_current_config(self, ip, auth):
        """获取设备当前网络配置"""
        url = f"http://{ip}/cgi-bin/configManager.cgi?action=getConfig&name=Network.eth0"
        try:
            response = requests.get(
                url,
                auth=HTTPDigestAuth(*auth),
                timeout=10,
                verify=False
            )
            if response.status_code == 200:
                return response.text  # 返回当前配置
            else:
                self.log(f"获取当前配置失败，状态码: {response.status_code}")
        except Exception as e:
            self.log(f"获取当前配置异常: {str(e)}")
        return None

    def parse_current_config(self, config_text):
        """解析设备当前配置"""
        config = {}
        try:
            lines = config_text.splitlines()
            for line in lines:
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
        except Exception as e:
            self.log(f"解析配置失败: {str(e)}")
        return config

    def merge_config(self, current_config, new_ip, subnet_mask, gateway):
        """合并新旧配置"""
        current_config["table.Network.eth0.IPAddress"] = new_ip
        current_config["table.Network.eth0.SubnetMask"] = subnet_mask
        current_config["table.Network.eth0.DefaultGateway"] = gateway
        # 移除不需要的配置项
        current_config.pop("table.Network.eth0.EnableDhcpReservedIP", None)
        current_config.pop("table.Network.eth0.Type", None)
        current_config.pop("table.Network.eth0.DnsAutoGet", None)
        return current_config

    def send_updated_config(self, ip, auth, updated_config, profile):
        """发送更新后的配置"""
        url = f"http://{ip}{profile['api_path']}"
        config_data = "&".join([f"{key.replace('table.', '')}={value}" for key, value in updated_config.items()])
        url = f"{url}&{config_data}"
        self.log(f"更新后的请求URL:\n{url}")
        try:
            self.log(f"发送更新请求到设备 {ip}...")
            response = requests.post(
                url,
                auth=HTTPDigestAuth(*auth),
                timeout=15,
                verify=False
            )
            self.log(f"响应状态码: {response.status_code}")
            if response.status_code == 200 and "OK" in response.text :
                self.log(f"✓ 成功配置设备 {ip}")
                return True
            else:
                self.log(f"✗ 错误响应内容:\n{response.text}")
                return False
        except requests.exceptions.RequestException as e:
            self.log(f"网络请求异常: {str(e)}")
            return False
        except Exception as e:
            self.log(f"未知异常: {traceback.format_exc()}")
            return False

    def reboot_device(self, ip, auth, profile):
        """执行设备重启"""
        reboot_url = f"http://{ip}{profile['reboot_path']}"
        try:
            self.log("正在发送重启指令...")
            response = requests.put(
                reboot_url,
                auth=HTTPDigestAuth(*auth),
                timeout=10
            )

            if response.status_code in [200, 204]:
                self.log("重启指令已接受，设备将在30秒内重启")
            else:
                self.log(f"重启失败，状态码：{response.status_code}")
        except Exception as e:
            self.log(f"重启异常：{str(e)}")

    def configure_devices(self, params):
        """设备配置主逻辑"""
        try:
            for idx, (old_ip, new_ip, new_device_id) in enumerate(zip(params['old_ips'], params['new_ips'], params['new_device_ids'])):
                self.log(f"\n=== 处理设备 {idx+1}/{len(params['old_ips'])} ===")
                self.log(f"旧IP: {old_ip} → 新IP: {new_ip}")

                # 获取设备版本信息
                version_info = self.get_device_version(old_ip, params)
                if not version_info or version_info['device'] == '未知':
                    self.log(f"无法获取设备版本信息，跳过此设备-{old_ip}")
                    continue

                # 获取配置模板
                profile = DahuaVersionAdapter.get_config_profile(version_info['firmware'])
                self.log(f"设备型号: {version_info['device']}")
                self.log(f"固件版本: {version_info['firmware']}")
                self.log(f"使用接口: {profile['api_path']}")

                # 获取当前配置
                current_config_text = self.get_current_config(old_ip, (params['username'], params['password']))
                if not current_config_text:
                    self.log(f"无法获取当前配置，跳过此设备-{old_ip}")
                    continue

                # 解析当前配置
                current_config = self.parse_current_config(current_config_text)

                # 合并新旧配置
                updated_config = self.merge_config(current_config, new_ip, params['subnet_mask'], params['gateway'])

                # 发送更新后的配置
                network_ok = self.send_updated_config(old_ip, (params['username'], params['password']), updated_config, profile)

                # 配置SIP
                # 配置平台接入，发送配置请求
                if self.sip_config_var.get():
                    self.log("\n开始配置平台接入...")
                    # 获取配置模板
                    profile = DahuaVersionAdapter.get_config_profile(version_info['firmware'])
                    self.log(f"设备型号: {version_info['device']}")
                    self.log(f"固件版本: {version_info['firmware']}")
                    self.log(f"使用接口: {profile['sip_path']}")

                    # 配置网络设置，发送配置请求
                    self.configure_platform_access(
                        old_ip=old_ip,
                        new_ip=new_ip,
                        new_device_id=new_device_id,
                        url=f"http://{old_ip}{profile['sip_path']}",
                        auth=(params['username'], params['password']),
                        profile=profile,
                        params=params,
                        network_ok=network_ok
                    )
                if self.reboot_var.get() and network_ok and not self.sip_config_var.get():
                    self.log("正在重启设备...")
                    self.reboot_device(old_ip, (params['username'], params['password']), profile)


            self.log("\n所有设备处理完成！")
        except Exception as e:
            self.log(f"全局异常: {traceback.format_exc()}")
        finally:
            self.execute_btn.config(state=tk.NORMAL)
    def configure_platform_access(self, old_ip, new_ip, url, new_device_id, auth, profile, params,network_ok):
        """配置平台接入 (GB28181)"""
        try:
            # Step 2: Prepare updated configuration
            updated_config = {
                "table.SIPServerIP": new_ip,
                "table.SIPServerPort": params.get("port", "5060"),
                "table.SIPDomain": params.get("domain", ""),
                "table.DeviceID": new_device_id,
                "table.AuthUser": auth[0],
                "table.AuthPassword": auth[1],
            }

            # Step 3: Send configuration to the device
            sip_ok = self.send_updated_config(old_ip, auth, updated_config, profile)

            self.log("Platform access configured successfully.")
            if network_ok and sip_ok and self.reboot_var.get():
                self.log("正在重启设备...")
                self.reboot_device(old_ip, (params['username'], params['password']), profile)
        except Exception as e:
            self.log(f"Error configuring platform access: {str(e)}")
            return False

    def get_device_version(self, ip, params):
        version_url = f"http://{ip}/cgi-bin/magicBox.cgi?action=getSoftwareVersion"

        try:
            response = requests.get(
                version_url,
                auth=HTTPDigestAuth(params['username'], params['password']),
                timeout=10,
                verify=False
            )
            if response.status_code == 200:
                return self.parse_version_response(response.text)
        except Exception:
            pass
        return None

    def parse_version_response(self, response_text):
        """解析版本信息"""
        try:
            lines = response_text.splitlines()
            for line in lines:
                if "version" in line.lower():
                    return {
                        'device': 'Dahua Device',
                        'firmware': line.split('=')[-1].strip()
                    }
        except Exception as e:
            self.log(f"版本解析失败: {str(e)}")
        return {'device': '未知', 'firmware': '0.0'}

if __name__ == "__main__":
    root = tk.Tk()
    app = DahuaIPConfigurator(root)
    root.mainloop()
