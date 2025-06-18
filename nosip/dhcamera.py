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
            'reboot_path': '/cgi-bin/magicBox.cgi?action=reboot',
        },
        ('2.0',): {
            'api_path': '/cgi-bin/configManager.cgi?action=setConfig',
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
        self.start_ip_entry.bind("<KeyRelease>", self.update_gateway)
        ttk.Label(new_ip_frame, text="终止IP:").grid(row=0, column=2, padx=5, sticky=tk.W)
        self.end_ip_entry = ttk.Entry(new_ip_frame)
        self.end_ip_entry.grid(row=0, column=3, padx=5, sticky=tk.EW)
        ttk.Label(new_ip_frame, text="子网掩码:").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.subnet_mask_entry = ttk.Entry(new_ip_frame)
        self.subnet_mask_entry.insert(0,"255.255.255.0")
        self.subnet_mask_entry.grid(row=1, column=1, padx=5, sticky=tk.EW)
        ttk.Label(new_ip_frame, text="网关:").grid(row=1, column=2, padx=5, sticky=tk.W)
        self.gateway_entry = ttk.Entry(new_ip_frame)
        self.gateway_entry.grid(row=1, column=3, padx=5, sticky=tk.EW)
        new_ip_frame.columnconfigure(1, weight=1)
        new_ip_frame.columnconfigure(3, weight=1)

        # 操作按钮
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.execute_btn = ttk.Button(btn_frame, text="开始执行", command=self.start_execution)
        self.execute_btn.pack(side=tk.LEFT, expand=True)

        self.reboot_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(btn_frame, text='配置后重启', variable=self.reboot_var).pack(side=tk.LEFT, padx=10)

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

    def update_gateway(self, event=None):
        """动态更新网关地址为起始IP网段的.1地址"""
        start_ip = self.start_ip_entry.get().strip()
        subnet_mask = self.subnet_mask_entry.get().strip()
        try:
            network = ipaddress.IPv4Network(f"{start_ip}/{subnet_mask}", strict=False)
            gateway = str(network.network_address + 1)
            self.gateway_entry.delete(0, tk.END)
            self.gateway_entry.insert(0, gateway)
        except ValueError:
            self.gateway_entry.delete(0, tk.END)

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

        return {
            'old_ips': old_ips,
            'new_ips': new_ips,
            'username': username,
            'password': password,
            'subnet_mask': subnet_mask,
            'gateway': gateway
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
        # self.log(f"更新后的请求URL:\n{url}")
        try:
            self.log(f"发送更新请求到设备 {ip}...")
            response = requests.post(
                url,
                auth=HTTPDigestAuth(*auth),
                timeout=15,
                verify=False
            )
            # self.log(f"响应状态码: {response.status_code}")
            if response.status_code == 200 and "OK" in response.text :
                self.log(f"✓ 成功配置设备 {ip}")
                # 重启设备（可选）
                if self.reboot_var.get():
                    self.reboot_device(ip, auth, profile)
            else:
                self.log(f"✗ 错误响应内容:\n{response.text}")
            return response
        except requests.exceptions.RequestException as e:
            self.log(f"网络请求异常: {str(e)}")
        except Exception as e:
            self.log(f"未知异常: {traceback.format_exc()}")

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
            success_entries = []
            failure_entries = []

            for idx, (old_ip, new_ip) in enumerate(zip(params['old_ips'], params['new_ips'])):
                self.log(f"\n=== 处理设备 {idx+1}/{len(params['old_ips'])} ===")
                self.log(f"旧IP: {old_ip} → 新IP: {new_ip}")

                # 获取设备版本信息
                version_info = self.get_device_version(old_ip, params)
                if not version_info or version_info['device'] == '未知':
                    failure_entries.append({'ip': old_ip, 'reason': '无法获取设备版本信息'})
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
                    failure_entries.append({'ip': old_ip, 'reason': '无法获取当前配置'})
                    self.log(f"无法获取当前配置，跳过此设备-{old_ip}")
                    continue

                # 解析当前配置
                current_config = self.parse_current_config(current_config_text)

                # 合并新旧配置
                updated_config = self.merge_config(current_config, new_ip, params['subnet_mask'], params['gateway'])

                # 发送更新后的配置
                response = self.send_updated_config(old_ip, (params['username'], params['password']), updated_config, profile)

                if response and response.status_code == 200 and "OK" in response.text:
                    success_entries.append({'old_ip': old_ip, 'new_ip': new_ip, 'device': version_info['device'], 'firmware': version_info['firmware']})
                else:
                    failure_entries.append({'ip': old_ip, 'reason': f"配置失败，状态码: {response.status_code if response else '无响应'}"})

            self.log("\n所有设备处理完成！")
            self.log(f"配置成功设备数量: {len(success_entries)}")
            for entry in success_entries:
                self.log(f"成功: 旧IP={entry['old_ip']}, 新IP={entry['new_ip']}, 设备={entry['device']}, 固件版本={entry['firmware']}")

            self.log(f"配置失败设备数量: {len(failure_entries)}")
            for entry in failure_entries:
                self.log(f"失败: IP={entry['ip']}, 原因={entry['reason']}")
        except Exception as e:
            self.log(f"全局异常: {traceback.format_exc()}")
        finally:
            self.execute_btn.config(state=tk.NORMAL)

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
