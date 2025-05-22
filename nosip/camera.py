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

class HikVersionAdapter:
    """海康设备版本适配器"""
    CONFIG_PROFILES = {
        ('5.0', '6.0'): {
            'api_path': '/ISAPI/System/Network/interfaces/1',
            'reboot_path': '/ISAPI/System/reboot',
        },
        ('4.0',): {
            'api_path': '/ISAPI/System/Network/interfaces/0',
            'reboot_path': '/ISAPI/System/reboot',
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
        return cls.CONFIG_PROFILES[('5.0', '6.0')]  # 默认返回最新配置

class HikvisionIPConfigurator:
    def __init__(self, parent=None):
        self.parent = parent or tk.Tk()
        if isinstance(self.parent, tk.Tk):
            self.parent.title("海康设备批量配置")
        self.log_queue = queue.Queue()
        self.create_widgets()
        self.parent.after(100, self.process_log_queue)

    def create_widgets(self):
        """创建界面组件"""
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

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

    def configure_devices(self, params):
        """设备配置主逻辑"""
        try:
            for idx, (old_ip, new_ip) in enumerate(zip(params['old_ips'], params['new_ips'])):
                self.log(f"\n=== 处理设备 {idx+1}/{len(params['old_ips'])} ===")
                self.log(f"旧IP: {old_ip} → 新IP: {new_ip}")

                # 获取设备版本信息
                version_info = self.get_device_version(old_ip, params)
                if not version_info or version_info['device'] == '未知':
                    self.log(f"无法获取设备版本信息，跳过此设备-{old_ip}")
                    continue

                # 获取配置模板
                profile = HikVersionAdapter.get_config_profile(version_info['firmware'])
                self.log(f"设备型号: {version_info['device']}")
                self.log(f"固件版本: {version_info['firmware']}")
                self.log(f"使用接口: {profile['api_path']}")

                # 发送配置请求
                self.send_config_request(
                    old_ip=old_ip,
                    new_ip=new_ip,
                    url=f"http://{old_ip}{profile['api_path']}",
                    auth=(params['username'], params['password']),
                    profile=profile,
                    subnet_mask=params['subnet_mask'],
                    gateway=params['gateway']
                )

            self.log("\n所有设备处理完成！")
        except Exception as e:
            self.log(f"全局异常: {traceback.format_exc()}")
        finally:
            self.execute_btn.config(state=tk.NORMAL)

    def get_device_version(self, ip, params):
        version_urls = [
            f"http://{ip}/ISAPI/System/version",
            f"https://{ip}/ISAPI/System/version",
            f"http://{ip}/ISAPI/System/deviceInfo"
        ]

        for url in version_urls:
            try:
                response = requests.get(
                    url,
                    auth=HTTPDigestAuth(params['username'], params['password']),
                    timeout=10,
                    verify=False
                )
                if response.status_code == 200:
                    return self.parse_version_xml(response.text)
            except Exception:
                continue
        return None

    def parse_version_xml(self, xml_str):
        """增强版XML解析"""
        try:
            root = ET.fromstring(xml_str)
            namespace = self.extract_namespace(xml_str)
            ns = {'ns': namespace} if namespace else {}

            device = root.find('.//ns:deviceType', namespaces=ns)
            firmware = root.find('.//ns:firmwareVersion', namespaces=ns)
            if device is not None and firmware is not None:
                return {
                    'device': device.text,
                    'firmware': firmware.text.split(' ')[0]
                }

            if '<deviceName>' in xml_str:
                return {
                    'device': 'Legacy Device',
                    'firmware': 'V3.0'
                }
        except Exception as e:
            self.log(f"XML解析失败: {str(e)}")
        return {'device': '未知', 'firmware': '0.0'}

    def extract_namespace(self, xml_str):
        """动态提取XML中的命名空间"""
        try:
            root = ET.fromstring(xml_str)
            if root.tag.startswith("{"):
                return root.tag.split("}")[0].strip("{")
        except Exception:
            pass
        return None

    def send_config_request(self, old_ip, new_ip, url, auth, profile, subnet_mask, gateway):
        """发送配置请求，仅修改IP、网关和掩码，保留其他配置"""
        headers = {
            "Content-Type": "application/xml; charset=UTF-8",
            "User-Agent": "HikConfigTool/3.0"
        }

        try:
            self.log(f"获取设备 {old_ip} 的现有网络配置...")
            response = requests.get(
                url,
                auth=HTTPDigestAuth(*auth),
                timeout=15,
                verify=False
            )

            if response.status_code != 200:
                self.log(f"无法获取设备 {old_ip} 的现有配置，状态码: {response.status_code}")
                return

            existing_config = ET.fromstring(response.text)
            namespace = self.extract_namespace(response.text)
            ns = {'ns': namespace} if namespace else {}

            ip_address = existing_config.find('.//ns:ipAddress', namespaces=ns)
            subnet_mask_node = existing_config.find('.//ns:subnetMask', namespaces=ns)
            gateway_node = existing_config.find('.//ns:DefaultGateway/ns:ipAddress', namespaces=ns)

            if ip_address is not None:
                ip_address.text = new_ip
            if subnet_mask_node is not None:
                subnet_mask_node.text = subnet_mask
            if gateway_node is not None:
                gateway_node.text = gateway

            # 移除命名空间前缀
            for elem in existing_config.iter():
                if '}' in elem.tag:
                    elem.tag = elem.tag.split('}', 1)[1]  # 移除命名空间
                elem.attrib = {k.split('}', 1)[-1]: v for k, v in elem.attrib.items()}  # 移除属性中的命名空间

            updated_config = ET.tostring(existing_config, encoding='utf-8', method='xml').decode('utf-8')
            self.log(f"更新后的配置XML:\n{updated_config}")

            self.log(f"发送更新请求到设备 {old_ip}...")
            response = requests.put(
                url,
                auth=HTTPDigestAuth(*auth),
                headers=headers,
                data=updated_config.encode('utf-8'),
                timeout=15,
                verify=False
            )

            self.log(f"响应状态码: {response.status_code}")
            if response.status_code == 200:
                self.log(f"✓ 成功配置 {old_ip} → {new_ip}")
                if self.reboot_var.get():
                    self.reboot_device(old_ip, auth, profile)
            else:
                self.log(f"✗ 错误响应内容:\n{response.text}")

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
                data='<reboot></reboot>',
                verify=False,
                timeout=10
            )

            if response.status_code in [200, 204]:
                self.log("重启指令已接受，设备将在30秒内重启")
            else:
                self.log(f"重启失败，状态码：{response.status_code}")
        except Exception as e:
            self.log(f"重启异常：{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = HikvisionIPConfigurator(root)
    root.mainloop()
