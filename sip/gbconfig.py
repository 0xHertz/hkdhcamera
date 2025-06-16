import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
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
            'sip_path': '/ISAPI/System/Network/SIP',
            'reboot_path': '/ISAPI/System/reboot',
        },
        ('4.0',): {
            'api_path': '/ISAPI/System/Network/interfaces/0',
            'sip_path': '/ISAPI/System/Network/SIP',
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

class GBConfigurator:
    def __init__(self, parent=None):
        self.parent = parent or tk.Tk()
        if isinstance(self.parent, tk.Tk):
            self.parent.title("海康设备批量配置")
        self.log_queue = queue.Queue()
        self.enable_sip_config = False  # Boolean to control SIP configuration
        self.create_widgets()
        self.parent.after(100, self.process_log_queue)


    def update_sip_domain(self, event):
        """Update SIP server domain based on the first 10 characters of SIP server ID."""
        sip_server_id = self.sip_server_id_entry.get()
        self.sip_server_domain_entry.delete(0, tk.END)
        self.sip_server_domain_entry.insert(0, sip_server_id[:10])

    # def update_sip_user_id(self, event):
    #     """Set SIP user ID to match the device ID."""
    #     device_id = self.device_id_entry.get()
    #     self.sip_user_id_entry.delete(0, tk.END)
    #     self.sip_user_id_entry.insert(0, device_id)

    def create_widgets(self):
        """创建界面组件"""
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 左侧配置面板
        config_frame = ttk.Frame(main_frame)
        config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        # 旧IP列表
        lxj_ips_frame = ttk.LabelFrame(config_frame, text="改造后IP列表（每行一个IP）")
        lxj_ips_frame.pack(fill=tk.X, pady=5)
        self.lxj_ips_text = tk.Text(lxj_ips_frame, height=12, width=30)
        self.lxj_ips_text.pack(fill=tk.X)

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

        # 平台接入配置
        platform_frame = ttk.LabelFrame(config_frame, text="平台接入配置 (GB28181)")
        platform_frame.pack(fill=tk.X, pady=5)
        ttk.Label(platform_frame, text="SIP服务器IP:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.sip_server_ip_entry = ttk.Entry(platform_frame)
        self.sip_server_ip_entry.insert(0, "10.124.64.141")  # Default value
        self.sip_server_ip_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="SIP服务器端口:").grid(row=0, column=2, padx=5, sticky=tk.W)
        self.sip_server_port_entry = ttk.Entry(platform_frame)
        self.sip_server_port_entry.insert(0, "5060")  # Default value
        self.sip_server_port_entry.grid(row=0, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="SIP服务器ID:").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.sip_server_id_entry = ttk.Entry(platform_frame)
        self.sip_server_id_entry.insert(0, "90010900132000000001")  # Default value
        self.sip_server_id_entry.grid(row=1, column=1, padx=5, sticky=tk.EW)
        self.sip_server_id_entry.bind("<KeyRelease>", self.update_sip_domain)
        ttk.Label(platform_frame, text="SIP服务器域:").grid(row=1, column=2, padx=5, sticky=tk.W)
        self.sip_server_domain_entry = ttk.Entry(platform_frame)
        self.sip_server_domain_entry.insert(0, "9001090013")
        self.sip_server_domain_entry.grid(row=1, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="设备ID起始位:").grid(row=2, column=0, padx=5, sticky=tk.W)
        self.device_id_entry = ttk.Entry(platform_frame)
        self.device_id_entry.grid(row=2, column=1, padx=5, sticky=tk.EW)
        # self.device_id_entry.bind("<KeyRelease>", self.update_sip_user_id)
        # ttk.Label(platform_frame, text="SIP用户ID:").grid(row=2, column=2, padx=5, sticky=tk.W)
        # self.sip_user_id_entry = ttk.Entry(platform_frame)
        # self.sip_user_id_entry.grid(row=2, column=3, padx=5, sticky=tk.EW)
        ttk.Label(platform_frame, text="用户密码:").grid(row=3, column=0, padx=5, sticky=tk.W)
        self.user_password_entry = ttk.Entry(platform_frame)
        self.user_password_entry.insert(0, "Sp.123456")
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
        lxj_ips = self.lxj_ips_text.get("1.0", tk.END).strip().splitlines()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        # 基础验证
        if not all([lxj_ips, username, password]):
            messagebox.showerror("错误", "所有字段必须填写！")
            return None

        # 验证平台接入配置
        sip_server_ip = self.sip_server_ip_entry.get().strip()
        sip_server_port = self.sip_server_port_entry.get().strip()
        device_id = self.device_id_entry.get().strip()
        if len(device_id) != 20:
            self.log(f"设备ID无效: {device_id} (必须为20位)")
            return None

        # 生成新的device_id
        new_device_ids = []
        base_device_id = device_id
        if len(base_device_id) != 20:
            self.log(f"设备ID无效: {base_device_id} (必须为20位)")
            return None
        if self.enable_sip_config:
            fixed_prefix = base_device_id[:13]
            current_suffix = int(base_device_id[13:])
            while len(new_device_ids) < len(lxj_ips):
                new_device_id = f"{fixed_prefix}{current_suffix:07d}"
                new_device_ids.append(new_device_id)
                current_suffix += 1
        else:
            new_device_ids = [base_device_id] * len(lxj_ips)


        local_port = self.local_port_entry.get().strip()
        register_valid = self.register_valid_entry.get().strip()
        heartbeat_interval = self.heartbeat_interval_entry.get().strip()
        heartbeat_timeout = self.heartbeat_timeout_entry.get().strip()

        sip_server_domain = self.sip_server_domain_entry.get().strip()
        user_password = self.user_password_entry.get().strip()

        if self.enable_sip_config:
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
            'lxj_ips': lxj_ips,
            'username': username,
            'password': password,
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

    def configure_devices(self, params):
        """设备配置主逻辑"""
        try:
            for idx, (lxj_ip, new_device_id) in enumerate(zip(params['lxj_ips'], params['new_device_ids'])):
                self.log(f"\n=== 处理设备 {idx+1}/{len(params['lxj_ips'])} ===")
                self.log(f"处理设备: {lxj_ip}")

                auth=(params['username'], params['password'])

                # 获取设备版本信息
                version_info = self.get_device_version(lxj_ip, params)
                if not version_info or version_info['device'] == '未知':
                    self.log(f"无法获取设备版本信息，跳过此设备-{lxj_ip}")
                    continue

                # 获取配置模板
                profile = HikVersionAdapter.get_config_profile(version_info['firmware'])
                self.log(f"设备型号: {version_info['device']}")
                self.log(f"固件版本: {version_info['firmware']}")
                self.log(f"使用接口: {profile['api_path']}")


                # 配置平台接入，发送配置请求
                self.log("\n开始配置平台接入...")

                # 配置网络设置，发送配置请求
                self.configure_platform_access(
                    lxj_ip=lxj_ip,
                    new_device_id=new_device_id,
                    url=f"http://{lxj_ip}{profile['sip_path']}",
                    auth=auth,
                    profile=profile,
                    params=params
                )
                if self.reboot_var.get():
                    self.reboot_device(lxj_ip, auth, profile)

            self.log("\n所有设备配置完成！")

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

    def _fetch_channels(self,ip,auth):
        try:

            url = f"http://{ip}/ISAPI/ContentMgmt/InputProxy/channels"
            channels = []  # 用于存储通道信息

            response = requests.get(url, auth=HTTPDigestAuth(*auth), timeout=10)

            if response.status_code == 200:
                self.log("API Response:{response.text}")  # 打印返回的 XML 数据
                namespaces = {'ns': 'http://www.hikvision.com/ver20/XMLSchema'}
                root = ET.fromstring(response.content)

                for channel in root.findall('.//ns:InputProxyChannel', namespaces):
                    channel_id = channel.find('ns:id', namespaces).text
                    name = channel.find('ns:name', namespaces).text
                    ip_element = channel.find('ns:sourceInputPortDescriptor/ns:ipAddress', namespaces)
                    ip_addr = ip_element.text if ip_element is not None else 'N/A'
                    # 入数组
                    channels.append({
                        'channel_id': channel_id,
                        'name': name,
                        'ip_address': ip_addr
                    })

                    self.log(f"Parsed Channel - ID: {channel_id}, Name: {name}, IP: {ip_addr}")  # 调试信息
                self.log("通道信息获取成功")
                return channels
            else:
                error_message = f"API返回异常状态码：{response.status_code}"
                self.log(error_message)
                messagebox.showerror("错误", error_message)
        except Exception as e:
            error_message = f"连接失败：{str(e)}"
            self.log(error_message)
            messagebox.showerror("错误", error_message)

    def config_channel_id(self,lxj_ip,auth):
        # 获取设备现有通道数量
        channels = self._fetch_channels(
            ip=lxj_ip,
            auth=auth
        )
        # 中断弹窗要求用户输入通道起始编号
        start_channel_id = simpledialog.askinteger(
            "输入通道起始编号",
            "请输入通道起始编号：",
            minvalue=1,
            maxvalue=9999
        )
        if start_channel_id is None:
            messagebox.showinfo("操作取消", "用户取消了操作")
            return

        # 发请求配置通道ID
        channel_url = f"http://{lxj_ip}/ISAPI/System/Network/SIP/1/SIPInfo"
        try:
            self.log(f"正在配置设备 {lxj_ip} 的通道ID...")
            response = requests.get(
                channel_url,
                auth=HTTPDigestAuth(*auth),
                timeout=15,
                verify=False
            )
            if response.status_code != 200:
                self.log(f"无法获取设备 {lxj_ip} 的通道配置，状态码: {response.status_code}")
                return

            existing_config = ET.fromstring(response.text)
            namespace = self.extract_namespace(response.text)
            ns = {'ns': namespace} if namespace else {}
            for channel in channels:
                channel_id = channel['channel_id']

                # 查找现有通道配置
                existing_channel = existing_config.find(f".//ns:VideoInputList/ns:VideoInput[ns:id='{channel_id}']", namespaces=ns)
                if existing_channel is not None:
                    self.log(f"更新通道 {channel_id} 的配置...")
                    # 通道起始编号自增1,保证通道起始编号始终20位，并以此更新videoInputID
                    channel_id_str = str(channel_id).zfill(20)  # 确保通道ID为20位
                    existing_channel.find("ns:videoInputID", namespaces=ns).text = channel_id_str
                    channel_id += 1  # 自增通道起始编号
            # 移除命名空间前缀
            for elem in existing_config.iter():
                if '}' in elem.tag:
                    elem.tag = elem.tag.split('}', 1)[1]
                elem.attrib = {k.split('}', 1)[-1]: v for k, v in elem.attrib.items()}
            updated_config = ET.tostring(existing_config, encoding='utf-8', method='xml').decode('utf-8')
            self.log(f"更新后的通道配置XML:\n{updated_config}")
            headers = {
                "Content-Type": "application/xml; charset=UTF-8",
                "User-Agent": "HikConfigTool/3.0"
            }
            response = requests.put(
                channel_url,
                auth=HTTPDigestAuth(*auth),
                headers=headers,
                data=updated_config.encode('utf-8'),
                timeout=15,
                verify=False
            )
            if response.status_code == 200:
                self.log(f"✓ 成功配置通道编码: {lxj_ip}")
                self.config_channel_id(
                    lxj_ip=lxj_ip,
                    auth=auth,
                )
            else:
                self.log(f"✗ 配置通道编码失败: {lxj_ip}, 状态码: {response.status_code}")
                self.log(f"✗ 配置通道编码失败: {lxj_ip}, 信息: {response.text}")
        except Exception as e:
            self.log(f"配置通道ID异常: {traceback.format_exc()}")
            messagebox.showerror("错误", f"配置通道ID异常: {str(e)}")


    def configure_platform_access(self, lxj_ip, url, new_device_id, auth, profile, params):
        """配置平台接入 (GB28181)"""
        try:
            self.log(f"配置设备 {lxj_ip} 的平台接入...")
            self.log(f"获取设备 {lxj_ip} 的现有平台配置...")
            response = requests.get(
                url,
                auth=HTTPDigestAuth(*auth),
                timeout=15,
                verify=False
            )
            if response.status_code != 200:
                self.log(f"无法获取设备 {lxj_ip} 的现有配置，状态码: {response.status_code}")
                return

            existing_config = ET.fromstring(response.text)
            namespace = self.extract_namespace(response.text)
            ns = {'ns': namespace} if namespace else {}

            local_port = existing_config.find('.//ns:localPort', namespaces=ns)
            enabled = existing_config.find('.//ns:GB28181/ns:enabled', namespaces=ns)
            registrar = existing_config.find('.//ns:GB28181/ns:registrar', namespaces=ns)
            registrarPort = existing_config.find('.//ns:GB28181/ns:registrarPort', namespaces=ns)
            serverId = existing_config.find('.//ns:GB28181/ns:serverId', namespaces=ns)
            serverDomain = existing_config.find('.//ns:GB28181/ns:serverDomain', namespaces=ns)
            authID = existing_config.find('.//ns:GB28181/ns:authID', namespaces=ns)
            expires = existing_config.find('.//ns:GB28181/ns:expires', namespaces=ns)
            heartbeatTime = existing_config.find('.//ns:GB28181/ns:heartbeatTime', namespaces=ns)
            heartbeatCount = existing_config.find('.//ns:GB28181/ns:heartbeatCount', namespaces=ns)

            if local_port is not None:
                local_port.text = params['local_port']
            if enabled is not None:
                enabled.text = 'true'
            if registrar is not None:
                registrar.text = params['sip_server_ip']
            if registrarPort is not None:
                registrarPort.text = params['sip_server_port']
            if serverId is not None:
                serverId.text = params['sip_server_id']
            if serverDomain is not None:
                serverDomain.text = params['sip_server_domain']
            if authID is not None:
                authID.text = new_device_id
            if expires is not None:
                expires.text = params['register_valid']
            if heartbeatTime is not None:
                heartbeatTime.text = params['heartbeat_interval']
            if heartbeatCount is not None:
                heartbeatCount.text = params['heartbeat_timeout']

            # 移除命名空间前缀
            for elem in existing_config.iter():
                if '}' in elem.tag:
                    elem.tag = elem.tag.split('}', 1)[1]  # 移除命名空间
                elem.attrib = {k.split('}', 1)[-1]: v for k, v in elem.attrib.items()}  # 移除属性中的命名空间

            updated_config = ET.tostring(existing_config, encoding='utf-8', method='xml').decode('utf-8')
            self.log(f"更新后的SIP配置XML:\n{updated_config}")

            headers = {
                "Content-Type": "application/xml; charset=UTF-8",
                "User-Agent": "HikConfigTool/3.0"
            }

            self.log(f"发送SIP更新请求到设备 {lxj_ip}...")
            response = requests.put(
                url,
                auth=HTTPDigestAuth(*auth),
                headers=headers,
                data=updated_config.encode('utf-8'),
                timeout=15,
                verify=False
            )
            if response.status_code == 200:
                self.log(f"✓ 成功配置平台接入: {lxj_ip}")
                self.config_channel_id(
                    lxj_ip=lxj_ip,
                    auth=auth,
                )
            else:
                self.log(f"✗ 配置平台接入失败: {lxj_ip}, 状态码: {response.status_code}")
                self.log(f"✗ 配置平台接入失败: {lxj_ip}, 信息: {response.text}")
        except Exception as e:
            self.log(f"配置平台接入异常: {traceback.format_exc()}")

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
    app = GBConfigurator(root)
    root.mainloop()
