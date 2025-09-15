import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests
import ipaddress
import traceback
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
from threading import Thread
import xml.etree.ElementTree as ET
from gbconfig import HikVersionAdapter

class HikvisionGBChannelManager:
    def __init__(self, root=None):
        self.root = root or tk.Tk()
        if isinstance(self.root, tk.Tk):
            self.root.title("海康设备通道管理")
            # self.root.geometry("1000x700")  # 设置窗口大小
            # self.root.resizable(False, False)  # 禁止调整窗口大小
        self.create_widgets()
        self.channels = []
    def update_sip_domain(self, event):
        """Update SIP server domain based on the first 10 characters of SIP server ID."""
        sip_server_id = self.sip_server_id_entry.get()
        self.sip_server_domain_entry.delete(0, tk.END)
        self.sip_server_domain_entry.insert(0, sip_server_id[:10])

    def get_device_version(self, ip, auth):
        version_urls = [
            f"http://{ip}/ISAPI/System/version",
            f"https://{ip}/ISAPI/System/version",
            f"http://{ip}/ISAPI/System/deviceInfo"
        ]

        for url in version_urls:
            try:
                response = requests.get(
                    url,
                    auth=HTTPDigestAuth(*auth),
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
            self.log_message(f"XML解析失败: {str(e)}")
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

    def create_widgets(self):
        # 顶部区域：设备信息和功能按钮
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(side=tk.TOP, fill=tk.X)

        # 设备信息输入框
        device_info_frame = ttk.Frame(top_frame)
        device_info_frame.pack(side=tk.LEFT, padx=10)

        ttk.Label(device_info_frame, text="设备IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.device_ip = ttk.Entry(device_info_frame, width=20)
        self.device_ip.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(device_info_frame, text="用户名:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.username = ttk.Entry(device_info_frame, width=20)
        self.username.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(device_info_frame, text="密码:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.password = ttk.Entry(device_info_frame, width=20)
        self.password.grid(row=2, column=1, padx=5, pady=5)

        # 功能按钮
        button_frame = ttk.Frame(top_frame)
        button_frame.pack(side=tk.RIGHT, padx=10)

        ttk.Button(button_frame, text="获取通道信息", command=self.fetch_channels, width=15).pack(pady=5)
        ttk.Button(button_frame, text="配置录像机国标", command=self.config_gb, width=15).pack(pady=5)
        ttk.Button(button_frame, text="更新通道编号", command=self.update_ips, width=15).pack(pady=5)

        # 平台接入配置
        platform_frame = ttk.LabelFrame(top_frame, text="平台接入配置 (GB28181)")
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
        ttk.Label(platform_frame, text="设备ID:").grid(row=2, column=0, padx=5, sticky=tk.W)
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

        # 中间区域：通道信息表格
        middle_frame = ttk.Frame(self.root, padding="10")
        middle_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            middle_frame,
            columns=('id', 'name', 'ip', 'new_ip'),
            show='headings',
            height=20
        )
        self.tree.heading('id', text='通道ID')
        self.tree.heading('name', text='通道名称')
        self.tree.heading('ip', text='当前IP')
        self.tree.heading('new_ip', text='通道编码')
        self.tree.column('id', width=100, anchor='center')
        self.tree.column('name', width=300, anchor='center')
        self.tree.column('ip', width=300, anchor='center')
        self.tree.column('new_ip', width=300, anchor='center')
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(middle_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # 底部区域：日志信息
        log_frame = ttk.LabelFrame(self.root, text="日志信息", padding="10")
        log_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, height=10, state='disabled', wrap='word')
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)

        # 绑定双击事件
        self.tree.bind("<Double-1>", self.on_double_click)

    def log_message(self, message):
        """在日志区域显示消息"""
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.configure(state='disabled')
        self.log_text.see(tk.END)

    def on_double_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            col = self.tree.identify_column(event.x)
            if col == "#4":  # 第四列是 "new_ip"
                item = self.tree.identify_row(event.y)
                if item:
                    values = self.tree.item(item, "values")
                    old_value = values[3] if len(values) > 3 else ""
                    start_channel_id = simpledialog.askstring("输入通道编码", "请输入通道编码:", initialvalue=old_value)
                    if len(start_channel_id) == 20:
                        self.tree.set(item, column=col, value=start_channel_id)
                        self.auto_fill_new_ips(item, start_channel_id)

    def auto_fill_new_ips(self, start_item, start_channel_id):
        """自动填充后续行的新IP地址"""
        try:
            # 获取所有行并找到起始行的索引
            items = self.tree.get_children()
            start_index = items.index(start_item)
            if start_channel_id == '':
                for i in range(start_index + 1, len(items)):
                    self.tree.set(items[i], column="#4", value='')
                return

            fixed_prefix = str(start_channel_id)[:13]
            current_suffix = int(str(start_channel_id)[13:])

            # 从起始行的下一行开始填充
            for i in range(start_index + 1, len(items)):
                current_suffix += 1
                new_channel_id = f"{fixed_prefix}{current_suffix:07d}"
                self.tree.set(items[i], column="#4", value=new_channel_id)
        except Exception as e:
            self.log_message(f"自动填充失败: {str(e)}")

    def validate_inputs(self):
        """验证输入有效性"""
        ip = self.device_ip.get()
        username = self.username.get()
        password = self.password.get()

        # 基础验证
        if not all([ip, username, password]):
            messagebox.showerror("错误", "所有字段必须填写！")
            return None

        # 验证平台接入配置
        sip_server_ip = self.sip_server_ip_entry.get().strip()
        sip_server_port = self.sip_server_port_entry.get().strip()
        device_id = self.device_id_entry.get().strip()
        if len(device_id) != 20:
            self.log_message(f"设备ID无效: {device_id} (必须为20位)")
            return None

        local_port = self.local_port_entry.get().strip()
        register_valid = self.register_valid_entry.get().strip()
        heartbeat_interval = self.heartbeat_interval_entry.get().strip()
        heartbeat_timeout = self.heartbeat_timeout_entry.get().strip()

        sip_server_domain = self.sip_server_domain_entry.get().strip()
        user_password = self.user_password_entry.get().strip()

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
            'ip': ip,
            'username': username,
            'password': password,
            'sip_server_ip': sip_server_ip,
            'sip_server_port': sip_server_port,
            'device_id': device_id,
            'local_port': local_port,
            'register_valid': register_valid,
            'heartbeat_interval': heartbeat_interval,
            'heartbeat_timeout': heartbeat_timeout,
            'sip_server_domain': sip_server_domain,
            'user_password': user_password,
            'sip_server_id': self.sip_server_id_entry.get().strip()
        }

    def config_gb(self):
        params = self.validate_inputs();
        auth=(params['username'], params['password'])

        # 获取设备版本信息
        version_info = self.get_device_version(params['ip'], auth)
        if not version_info or version_info['device'] == '未知':
            self.log_message(f"无法获取设备版本信息，跳过此设备-{params['ip']}")
            return

        # 获取配置模板
        profile = HikVersionAdapter.get_config_profile(version_info['firmware'])
        self.log_message(f"设备型号: {version_info['device']}")
        self.log_message(f"固件版本: {version_info['firmware']}")
        self.log_message(f"使用接口: {profile['api_path']}")


        # 配置平台接入，发送配置请求
        self.log_message("\n开始配置平台接入...")

        # 配置网络设置，发送配置请求
        self.configure_platform_access(
            lxj_ip=params['ip'],
            new_device_id=params['device_id'],
            url=f"http://{params['ip']}{profile['sip_path']}",
            auth=auth,
            profile=profile,
            params=params
        )

    def configure_platform_access(self, lxj_ip, url, new_device_id, auth, profile, params):
        """配置平台接入 (GB28181)"""
        try:
            self.log_message(f"配置设备 {lxj_ip} 的平台接入...")
            self.log_message(f"获取设备 {lxj_ip} 的现有平台配置...")
            response = requests.get(
                url,
                auth=HTTPDigestAuth(*auth),
                timeout=15,
                verify=False
            )
            if response.status_code != 200:
                self.log_message(f"无法获取设备 {lxj_ip} 的现有配置，状态码: {response.status_code}")
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
            # self.log(f"更新后的SIP配置XML:\n{updated_config}")

            headers = {
                "Content-Type": "application/xml; charset=UTF-8",
                "User-Agent": "HikConfigTool/3.0"
            }

            self.log_message(f"发送SIP更新请求到设备 {lxj_ip}...")
            response = requests.put(
                url,
                auth=HTTPDigestAuth(*auth),
                headers=headers,
                data=updated_config.encode('utf-8'),
                timeout=15,
                verify=False
            )
            if response.status_code == 200:
                self.log_message(f"✓ 成功配置平台接入: {lxj_ip}")
            else:
                self.log_message(f"✗ 配置平台接入失败: {lxj_ip}, 状态码: {response.status_code}")
                self.log_message(f"✗ 配置平台接入失败: {lxj_ip}, 信息: {response.text}")
        except Exception as e:
            self.log_message(f"配置平台接入异常: {traceback.format_exc()}")


    def fetch_channels(self):
        Thread(target=self._fetch_channels, daemon=True).start()

    def findall_with_ns(self, root, tagname):
        import re
        m = re.match(r'\{(.*)\}', root.tag)
        if m:  # 有命名空间
            ns = {'ns': m.group(1)}
            return [root.findall(f'.//ns:{tagname}', ns),ns]
        else:  # 没有命名空间
            return root.findall(f'.//{tagname}')


    def _fetch_channels(self):
        try:
            ip = self.device_ip.get()
            user = self.username.get()
            pwd = self.password.get()

            url = f"http://{ip}/ISAPI/ContentMgmt/InputProxy/channels"

            try:
                response = requests.get(url, auth=HTTPDigestAuth(user, pwd), timeout=10)
            except requests.exceptions.HTTPError:
                response = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=10)

            if response.status_code == 200:
                # self.log_message("API Response:{response.text}")  # 打印返回的 XML 数据
                root = ET.fromstring(response.content)
                result = self.findall_with_ns(root, 'InputProxyChannel')
                old_channels = result[0]
                namespaces = result[1]

                self.tree.delete(*self.tree.get_children())
                for channel in old_channels:
                    channel_id = channel.find('ns:id', namespaces).text
                    name = channel.find('ns:name', namespaces).text
                    ip_element = channel.find('ns:sourceInputPortDescriptor/ns:ipAddress', namespaces)
                    ip_addr = ip_element.text if ip_element is not None else 'N/A'

                    self.log_message(f"Parsed Channel - ID: {channel_id}, Name: {name}, IP: {ip_addr}")  # 调试信息
                    self.tree.insert('', 'end', values=(channel_id, name, ip_addr, ''))
                self.log_message("通道信息获取成功")
            else:
                error_message = f"API返回异常状态码：{response.status_code}"
                self.log_message(error_message)
                messagebox.showerror("错误", error_message)
        except Exception as e:
            error_message = f"连接失败：{str(e)}"
            self.log_message(error_message)
            messagebox.showerror("错误", error_message)


    def update_ips(self):
        Thread(target=self._update_ips, daemon=True).start()

    def _update_ips(self):
        try:
            ip = self.device_ip.get()
            user = self.username.get()
            pwd = self.password.get()

            for item in self.tree.get_children():
                values = self.tree.item(item)['values']
                if len(values) >= 4 and values[3]:  # 检查新IP是否为空
                    channel_id = values[0]
                    new_channel_id = str(values[3])

                    # 发请求配置通道ID
                    channel_url = f"http://{ip}/ISAPI/System/Network/SIP/1/SIPInfo"
                    self.log_message(f"正在配置设备 {ip} 的通道ID...")
                    response = requests.get(
                        channel_url,
                        auth=HTTPDigestAuth(user, pwd),
                        timeout=15,
                        verify=False
                    )
                    if response.status_code != 200:
                        self.log(f"无法获取设备 {ip} 的通道配置，状态码: {response.status_code}")
                        return

                    existing_config = ET.fromstring(response.text)
                    namespace = self.extract_namespace(response.text)
                    ns = {'ns': namespace} if namespace else {}
                    # 查找现有通道配置
                    existing_channel = existing_config.find(f".//ns:VideoInputList/ns:VideoInput[ns:id='{channel_id}']", namespaces=ns)
                    if existing_channel is not None:
                        self.log_message(f"更新通道 {channel_id} 的配置...")
                        # 通道起始编号自增1,保证通道起始编号始终20位，并以此更新videoInputID
                        existing_channel.find("ns:videoInputID", namespaces=ns).text = new_channel_id
                        self.log_message(f"配置通道：{channel_id}->{new_channel_id}")

                    # 移除命名空间前缀
                    for elem in existing_config.iter():
                        if '}' in elem.tag:
                            elem.tag = elem.tag.split('}', 1)[1]
                        elem.attrib = {k.split('}', 1)[-1]: v for k, v in elem.attrib.items()}
                    updated_config = ET.tostring(existing_config, encoding='utf-8', method='xml').decode('utf-8')
                    # self.log(f"更新后的通道配置XML:\n{updated_config}")
                    headers = {
                        "Content-Type": "application/xml; charset=UTF-8",
                        "User-Agent": "HikConfigTool/3.0"
                    }
                    put_response = requests.put(
                        channel_url,
                        auth=HTTPDigestAuth(user,pwd),
                        headers=headers,
                        data=updated_config.encode('utf-8'),
                        timeout=15,
                        verify=False
                    )
                    # 打印调试信息
                    # self.log_message(f"更新通道 {channel_id} 的 XML: {updated_xml.decode('utf-8')}")

                    if put_response.status_code == 200:
                        self.tree.item(item, values=(values[0], values[1], new_channel_id, ''))
                        self.log_message(f"通道 {channel_id} 更新成功")
                    else:
                        error_message = f"通道 {channel_id} 更新失败（状态码 {put_response.status_code}）\n 失败信息 {put_response.text}"
                        self.log_message(error_message)
                        messagebox.showwarning("警告", error_message)

            self.log_message("配置操作已完成")
            messagebox.showinfo("完成", "配置操作已完成")

        except Exception as e:
            error_message = f"更新失败：{str(e)}"
            self.log_message(error_message)
            messagebox.showerror("错误", error_message)

if __name__ == "__main__":
    app = HikvisionGBChannelManager()
    app.root.mainloop()
