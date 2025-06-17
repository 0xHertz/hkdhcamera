import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests
from threading import Thread
from requests.auth import HTTPDigestAuth,HTTPBasicAuth

class DahuaChannelManager:
    def __init__(self, root=None):
        self.root = root or tk.Tk()
        if isinstance(self.root, tk.Tk):
            self.root.title("大华设备通道管理")
            # self.root.geometry("1000x700")  # 设置窗口大小
            # self.root.resizable(False, False)  # 禁止调整窗口大小
        self.create_widgets()
        self.channels = []

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
        self.password = ttk.Entry(device_info_frame, show="*", width=20)
        self.password.grid(row=2, column=1, padx=5, pady=5)

        # 功能按钮
        button_frame = ttk.Frame(top_frame)
        button_frame.pack(side=tk.RIGHT, padx=10)

        ttk.Button(button_frame, text="获取通道信息", command=self.fetch_channels, width=15).pack(pady=5)
        ttk.Button(button_frame, text="批量更新IP", command=self.update_ips, width=15).pack(pady=5)

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
        self.tree.heading('new_ip', text='新IP')
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
                    new_ip = simpledialog.askstring("输入新IP", "请输入新的IP地址:", initialvalue=old_value)
                    if new_ip is not None:
                        self.tree.set(item, column=col, value=new_ip)

    def fetch_channels(self):
        Thread(target=self._fetch_channels, daemon=True).start()

    def _fetch_channels(self):
        try:
            ip = self.device_ip.get()
            user = self.username.get()
            pwd = self.password.get()

            url = f"http://{ip}/cgi-bin/configManager.cgi?action=getConfig&name=RemoteDevice"

            try:
                response = requests.get(url, auth=HTTPDigestAuth(user, pwd), timeout=10)
            except requests.exceptions.HTTPError:
                response = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=10)

            if response.status_code == 200:
                # self.log_message(f"API Response: {response.text}")  # 打印返回的原始数据
                try:
                    # 假设返回的是纯文本格式
                    lines = response.text.strip().split('\n')

                    # 清空表格
                    self.tree.delete(*self.tree.get_children())
                    device_id = None
                    current_ip = None
                    # 遍历每一行，提取通道信息
                    for line in lines:
                        if "System_CONFIG_NETCAMERA_INFO_" in line:
                            parts = line.split('=')
                            if len(parts) == 2:
                                key, value = parts
                                if ".Address" in key:
                                    device_id = key.split('_')[-1].split('.')[0]  # 提取设备 ID
                                    current_ip = value.strip()
                                elif ".VideoInputs[0].Name" in key:
                                    channel_name = value.strip()
                                    # 将设备信息插入表格
                                    self.tree.insert('', 'end', values=(device_id, channel_name, current_ip, ''))
                    self.log_message("通道信息获取成功")
                except Exception as e:
                    error_message = f"数据解析失败：{str(e)}"
                    self.log_message(error_message)
                    messagebox.showerror("错误", error_message)
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
                    new_ip = values[3]

                    # 修改 IP 地址并发送更新请求
                    update_url = f"http://{ip}/cgi-bin/configManager.cgi?action=setConfig&RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_{channel_id}.Address={new_ip}"

                    response = requests.post(update_url, auth=HTTPDigestAuth(user, pwd), timeout=10)

                    if response.status_code == 200 and "OK" in response.text:
                        self.tree.item(item, values=(values[0], values[1], new_ip, ''))
                        self.log_message(f"通道 {channel_id} 更新成功")
                    else:
                        error_message = f"通道 {channel_id} 更新失败（状态码 {response.status_code}）\n {response.text}"
                        self.log_message(error_message)
                        messagebox.showwarning("警告", error_message)

            self.log_message("IP更新操作已完成")
            messagebox.showinfo("完成", "IP更新操作已完成")

        except Exception as e:
            error_message = f"更新失败：{str(e)}"
            self.log_message(error_message)
            messagebox.showerror("错误", error_message)


if __name__ == "__main__":
    app = DahuaChannelManager()
    app.root.mainloop()
