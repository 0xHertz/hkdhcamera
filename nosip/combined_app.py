import tkinter as tk
from tkinter import ttk,messagebox
from dhcamera import DahuaIPConfigurator
from dhchannel import DahuaChannelManager
from channl import HikvisionChannelManager
from camera import HikvisionIPConfigurator
from gbconfig import GBConfigurator
from videoconfig import VideoEncodingConfigurator

class CombinedApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("综合设备管理工具")
        self.geometry("1200x900")
        self.show_warning()
        self.create_tabs()

    def show_warning(self):
        """显示启动警告弹窗"""
        messagebox.showwarning("警告", "第三方工具，风险不可控")

    def create_tabs(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Hikvision IP Configurator Tab
        hikvision_ip_frame = ttk.Frame(notebook)
        notebook.add(hikvision_ip_frame, text="海康摄像头批量配置")
        HikvisionIPConfigurator(hikvision_ip_frame)

        # Hikvision Channel Manager Tab
        hikvision_channel_frame = ttk.Frame(notebook)
        notebook.add(hikvision_channel_frame, text="海康设备通道管理")
        HikvisionChannelManager(hikvision_channel_frame)

        # Dahua IP Configurator Tab
        dahua_ip_frame = ttk.Frame(notebook)
        notebook.add(dahua_ip_frame, text="大华摄像头批量配置")
        DahuaIPConfigurator(dahua_ip_frame)

        # Dahua Channel Manager Tab
        dahua_channel_frame = ttk.Frame(notebook)
        notebook.add(dahua_channel_frame, text="大华设备通道管理")
        DahuaChannelManager(dahua_channel_frame)

        # GB Configurator Tab
        gb_config_frame = ttk.Frame(notebook)
        notebook.add(gb_config_frame, text="海康国标&通道编号配置")
        GBConfigurator(gb_config_frame)

        # Video encoding Configurator Tab
        gb_config_frame = ttk.Frame(notebook)
        notebook.add(gb_config_frame, text="视频编码配置")
        VideoEncodingConfigurator(gb_config_frame)

if __name__ == "__main__":
    app = CombinedApp()
    app.mainloop()
