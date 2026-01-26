import os
import threading
import time
import configparser
import requests
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinterdnd2 import DND_FILES, TkinterDnD
import tempfile
import sys
import segno
from io import BytesIO
from PIL import Image, ImageTk
import base64
import re
import requests
from utils import get_idle_seconds, get_filename_suffix, is_valid_host, decode_response_content

class CloudLoginClient:
    def __init__(self, server_address, username, password, on_error):
        self.server_address = server_address
        self.username = username
        self.password = password
        self.on_error = on_error

        self.session_id = None
        self.user_id = None

        self.modulus_hex = None
        self.exponent_hex = None
        self.encrypted_password = None

    def login(self):
        try:
            self.get_public_params()
            self.encrypt()
            self.get_user_credentials()
            return self.user_id, self.session_id
        except Exception as exc:
            self.on_error("login", exc)

    def get_public_params(self):
        url = f"http://{self.server_address}/cloudservice/cloud/cloudoffice_encryption.js"
        params = {"v": "2.02"}
        headers = {
            "Referer": f"http://{self.server_address}/cloudservice/login.html",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
        }
        response = requests.get(url, params=params, headers=headers, timeout=10)
        js_string = decode_response_content(response.content)

        self.modulus_hex = re.search(
            r'modulusForHex:\s*"([^"]+)"', js_string
        ).group(1)
        self.exponent_hex = re.search(
            r'publicExponentForHex:\s*"([^"]+)"', js_string
        ).group(1)

    def pkcs1_pad(self, message, key_size):
        max_len = key_size - 11
        padding_len = key_size - len(message) - 3
        padding = b""
        while len(padding) < padding_len:
            byte = os.urandom(1)
            if byte != b"\x00":
                padding += byte

        return b"\x00\x02" + padding + b"\x00" + message

    def encrypt(self):
        n = int(self.modulus_hex, 16)
        e = int(self.exponent_hex, 16)

        key_size = (n.bit_length() + 7) // 8
        padded = self.pkcs1_pad(self.password.encode("utf-8"), key_size)
        m = int.from_bytes(padded, "big")
        c = pow(m, e, n)
        encrypted = c.to_bytes(key_size, "big")
        self.encrypted_password = base64.b64encode(encrypted).decode("utf-8")

    def get_user_credentials(self):
        url = f"http://{self.server_address}/cloudservice/userManage/loginOrRegister/login"
        params = {
            "userName": self.username,
            "password": self.encrypted_password,
            "version": "1.0.6.02",
            "client": "pc",
            "_token_": "e5cd7e4891bf95d1d19206ce24a7b32e",
        }
        headers = {
            "Accept": "text/html, application/xhtml+xml, image/jxr, */*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
            "Referer": f"http://{self.server_address}/",
            "Accept-Language": "zh-CN",
            "Host": "141.28.16.127",
            "Connection": "Close",
            "Accept-Encoding": "gzip, deflate",
        }
        response = requests.get(url, params=params, headers=headers, timeout=10)
        json_data = response.json()

        self.session_id = json_data["data"]["userInfo"]["sessionId"]
        self.user_id = json_data["data"]["userInfo"]["userId"]

class ConfigDialog:
    def __init__(self, parent, current_config, on_save_callback):
        self.parent = parent
        self.current_config = current_config or {}
        self.on_save_callback = on_save_callback
        
        self.dialog = None
        
        self._create_dialog()
    
    def _create_dialog(self):
        self.dialog = ttk.Toplevel(self.parent)
        self.dialog.title("配置")
        self.dialog.geometry("380x260")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() - 450) // 2
        y = (self.dialog.winfo_screenheight() - 340) // 2
        self.dialog.geometry(f"+{x}+{y}")
        
        frame = ttk.Frame(self.dialog, padding=20)
        frame.pack(fill=BOTH, expand=YES)
        
        ttk.Label(frame, text="服务器地址:").grid(row=0, column=0, sticky=W, pady=8)
        self.server_entry = ttk.Entry(frame, width=35)
        self.server_entry.grid(row=0, column=1, pady=8, padx=(10, 0))
        self.server_entry.insert(0, self.current_config.get('server_address', ''))
        
        ttk.Label(frame, text="账号:").grid(row=1, column=0, sticky=W, pady=8)
        self.username_entry = ttk.Entry(frame, width=35)
        self.username_entry.grid(row=1, column=1, pady=8, padx=(10, 0))
        self.username_entry.insert(0, self.current_config.get('username', ''))
        
        ttk.Label(frame, text="密码:").grid(row=2, column=0, sticky=W, pady=8)
        self.password_entry = ttk.Entry(frame, width=35, show="*")
        self.password_entry.grid(row=2, column=1, pady=8, padx=(10, 0))
        self.password_entry.insert(0, self.current_config.get('password', ''))
        
        ttk.Label(
            frame, 
            text="服务器地址格式: IP或域名，如 192.168.1.100 或 example.com",
            font=("宋体", 8), 
            foreground="gray"
        ).grid(row=4, column=0, columnspan=2, sticky=W, pady=(5, 0))
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=20)
        
        ttk.Button(
            btn_frame, 
            text="登录",
            command=self._on_login,
            bootstyle="success", 
            width=10
        ).pack(side=LEFT, padx=10)
        
        ttk.Button(
            btn_frame, 
            text="取消", 
            command=self._on_close, 
            bootstyle="secondary", 
            width=10
        ).pack(side=LEFT)
        
    
    def _on_login(self):
        server = self.server_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not server:
            messagebox.showwarning("警告", "服务器地址不能为空！", parent=self.dialog)
            return
        if not is_valid_host(server):
            messagebox.showwarning("警告", "请填写正确的服务器地址！", parent=self.dialog)
            return
        if not username or not password:
            messagebox.showwarning("警告", "账号和密码不能为空！", parent=self.dialog)
            return
        
        def on_error(stage, exc):
            messagebox.showerror("错误", f"登录失败（{stage}）: {exc}", parent=self.dialog)
        
        try:
            client = CloudLoginClient(server, username, password, on_error)
            result = client.login()
            if not result:
                return
            user_id, session_id = result
            if not user_id or not session_id:
                messagebox.showerror("错误", "登录失败，未获取到用户信息。", parent=self.dialog)
                return
        except Exception as exc:
            messagebox.showerror("错误", f"登录异常: {exc}", parent=self.dialog)
            return
        
        if self.on_save_callback:
            self.on_save_callback(server, username, password, user_id, session_id)
        
        self.dialog.destroy()
    

    def _on_close(self):
        self.dialog.destroy()

class DownloadManager:
    def __init__(self, parent, files_to_download, save_dir, user_id, session_id, base_url):
        self.parent = parent
        self.files_to_download = files_to_download
        self.save_dir = save_dir
        self.user_id = user_id
        self.session_id = session_id
        self.base_url = base_url
        
        self.is_cancelled = False
        self.download_complete = False
        self.file_status = {}
        self.active_responses = []
        
        self.setup_window()
        self.start_downloads()
        
    def setup_window(self):
        self.window = ttk.Toplevel(self.parent)
        self.window.title("下载管理器")
        self.window.geometry("650x450")
        self.window.resizable(True, True)
        self.window.transient(self.parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() - 650) // 2
        y = (self.window.winfo_screenheight() - 450) // 2
        self.window.geometry(f"+{x}+{y}")
        
        main_frame = ttk.Frame(self.window, padding=10)
        main_frame.pack(fill=BOTH, expand=YES)
        
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=X, pady=(0, 10))
        
        self.status_var = ttk.StringVar(value=f"准备下载 {len(self.files_to_download)} 个文件...")
        ttk.Label(top_frame, textvariable=self.status_var, font=("Helvetica", 11, "bold")).pack(side=LEFT)
        
        total_frame = ttk.Frame(main_frame)
        total_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(total_frame, text="总进度:").pack(side=LEFT)
        self.total_progress_var = ttk.DoubleVar(value=0)
        self.total_progress = ttk.Progressbar(total_frame, variable=self.total_progress_var,
            maximum=100, bootstyle="success-striped", length=450)
        self.total_progress.pack(side=LEFT, fill=X, expand=YES, padx=10)
        
        self.total_percent_var = ttk.StringVar(value="0%")
        ttk.Label(total_frame, textvariable=self.total_percent_var, width=6).pack(side=RIGHT)
        
        list_frame = ttk.LabelFrame(main_frame, text="下载详情", padding=5)
        list_frame.pack(fill=BOTH, expand=YES, pady=10)
        
        canvas = ttk.Canvas(list_frame)
        scrollbar = ttk.Scrollbar(list_frame, orient=VERTICAL, command=canvas.yview)
        self.files_frame = ttk.Frame(canvas)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill=Y)
        canvas.pack(side=LEFT, fill=BOTH, expand=YES)
        
        canvas_window = canvas.create_window((0, 0), window=self.files_frame, anchor=NW)
        
        self.files_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_window, width=e.width))
        
        self.file_widgets = {}
        for idx, file_info in self.files_to_download:
            file_name = file_info.get('fileName', '')
            
            item_frame = ttk.Frame(self.files_frame)
            item_frame.pack(fill=X, pady=3, padx=5)
            
            name_label = ttk.Label(item_frame, text=file_name, width=35, anchor=W)
            name_label.pack(side=LEFT)
            
            progress_var = ttk.DoubleVar(value=0)
            progress_bar = ttk.Progressbar(item_frame, variable=progress_var,
                maximum=100, bootstyle="info-striped", length=200)
            progress_bar.pack(side=LEFT, padx=10)
            
            status_var = ttk.StringVar(value="等待中...")
            ttk.Label(item_frame, textvariable=status_var, width=15, anchor=W).pack(side=LEFT)
            
            self.file_widgets[idx] = {
                'progress_var': progress_var,
                'progress_bar': progress_bar,
                'status_var': status_var
            }
            self.file_status[idx] = {'status': 'waiting', 'path': ''}
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X, pady=(10, 0))
        
        self.cancel_btn = ttk.Button(btn_frame, text="取消下载", command=self.on_cancel,
            bootstyle="danger", width=15)
        self.cancel_btn.pack(side=RIGHT)
        
        self.close_btn = ttk.Button(btn_frame, text="关闭", command=self.on_close,
            bootstyle="secondary", width=15, state=DISABLED)
        self.close_btn.pack(side=RIGHT, padx=10)
        
        self.open_folder_btn = ttk.Button(btn_frame, text="打开文件夹", command=self.open_folder,
            bootstyle="info", width=15, state=DISABLED)
        self.open_folder_btn.pack(side=RIGHT, padx=10)
        
    def open_folder(self):
        try:
            os.startfile(self.save_dir)
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件夹: {e}", parent=self.window)

    def start_downloads(self):
        threading.Thread(target=self.download_all, daemon=True).start()

    def download_all(self):
        total_files = len(self.files_to_download)
        completed = 0

        def download_single(idx, file_info):
            if self.is_cancelled:
                return False

            file_name = file_info.get('fileName', '')
            file_id = file_info.get('id', '')
            file_size = int(file_info.get('size', 0))

            save_path = os.path.join(self.save_dir, file_name)
            self.file_status[idx]['path'] = save_path
            self.file_status[idx]['status'] = 'downloading'

            RETRY_LIMIT = 3
            retry_count = 0
            LOW_SPEED_LIMIT = 100 * 1024  # 100 KB/s

            while True:
                if self.is_cancelled:
                    return False

                response = None
                try:
                    self.update_file_status(idx, "连接中...", 0)

                    params = {'fileIds': file_id, 'userId': self.user_id, 'sessionId': self.session_id}
                    response = requests.get(
                        f"{self.base_url}/downLoadCacheFile",
                        params=params,
                        stream=True,
                        timeout=(10, 30)
                    )
                    response.raise_for_status()
                    self.active_responses.append(response)

                    total_size = int(response.headers.get('content-length', file_size)) or file_size or 1
                    downloaded = 0

                    last_time = time.time()
                    last_bytes = 0
                    low_speed_start = None

                    with open(save_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if self.is_cancelled:
                                f.close()
                                self.cleanup_file(save_path)
                                return False

                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)

                                now = time.time()
                                if now - last_time >= 0.3:
                                    speed = (downloaded - last_bytes) / (now - last_time)
                                    progress = downloaded / total_size * 100
                                    self.update_file_status(idx, self.format_speed(speed), progress)
                                    last_time, last_bytes = now, downloaded

                                    if retry_count < RETRY_LIMIT:
                                        if speed < LOW_SPEED_LIMIT:
                                            if low_speed_start is None:
                                                low_speed_start = now
                                            elif now - low_speed_start >= 1:
                                                retry_count += 1
                                                self.update_file_status(idx, f"速度过低，重试({retry_count}/{RETRY_LIMIT})...", progress, "warning")
                                                raise RuntimeError("LOW_SPEED_RETRY")
                                        else:
                                            low_speed_start = None

                        self.file_status[idx]['status'] = 'completed'
                        self.update_file_status(idx, "✓ 完成", 100, "success")
                        return True

                except RuntimeError as re:
                    if str(re) == "LOW_SPEED_RETRY":
                        try:
                            if response:
                                response.close()
                        except:
                            pass

                        if retry_count >= RETRY_LIMIT:
                            self.update_file_status(idx, "已达重试上限，继续下载...", 0, "info")
                            time.sleep(1)
                            continue
                        else:
                            time.sleep(1)
                            continue
                    else:
                        self.file_status[idx]['status'] = 'failed'
                        self.update_file_status(idx, "✗ 失败", 0, "danger")
                        self.cleanup_file(save_path)
                        return False

                except requests.exceptions.Timeout:
                    self.file_status[idx]['status'] = 'failed'
                    self.update_file_status(idx, "✗ 超时", 0, "danger")
                    self.cleanup_file(save_path)
                    return False

                except Exception:
                    self.file_status[idx]['status'] = 'failed'
                    err_msg = "✗ 已取消" if self.is_cancelled else "✗ 失败"
                    self.update_file_status(idx, err_msg, 0, "danger")
                    self.cleanup_file(save_path)
                    return False

                finally:
                    if response and response in self.active_responses:
                        try:
                            self.active_responses.remove(response)
                        except:
                            pass
                    try:
                        if response:
                            response.close()
                    except:
                        pass

        with ThreadPoolExecutor(max_workers=min(5, total_files)) as executor:
            futures = {executor.submit(download_single, idx, info): idx 
                      for idx, info in self.files_to_download}
            for future in as_completed(futures):
                if self.is_cancelled:
                    break
                completed += 1
                self.update_total_progress(completed, total_files)

        self.download_complete = True
        
        if not self.is_cancelled:
            success = sum(1 for s in self.file_status.values() if s['status'] == 'completed')
            failed = sum(1 for s in self.file_status.values() if s['status'] == 'failed')
            self.window.after(0, lambda: self.status_var.set(f"下载完成！成功: {success}, 失败: {failed}"))
            self.window.after(0, lambda: self.open_folder_btn.configure(state=NORMAL))
        else:
            self.window.after(0, lambda: self.status_var.set("下载已取消"))
        
        self.window.after(0, lambda: self.cancel_btn.configure(state=DISABLED))
        self.window.after(0, lambda: self.close_btn.configure(state=NORMAL))

    def update_file_status(self, idx, text, progress, style=None):
        def update():
            if idx in self.file_widgets:
                self.file_widgets[idx]['status_var'].set(text)
                self.file_widgets[idx]['progress_var'].set(progress)
                if style:
                    self.file_widgets[idx]['progress_bar'].configure(bootstyle=style)
        self.window.after(0, update)

    def update_total_progress(self, completed, total):
        def update():
            percent = completed / total * 100
            self.total_progress_var.set(percent)
            self.total_percent_var.set(f"{percent:.0f}%")
            self.status_var.set(f"正在下载... ({completed}/{total})")
        self.window.after(0, update)

    def format_speed(self, speed):
        if speed < 1024:
            return f"{speed:.0f} B/s"
        elif speed < 1024 * 1024:
            return f"{speed/1024:.1f} KB/s"
        return f"{speed/1024/1024:.1f} MB/s"

    def cleanup_file(self, path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except:
            pass

    def on_cancel(self):
        has_pending = any(
            status['status'] in ['downloading', 'waiting'] 
            for status in self.file_status.values()
        )
        
        if not has_pending or self.download_complete:
            self.window.destroy()
            return
        
        if self.is_cancelled:
            return
        
        if messagebox.askyesno("确认", "确定取消下载？\n未完成的文件将被删除。", parent=self.window):
            self.is_cancelled = True
            self.status_var.set("正在取消...")
            self.cancel_btn.configure(state=DISABLED)
            
            for response in self.active_responses[:]:
                try:
                    response.close()
                except:
                    pass
            self.active_responses.clear()
            
            for idx, status in self.file_status.items():
                if status['status'] in ['downloading', 'waiting']:
                    self.cleanup_file(status['path'])
                    status['status'] = 'cancelled'
                    self.update_file_status(idx, "已取消", 0, "secondary")

    def on_close(self):
        self.window.destroy()


class CloudFileManager:
    def __init__(self):
        self.root = TkinterDnD.Tk()
        self.style = ttk.Style(theme="cosmo")
        self.root.title("云端文件管理器")
        self.root.geometry("900x700")
        
        self.user_id = ""
        self.session_id = ""
        self.server_address = ""
        self.username = ""
        self.password = ""
        self.is_configured = False
        self.files_data = []
        self.selected_file_index = None
        self.checked_files = set()
        self.current_tab = "download"
        self.text_extensions = {'.txt','.js','.html','.htm','.py','.cpp','.c','.h','.hpp',
            '.css','.json','.xml','.md','.yaml','.yml','.ini','.cfg','.sh','.bat',
            '.java','.cs','.go','.rs','.php','.rb','.sql','.log','.csv'}
        self.running = True
        
        self.config_dialog_open = False
        self.countdown_reset_event = threading.Event()
        self.skip_fetch_on_reset = False
        
        self.upload_files_list = []
        self.upload_in_progress = False
        self.upload_cancelled = False
        self.upload_file_widgets = {}
        self.upload_executor = None
        
        self.setup_ui()
        self.load_config()
        self.start_background_tasks()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)


    @property
    def base_url(self):
        """动态生成base_url"""
        return f"http://{self.server_address}/cloudservice/commoncodenew"
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=BOTH, expand=YES)
        
        # 顶部区域（保持不变）
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=X, pady=(0, 10))
        
        code_frame = ttk.LabelFrame(top_frame, text="上传码", padding=10)
        code_frame.pack(side=LEFT, fill=X, expand=YES)
        
        self.code_var = ttk.StringVar(value="------")
        ttk.Label(code_frame, textvariable=self.code_var, font=("Helvetica", 48, "bold"),
            foreground="#007bff", anchor=CENTER).pack(fill=X, pady=10)
        
        self.countdown_var = ttk.StringVar(value="")
        ttk.Label(code_frame, textvariable=self.countdown_var, foreground="gray").pack()
        
        config_frame = ttk.Frame(top_frame)
        config_frame.pack(side=RIGHT, padx=(50, 0))
        
        ttk.Button(config_frame, text="⚙ 配置", command=self.show_config_dialog,
            bootstyle="secondary-outline", width=10).pack()
        
        self.status_var = ttk.StringVar(value="● 未配置")
        self.status_label = ttk.Label(config_frame, textvariable=self.status_var,
            font=("Helvetica", 9), foreground="red")
        self.status_label.pack(pady=(5, 0))
        
        # 分页区域（新增）
        self.notebook = ttk.Notebook(main_frame, bootstyle="primary")
        self.notebook.pack(fill=BOTH, expand=YES, pady=10)
        
        # 下载页面
        download_page = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(download_page, text="  下载  ")
        self.setup_download_page(download_page)
        
        # 上传页面
        upload_page = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(upload_page, text="  上传  ")
        self.setup_upload_page(upload_page)
        
        # 绑定标签页切换事件
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # 底部状态栏
        self.info_var = ttk.StringVar(value="准备就绪")
        ttk.Label(main_frame, textvariable=self.info_var, foreground="gray").pack(anchor=W)

    def force_fetch_code(self):
        """
        登录成功 / 重新登录后，强制立即获取验证码
        """
        if not self.is_configured:
            return

        threading.Thread(target=self.fetch_code, daemon=True).start()

        self.skip_fetch_on_reset = False
        self.countdown_reset_event.set()

    def setup_download_page(self, parent):
        """设置下载页面"""
        middle_frame = ttk.Frame(parent)
        middle_frame.pack(fill=BOTH, expand=YES)
        
        file_frame = ttk.LabelFrame(middle_frame, text="文件列表", padding=5)
        file_frame.pack(side=LEFT, fill=BOTH, expand=YES, padx=(0, 5))
        
        list_container = ttk.Frame(file_frame)
        list_container.pack(fill=BOTH, expand=YES)
        
        self.file_canvas = ttk.Canvas(list_container)
        scrollbar = ttk.Scrollbar(list_container, orient=VERTICAL, command=self.file_canvas.yview)
        self.file_list_frame = ttk.Frame(self.file_canvas)
        
        self.file_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.file_canvas.pack(side=LEFT, fill=BOTH, expand=YES)
        
        self.canvas_window = self.file_canvas.create_window((0, 0), window=self.file_list_frame, anchor=NW)
        self.file_list_frame.bind("<Configure>", lambda e: self.file_canvas.configure(scrollregion=self.file_canvas.bbox("all")))
        self.file_canvas.bind("<Configure>", lambda e: self.file_canvas.itemconfig(self.canvas_window, width=e.width))
        
        self.file_items = []
        self.check_vars = []
        
        for i in range(20):
            item_frame = ttk.Frame(self.file_list_frame)
            item_frame.pack(fill=X, pady=1)
            
            check_var = ttk.BooleanVar(value=False)
            self.check_vars.append(check_var)
            
            ttk.Checkbutton(item_frame, variable=check_var,
                command=lambda idx=i: self.on_check_changed(idx), bootstyle="primary").pack(side=LEFT)
            
            file_label = ttk.Label(item_frame, text="", cursor="hand2", anchor=W)
            file_label.pack(side=LEFT, fill=X, expand=YES, padx=5)
            file_label.bind("<Button-1>", lambda e, idx=i: self.on_file_select(idx))
            
            self.file_items.append({'frame': item_frame, 'check_var': check_var, 'label': file_label})
        
        file_btn_frame = ttk.Frame(file_frame)
        file_btn_frame.pack(fill=X, pady=(5, 0))
        
        self.refresh_btn = ttk.Button(file_btn_frame, text="刷新",
            command=self.refresh_files, bootstyle="info", state=DISABLED)
        self.refresh_btn.pack(side=LEFT, padx=2)
        
        self.download_btn = ttk.Button(file_btn_frame, text="下载",
            command=self.download_files, bootstyle="success", state=DISABLED)
        self.download_btn.pack(side=LEFT, padx=2)
        
        text_frame = ttk.LabelFrame(middle_frame, text="文件内容预览", padding=5)
        text_frame.pack(side=RIGHT, fill=BOTH, expand=YES, padx=(5, 0))
        
        self.text_area = ttk.Text(text_frame, wrap=WORD, font=("Consolas", 10))
        text_scrollbar = ttk.Scrollbar(text_frame, orient=VERTICAL, command=self.text_area.yview)
        self.text_area.configure(yscrollcommand=text_scrollbar.set)
        text_scrollbar.pack(side=RIGHT, fill=Y)
        self.text_area.pack(side=LEFT, fill=BOTH, expand=YES)

    def setup_upload_page(self, parent):
        middle_frame = ttk.Frame(parent)
        middle_frame.pack(fill=BOTH, expand=YES)
        
        file_frame = ttk.LabelFrame(middle_frame, text="拖拽文件到此处上传", padding=5)
        file_frame.pack(side=LEFT, fill=BOTH, expand=YES, padx=(0, 5))
        
        list_container = ttk.Frame(file_frame)
        list_container.pack(fill=BOTH, expand=YES)
        
        self.upload_canvas = ttk.Canvas(list_container)
        upload_scrollbar = ttk.Scrollbar(list_container, orient=VERTICAL, command=self.upload_canvas.yview)
        self.upload_list_frame = ttk.Frame(self.upload_canvas)
        
        self.upload_canvas.configure(yscrollcommand=upload_scrollbar.set)
        upload_scrollbar.pack(side=RIGHT, fill=Y)
        self.upload_canvas.pack(side=LEFT, fill=BOTH, expand=YES)
        
        self.upload_canvas_window = self.upload_canvas.create_window((0, 0), window=self.upload_list_frame, anchor=NW)
        self.upload_list_frame.bind("<Configure>", lambda e: self.upload_canvas.configure(scrollregion=self.upload_canvas.bbox("all")))
        self.upload_canvas.bind("<Configure>", lambda e: self.upload_canvas.itemconfig(self.upload_canvas_window, width=e.width))
        
        self.upload_hint_label = ttk.Label(self.upload_list_frame, 
            text="\n\n\n将文件拖拽到此处\n\n支持同时拖拽多个文件", 
            font=("宋体", 12), foreground="gray", anchor=CENTER, justify=CENTER)
        self.upload_hint_label.pack(fill=BOTH, expand=YES, pady=50)
        
        upload_btn_frame = ttk.Frame(file_frame)
        upload_btn_frame.pack(fill=X, pady=(5, 0))
        
        self.add_upload_btn = ttk.Button(upload_btn_frame, text="选择文件",
            command=self.select_files, bootstyle="success")
        self.add_upload_btn.pack(side=LEFT, padx=2)
        
        self.cancel_upload_btn = ttk.Button(upload_btn_frame, text="取消上传",
            command=self.cancel_upload, bootstyle="danger", state=DISABLED)
        self.cancel_upload_btn.pack(side=RIGHT, padx=2)
        
        text_frame = ttk.LabelFrame(middle_frame, text="文本内容", padding=5)
        text_frame.pack(side=RIGHT, fill=BOTH, expand=YES, padx=(5, 0))
        
        text_container = ttk.Frame(text_frame)
        text_container.pack(fill=BOTH, expand=YES)
        
        self.upload_text_area = ttk.Text(text_container, wrap=WORD, height=15)
        upload_text_scrollbar = ttk.Scrollbar(text_container, orient=VERTICAL, command=self.upload_text_area.yview)
        self.upload_text_area.configure(yscrollcommand=upload_text_scrollbar.set)
        upload_text_scrollbar.pack(side=RIGHT, fill=Y)
        self.upload_text_area.pack(side=LEFT, fill=BOTH, expand=YES)
        
        text_btn_frame = ttk.Frame(text_frame)
        text_btn_frame.pack(fill=X, pady=(10, 5))
        
        btn_container = ttk.Frame(text_btn_frame)
        btn_container.pack(expand=YES)
        
        self.text_upload_btn = ttk.Button(btn_container, text="文本方式上传", 
            command=self.on_text_upload, bootstyle="info-outline", width=18)
        self.text_upload_btn.pack(side=LEFT, padx=8, pady=5)
        
        self.qrcode_upload_btn = ttk.Button(btn_container, text="二维码方式上传", 
            command=self.on_qrcode_upload, bootstyle="primary-outline", width=18)
        self.qrcode_upload_btn.pack(side=LEFT, padx=8, pady=5)
        
        self.root.after(100, self.register_drop_handler)

    def register_drop_handler(self):
        self.upload_canvas.drop_target_register(DND_FILES)
        self.upload_canvas.dnd_bind('<<Drop>>', self.on_files_dropped)

    def on_files_dropped(self, event):
        self.clear_upload_list()
        
        file_paths = self.parse_drop_data(event.data)
        
        decoded_paths = []
        for path in file_paths:
            if os.path.isfile(path):
                decoded_paths.append(path)
        
        if decoded_paths:
            self.handle_dropped_files(decoded_paths)

    def select_files(self):
        files = filedialog.askopenfilenames(
            title="选择文件",
            filetypes=[
                ("所有文件", "*.*"),
            ]
        )
        if files:
            file_paths = list(files)
            self.add_files_to_upload_list(file_paths)
        
    def parse_drop_data(self, data):
        files = []
        i = 0
        while i < len(data):
            if data[i] == '{':
                j = data.index('}', i)
                files.append(data[i+1:j])
                i = j + 2
            elif data[i] == ' ':
                i += 1
            else:
                j = data.find(' ', i)
                if j == -1:
                    j = len(data)
                files.append(data[i:j])
                i = j + 1
        return files
    
    def handle_dropped_files(self, file_paths):
        if not self.is_configured:
            messagebox.showwarning("警告", "请先配置服务器信息！")
            return
        
        if self.upload_in_progress:
            messagebox.showwarning("警告", "正在上传中，请等待完成或取消当前上传！")
            return
        
        self.add_files_to_upload_list(file_paths)

    def add_files_to_upload_list(self, file_paths):
        self.upload_hint_label.pack_forget()
        
        start_index = len(self.upload_files_list)
        for path in file_paths:
            if path not in self.upload_files_list:
                self.upload_files_list.append(path)
                self.create_upload_file_widget(len(self.upload_files_list) - 1, path)
        
        if not self.upload_in_progress and self.upload_files_list:
            self.start_upload()

    def create_upload_file_widget(self, index, file_path):
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        item_frame = ttk.Frame(self.upload_list_frame)
        item_frame.pack(fill=X, pady=2, padx=5)
        
        name_label = ttk.Label(item_frame, text=file_name, width=30, anchor=W)
        name_label.pack(side=LEFT)
        
        status_var = ttk.StringVar(value="等待中...")
        status_label = ttk.Label(item_frame, textvariable=status_var, width=15, anchor=W)
        status_label.pack(side=LEFT, padx=5)
        
        self.upload_file_widgets[index] = {
            'frame': item_frame,
            'status_var': status_var,
            'path': file_path,
            'size': file_size,
            'status': 'waiting',
            'file_id': None
        }

    def start_upload(self):
        self.upload_in_progress = True
        self.upload_cancelled = False
        self.cancel_upload_btn.configure(state=NORMAL)
        self.add_upload_btn.configure(state=DISABLED)
        
        threading.Thread(target=self.upload_all_files, daemon=True).start()

    def upload_all_files(self):
        total_files = len(self.upload_files_list)
        completed = 0
        success_ids = []
        
        def upload_single(index, file_path):
            if self.upload_cancelled:
                return None
            
            file_name = os.path.basename(file_path)
            
            try:
                self.update_upload_status(index, "上传中...")
                
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                file_size = len(file_content)
                
                if self.upload_cancelled:
                    return None
                
                url = f"{self.base_url}/uploadFileForTempOut"
                params = {
                    'userId': self.user_id,
                    'fileName': file_name,
                    'hash': '',
                    'size': file_size,
                    'sessionId': self.session_id,
                    'startPos': 0,
                }
                headers = {'Expect': '100-continue'}
                files = {'Filedata': (file_path, file_content, 'application/octet-stream')}
                
                response = requests.post(url, params=params, files=files, headers=headers, timeout=1200)
                
                if self.upload_cancelled:
                    return None
                
                if response and response.status_code == 200:
                    data = response.json()
                    assert data.get('msg') != "未登录"
                    file_id = data.get('data', {}).get('id')
                    self.upload_file_widgets[index]['file_id'] = file_id
                    self.upload_file_widgets[index]['status'] = 'completed'
                    self.update_upload_status(index, "已上传", "success")
                    return file_id
                else:
                    raise Exception(f"HTTP {response.status_code if response else 'Error'}")
            except AssertionError:
                self.root.after(0, lambda: self.info_var.set("登录状态失效，正在重新登录..."))
                if not self.relogin():
                    self.root.after(0, self.show_config_dialog)
            except:
                self.upload_file_widgets[index]['status'] = 'failed'
                self.update_upload_status(index, "✗ 失败", "danger")
                return None


        with ThreadPoolExecutor(max_workers=min(10, total_files)) as executor:
            self.upload_executor = executor
            futures = {executor.submit(upload_single, idx, path): idx 
                      for idx, path in enumerate(self.upload_files_list)}
            
            for future in as_completed(futures):
                if self.upload_cancelled:
                    break
                result = future.result()
                if result:
                    success_ids.append(result)
                completed += 1
        
        self.upload_executor = None
        
        self.root.after(0, lambda: self.on_upload_complete(success_ids))

    def do_update_upload_status(self, index, text, style=None):
        if index in self.upload_file_widgets:
            self.upload_file_widgets[index]['status_var'].set(text)
            if style:
                self.upload_file_widgets[index]['status_var'].set(text)

    def update_upload_status(self, index, text, style=None):
        self.root.after(0, lambda: self.do_update_upload_status(index, text, style))

    def on_upload_complete(self, success_ids):
        self.upload_in_progress = False
        self.cancel_upload_btn.configure(state=DISABLED)
        self.add_upload_btn.configure(state=NORMAL)
        self.info_var.set(f"上传完成")
        
        if hasattr(self, 'temp_upload_files'):
            for temp_path in self.temp_upload_files:
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except:
                    pass
            self.temp_upload_files.clear()
        
        if self.upload_cancelled:
            return
        
        if success_ids:
            self.create_download_code(success_ids)


    def create_download_code(self, file_ids):
        try:
            file_ids_str = ','.join(str(fid) for fid in file_ids)
            
            url = f"{self.base_url}/createDownCode"
            params = {
                'ownerType': '0',
                'fileIds': file_ids_str,
                'userId': self.user_id,
                'sessionId': self.session_id
            }
            
            response = requests.get(url, params=params, timeout=30)
            data = response.json()
            
            if data.get('success'):
                code = data.get('data', {}).get('code', '------')
                self.root.after(0, lambda: self.code_var.set(code))
                self.skip_fetch_on_reset = True
                self.countdown_reset_event.set()
            else:
                raise
        except:
            self.root.after(0, lambda: self.info_var.set("获取下载码失败"))

    def cancel_upload(self):
        if not self.upload_in_progress:
            return
        if messagebox.askyesno("确认", "确定取消上传？"):
            self.upload_cancelled = True
            self.cancel_upload_btn.configure(state=DISABLED)
            
            for idx, widget in self.upload_file_widgets.items():
                if widget['status'] == 'waiting':
                    self.update_upload_status(idx, "已取消", "secondary")
            
            if hasattr(self, 'temp_upload_files'):
                for temp_path in self.temp_upload_files:
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except:
                        pass
                self.temp_upload_files.clear()

    def clear_upload_list(self):
        self.upload_files_list.clear()
        
        for widget in self.upload_file_widgets.values():
            widget['frame'].destroy()
        self.upload_file_widgets.clear()
        
        self.upload_hint_label.pack(fill=BOTH, expand=YES, pady=50)

    def on_tab_changed(self, event):
        selected_tab = self.notebook.index(self.notebook.select())
        if selected_tab == 0:
            self.current_tab = "download"
            if self.is_configured:
                threading.Thread(target=self.fetch_files, daemon=True).start()
        else:
            self.current_tab = "upload"

    def load_config(self):
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
        if not hasattr(self, "username"):
            self.username = ""
        if not hasattr(self, "password"):
            self.password = ""
        try:
            if os.path.exists(config_path):
                config = configparser.ConfigParser()
                config.read(config_path, encoding='utf-8')
                self.user_id = config.get('Settings', 'userId', fallback='')
                self.session_id = config.get('Settings', 'sessionId', fallback='')
                self.server_address = config.get('Settings', 'serverAddress', fallback='')
                self.username = config.get('Settings', 'username', fallback=self.username)
                self.password = config.get('Settings', 'password', fallback=self.password)
        except Exception:
            pass

        if not self.server_address:
            self.root.after(500, self.show_config_dialog)
            return

        if self.user_id and self.session_id:
            self.is_configured = True
            self.update_status(True)
            self.enable_controls()
            self.force_fetch_code()
            threading.Thread(target=self.fetch_files, daemon=True).start()
            return

        if self.username and self.password:
            def auto_login():
                if self.relogin():
                    def after_success():
                        self.is_configured = True
                        self.update_status(True)
                        self.enable_controls()
                        self.info_var.set(f"配置已保存 - 服务器: {self.server_address}")
                        self.force_fetch_code()
                        threading.Thread(target=self.fetch_files, daemon=True).start()
                    self.root.after(0, after_success)
                else:
                    self.root.after(0, self.show_config_dialog)
            threading.Thread(target=auto_login, daemon=True).start()
        else:
            self.root.after(500, self.show_config_dialog)


    def save_config(self):
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
        config = configparser.ConfigParser()
        config['Settings'] = {
            'userId': self.user_id or '',
            'sessionId': self.session_id or '',
            'serverAddress': self.server_address or '',
            'username': self.username or '',
            'password': self.password or ''
        }
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                config.write(f)
            return True
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {e}")
            return False


    def show_config_dialog(self):
        for w in self.root.winfo_children():
            try:
                if w.winfo_exists() and hasattr(w, "title") and w.title() == "配置":
                    return
            except Exception:
                continue

        def on_config_saved(server_address, username, password, user_id, session_id):
            self.server_address = server_address
            self.username = username
            self.password = password
            self.user_id = user_id
            self.session_id = session_id
            
            if self.save_config():
                self.is_configured = True
                self.update_status(True)
                self.enable_controls()
                self.info_var.set(f"配置已保存 - 服务器: {server_address}")
                self.force_fetch_code()
                threading.Thread(target=self.fetch_files, daemon=True).start()
        
        ConfigDialog(
            parent=self.root,
            current_config={
                'server_address': self.server_address,
                'username': getattr(self, 'username', ''),
                'password': getattr(self, 'password', '')
            },
            on_save_callback=on_config_saved
        )

    def handle_login_error(self, stage, exc):
        def _show():
            self.info_var.set("登录失败")
            messagebox.showerror("错误", f"登录失败（{stage}）: {exc}")
        self.root.after(0, _show)

    def relogin(self):
        if not (self.server_address and getattr(self, 'username', '') and getattr(self, 'password', '')):
            def _warn():
                self.info_var.set("缺少账号或密码，请重新配置")
                messagebox.showwarning("警告", "缺少账号或密码，请在配置界面填写账号和密码后重新登录！")
                self.show_config_dialog()
            self.root.after(0, _warn)
            return False
        try:
            client = CloudLoginClient(self.server_address, self.username, self.password, self.handle_login_error)
            result = client.login()
            if not result:
                return False
            user_id, session_id = result
            if not user_id or not session_id:
                self.root.after(0, lambda: self.info_var.set("登录失败，未获取到用户信息"))
                return False
            self.user_id = user_id
            self.session_id = session_id
            self.save_config()
            self.force_fetch_code()
            return True
        except Exception as exc:
            self.handle_login_error("login", exc)
            return False

    def update_status(self, configured):
        if configured:
            self.status_var.set("● 已配置")
            self.status_label.configure(foreground="green")
        else:
            self.status_var.set("● 未配置")
            self.status_label.configure(foreground="red")

    def enable_controls(self):
        self.refresh_btn.configure(state=NORMAL)
        self.download_btn.configure(state=NORMAL)

    def start_background_tasks(self):
        threading.Thread(target=self.code_update_loop, daemon=True).start()
        threading.Thread(target=self.files_update_loop, daemon=True).start()

    def code_update_loop(self):
        while self.running:
            if self.skip_fetch_on_reset:
                self.skip_fetch_on_reset = False
            elif self.is_configured:
                self.fetch_code()
            
            self.countdown_reset_event.clear()
            for i in range(3600):
                if not self.running:
                    break
                if self.countdown_reset_event.wait(timeout=1):
                    break
                if self.is_configured:
                    r = 3600 - i - 1
                    self.root.after(0, lambda m=r//60, s=r%60: self.countdown_var.set(f"刷新倒计时: {m}分{s}秒"))

    def should_auto_fetch_files(self):
        if not (self.is_configured and self.current_tab == "download"):
            return False

        idle_seconds = get_idle_seconds()
        if idle_seconds is None:
            return True

        return idle_seconds < 60

    def files_update_loop(self):
        paused_by_idle = False

        while self.running:
            if self.should_auto_fetch_files():
                if paused_by_idle:
                    paused_by_idle = False
                    self.root.after(
                        0,
                        lambda: self.info_var.set("检测到用户操作，恢复自动刷新文件列表")
                    )

                self.fetch_files()
            else:
                if self.is_configured and self.current_tab == "download":
                    idle_seconds = get_idle_seconds()
                    if (
                        idle_seconds is not None
                        and idle_seconds >= 60
                        and not paused_by_idle
                    ):
                        paused_by_idle = True
                        self.root.after(
                            0,
                            lambda: self.info_var.set("已暂停自动刷新（空闲超过 60 秒）")
                        )
                        
            for _ in range(60):
                if not self.running:
                    break

                if paused_by_idle and self.should_auto_fetch_files():
                    break

                time.sleep(1)

    def fetch_code(self):
        if not self.is_configured:
            return
        try:
            self.root.after(0, lambda: self.info_var.set("获取上传码..."))
            resp = requests.get(f"{self.base_url}/createUploadCode",
                params={'ownerType': '0', 'userId': self.user_id, 'sessionId': self.session_id}, timeout=30)
            data = resp.json()
            assert data.get('msg') != "未登录"
            code = data.get('data', {}).get('code', '------')
            self.root.after(0, lambda: self.code_var.set(code))
            self.root.after(0, lambda: self.info_var.set("获取上传码成功"))
        except AssertionError:
            self.root.after(0, lambda: self.info_var.set("登录状态失效，正在重新登录..."))
            if not self.relogin():
                self.root.after(0, self.show_config_dialog)
        except:
            self.root.after(0, lambda: self.info_var.set(f"获取上传码失败"))

    def fetch_files(self):
        if not self.is_configured:
            return
        try:
            self.root.after(0, lambda: self.info_var.set("获取文件列表..."))
            resp = requests.get(f"{self.base_url}/getUploadFiles",
                params={'page': '1', 'count': '20', 'userId': self.user_id, 'sessionId': self.session_id}, timeout=30)
            data = resp.json()
            assert data.get('msg') != "未登录"
            datas = data.get('data', {}).get('datas', [])
            self.files_data = datas
            self.root.after(0, self.update_file_list)
            self.root.after(0, lambda: self.info_var.set(f"获取到 {len(datas)} 个文件"))
        except AssertionError:
            self.root.after(0, lambda: self.info_var.set("登录状态失效，正在重新登录..."))
            if not self.relogin():
                self.root.after(0, self.show_config_dialog)
        except:
            self.root.after(0, lambda: self.info_var.set(f"获取文件列表失败"))

    def update_file_list(self):
        for i, item in enumerate(self.file_items):
            if i < len(self.files_data):
                item['label'].configure(text=self.files_data[i].get('fileName', ''))
                item['frame'].pack(fill=X, pady=1)
            else:
                item['label'].configure(text='')
                item['frame'].pack_forget()

    def on_file_select(self, index):
        if not self.is_configured or index >= len(self.files_data):
            return
        for i, item in enumerate(self.file_items):
            if i == index:
                item['label'].configure(background="#007bff", foreground="white")
            else:
                item['label'].configure(background="", foreground="")
        self.selected_file_index = index
        file_info = self.files_data[index]
        _, ext = os.path.splitext(file_info.get('fileName', '').lower())
        if ext in self.text_extensions:
            threading.Thread(target=self.fetch_file_content, args=(file_info.get('id'),), daemon=True).start()
        else:
            self.set_text_content(f"文件名: {file_info.get('fileName')}\n大小: {self.format_size(file_info.get('size', 0))}\n时间: {file_info.get('ctime')}")

    def on_check_changed(self, index):
        if self.check_vars[index].get():
            self.checked_files.add(index)
        else:
            self.checked_files.discard(index)

    def fetch_file_content(self, file_id):
        try:
            resp = requests.get(f"{self.base_url}/downLoadCacheFile",
                params={'fileIds': file_id, 'userId': self.user_id, 'sessionId': self.session_id}, timeout=30)
            content = decode_response_content(resp.content)
            self.root.after(0, lambda: self.set_text_content(content))
        except Exception as e:
            self.root.after(0, lambda: self.set_text_content(f"获取失败: {e}"))

    def set_text_content(self, content):
        self.text_area.configure(state=NORMAL)
        self.text_area.delete(1.0, END)
        self.text_area.insert(1.0, content)
        self.text_area.configure(state=DISABLED)

    def format_size(self, size):
        try:
            size = int(size)
            if size < 1024:
                return f"{size} B"
            elif size < 1024**2:
                return f"{size/1024:.2f} KB"
            return f"{size/1024**2:.2f} MB"
        except:
            return str(size)

    def refresh_files(self):
        if self.is_configured:
            threading.Thread(target=self.fetch_files, daemon=True).start()

    def download_files(self):
        if not self.is_configured:
            messagebox.showwarning("警告", "请先配置！")
            return
        
        if self.checked_files:
            indices = self.checked_files.copy()
        elif self.selected_file_index is not None and self.selected_file_index < len(self.files_data):
            indices = {self.selected_file_index}
        else:
            messagebox.showwarning("警告", "请先选择要下载的文件！")
            return
        
        save_dir = filedialog.askdirectory(title="选择保存文件夹")
        if not save_dir:
            return
        
        files_to_download = [(idx, self.files_data[idx]) for idx in indices if idx < len(self.files_data)]
        
        for var in self.check_vars:
            var.set(False)
        self.checked_files.clear()
        
        DownloadManager(self.root, files_to_download, save_dir, self.user_id, self.session_id, self.base_url)

    def on_text_upload(self):
        text = self.upload_text_area.get(1.0, 'end-1c')
        
        if not text.strip():
            messagebox.showwarning("警告", "请先输入文本内容！")
            return
        
        if not self.is_configured:
            messagebox.showwarning("警告", "请先配置服务器信息！")
            return
        
        if self.upload_in_progress:
            messagebox.showwarning("警告", "正在上传中，请等待完成或取消当前上传！")
            return
        
        file_name = f"文本_{get_filename_suffix()}.txt"
        
        temp_path = os.path.join(tempfile.gettempdir(), file_name)
        
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            if not hasattr(self, 'temp_upload_files'):
                self.temp_upload_files = []
            self.temp_upload_files.append(temp_path)
            
            self.clear_upload_list()
            self.add_files_to_upload_list([temp_path])
            
        except Exception as e:
            messagebox.showerror("错误", f"创建临时文件失败：{e}")

    def on_qrcode_upload(self):
        text = self.upload_text_area.get(1.0, 'end-1c')
        
        if not text.strip():
            messagebox.showwarning("警告", "请先输入文本内容！")
            return
        
        text_bytes = text.encode('utf-8')
        
        chunk_size = 800
        chunks = []
        for i in range(0, len(text_bytes), chunk_size):
            chunks.append(text_bytes[i:i + chunk_size])
        
        qr_images = []
        max_display_size = 450  # 最大显示尺寸
        
        for idx, chunk in enumerate(chunks):
            try:
                qr = segno.make(chunk, error='H')
                buffer = BytesIO()
                qr.save(buffer, kind='png', scale=10)
                buffer.seek(0)
                img = Image.open(buffer)
                
                width, height = img.size
                if width > max_display_size or height > max_display_size:
                    ratio = min(max_display_size / width, max_display_size / height)
                    new_size = (int(width * ratio), int(height * ratio))
                    img = img.resize(new_size, Image.NEAREST)
                
                qr_images.append(img)
            except Exception as e:
                messagebox.showerror("错误", f"生成第 {idx + 1} 个二维码失败：{e}")
                return
        
        self.show_qrcode_window(qr_images, len(text_bytes))


    def show_qrcode_window(self, qr_images, total_bytes):
        window = ttk.Toplevel(self.root)
        window.title("二维码预览")
        window.geometry("550x650")
        window.resizable(False, False)
        window.transient(self.root)
        window.grab_set()
        
        window.update_idletasks()
        x = (window.winfo_screenwidth() - 550) // 2
        y = (window.winfo_screenheight() - 650) // 2
        window.geometry(f"+{x}+{y}")
        
        current_index = [0]
        total = len(qr_images)
        photo_refs = []
        
        main_frame = ttk.Frame(window, padding=15)
        main_frame.pack(fill=BOTH, expand=YES)
        
        info_label = ttk.Label(main_frame, 
            text=f"共 {total_bytes} 字节，分为 {total} 个二维码", 
            font=("Helvetica", 10), foreground="gray")
        info_label.pack(pady=(0, 5))
        
        page_var = ttk.StringVar(value=f"1 / {total}")
        page_label = ttk.Label(main_frame, textvariable=page_var, font=("Helvetica", 12, "bold"))
        page_label.pack(pady=(0, 10))
        
        qr_frame = ttk.Frame(main_frame, width=450, height=450)
        qr_frame.pack_propagate(False)
        qr_frame.pack(pady=5)
        
        qr_label = ttk.Label(qr_frame, anchor=CENTER)
        qr_label.pack(expand=YES)
        
        def show_qr(index):
            img = qr_images[index]
            photo = ImageTk.PhotoImage(img)
            photo_refs.clear()
            photo_refs.append(photo)
            qr_label.configure(image=photo)
            page_var.set(f"{index + 1} / {total}")
            
            if total > 1:
                prev_btn.configure(state=NORMAL if index > 0 else DISABLED)
                next_btn.configure(state=NORMAL if index < total - 1 else DISABLED)
        
        def prev_page():
            if current_index[0] > 0:
                current_index[0] -= 1
                show_qr(current_index[0])
        
        def next_page():
            if current_index[0] < total - 1:
                current_index[0] += 1
                show_qr(current_index[0])
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X, pady=(10, 0))
        
        if total > 1:
            nav_frame = ttk.Frame(btn_frame)
            nav_frame.pack(fill=X, pady=(0, 10))
            
            prev_btn = ttk.Button(nav_frame, text="◀ 上一页", command=prev_page, 
                bootstyle="info-outline", width=10)
            prev_btn.pack(side=LEFT, expand=YES)
            
            next_btn = ttk.Button(nav_frame, text="下一页 ▶", command=next_page,
                bootstyle="info-outline", width=10)
            next_btn.pack(side=RIGHT, expand=YES)
        
        close_btn = ttk.Button(btn_frame, text="关闭", command=window.destroy,
            bootstyle="secondary", width=10)
        close_btn.pack()
        
        def on_key(event):
            if event.keysym == 'Left':
                prev_page()
            elif event.keysym == 'Right':
                next_page()
            elif event.keysym == 'Escape':
                window.destroy()
        
        window.bind('<Key>', on_key)
        window.focus_set()
        
        show_qr(0)

    def on_closing(self):
        self.running = False
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = CloudFileManager()
    app.run()