import tkinter as tk
from tkinter import ttk, messagebox
import json
import subprocess
import threading
import os
import signal

class ServerControlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Server Control Panel")
        self.server_process = None
        self.log_thread = None
        self.stop_log_thread = False

        self.create_widgets()

        # Bind the window close event to the on_closing method
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        # Server Control Frame
        control_frame = ttk.LabelFrame(self.root, text="Server Control")
        control_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.start_button = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)

        # Log Frame
        log_frame = ttk.LabelFrame(self.root, text="Server Logs")
        log_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.log_text = tk.Text(log_frame, height=20, width=80, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, padx=5, pady=5)

        # Settings Frame
        settings_frame = ttk.LabelFrame(self.root, text="Settings")
        settings_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        ttk.Label(settings_frame, text="Port:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.port_entry = ttk.Entry(settings_frame)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(settings_frame, text="Entry Point:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.entry_point_entry = ttk.Entry(settings_frame)
        self.entry_point_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(settings_frame, text="Rate Limit:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.rate_limit_entry = ttk.Entry(settings_frame)
        self.rate_limit_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        self.save_button = ttk.Button(settings_frame, text="Save Settings", command=self.save_settings)
        self.save_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.load_settings()

    def load_settings(self):
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
            self.port_entry.insert(0, config.get('port', ''))
            self.entry_point_entry.insert(0, config.get('entry_point', ''))
            self.rate_limit_entry.insert(0, config.get('rate_limit', ''))
        except FileNotFoundError:
            messagebox.showerror("Error", "Configuration file not found.")
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Error decoding JSON from configuration file.")

    def save_settings(self):
        config = {
            "port": int(self.port_entry.get()),
            "entry_point": self.entry_point_entry.get(),
            "rate_limit": int(self.rate_limit_entry.get()),
            # Add other settings as needed
        }
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=4)
        messagebox.showinfo("Info", "Settings saved successfully.")

    def start_server(self):
        if self.server_process is None:
            self.server_process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.stop_log_thread = False
            self.log_thread = threading.Thread(target=self.update_logs)
            self.log_thread.start()

    def stop_server(self):
        if self.server_process is not None:
            os.kill(self.server_process.pid, signal.SIGINT)
            self.server_process = None
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.stop_log_thread = True
            if self.log_thread is not None:
                self.log_thread.join()

    def update_logs(self):
        while not self.stop_log_thread:
            if self.server_process is not None:
                output = self.server_process.stdout.readline()
                if output:
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, output)
                    self.log_text.config(state=tk.DISABLED)
                    self.log_text.yview(tk.END)

    def on_closing(self):
        self.stop_server()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerControlApp(root)
    root.mainloop()
