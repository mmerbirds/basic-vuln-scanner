import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import subprocess

def run_scan(target, output_text):
    try:
        output_text.insert(tk.END, f"[*] Starting scan on target: {target}\n")
        cmd = ["python3", "scanner.py", target]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            output_text.insert(tk.END, line)
            output_text.see(tk.END)
        process.wait()
        output_text.insert(tk.END, "[+] Scan finished.\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def start_scan():
    target = entry_target.get().strip()
    if not target:
        messagebox.showwarning("Input Error", "Please enter a target domain or IP.")
        return
    output_text.delete(1.0, tk.END)
    threading.Thread(target=run_scan, args=(target, output_text), daemon=True).start()

app = tk.Tk()
app.title("Basic Vulnerability Scanner GUI")
app.geometry("700x500")

frame = ttk.Frame(app, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

label = ttk.Label(frame, text="Enter Target Domain or IP:")
label.pack(anchor=tk.W)

entry_target = ttk.Entry(frame, width=50)
entry_target.pack(fill=tk.X, pady=5)

btn_scan = ttk.Button(frame, text="Start Scan", command=start_scan)
btn_scan.pack(pady=5)

output_text = scrolledtext.ScrolledText(frame, height=20)
output_text.pack(fill=tk.BOTH, expand=True)

app.mainloop()