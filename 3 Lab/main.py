import logging
import time
import threading
import datetime

import psutil
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

from my_token import sender_email, password, receiver_email

logging.basicConfig(filename="3 Lab/system_audit.log", level=logging.INFO, format="%(asctime)s - %(message)s")

process_dict = {}
process_statistics = []
current_canvas = None


def monitor_system():
    while True:
        current_processes = {}
        status_counts = {}

        for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
            try:
                current_processes[proc.info['pid']] = (proc.info['name'], proc.info['username'], proc.info['status'])
                status = proc.info['status']
                status_counts[status] = status_counts.get(status, 0) + 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        for pid in current_processes:
            process_name, username, status = current_processes[pid]
            process_dict[pid] = current_processes[pid]
            log_event(pid=pid, name=process_name, username=username, status=status)

        else:
            process_dict.update(current_processes)

        process_statistics.append({
            "timestamp": datetime.datetime.now(),
            "total": len(current_processes),
            **status_counts
        })

        time.sleep(10)
        notify_event("System Update")
        send_log_email()


def notify_event(message):
    messagebox.showinfo("Event Notification", message)


def log_event(pid=None, name=None, username=None, status=None, message=None):
    if pid is not None and name is not None and username is not None and status is not None:
        log_message = f"Name: {name}, PID: {pid}, User: {username}, Status: {status}"
        logging.info(log_message)


def update_process_list():
    process_listbox.delete(0, tk.END)
    for pid, (name, username, status) in process_dict.items():
        process_listbox.insert(tk.END, f"{name} (PID: {pid}, User: {username}, Status: {status})")
    process_listbox.yview(tk.END)


def show_report():
    global current_canvas
    if not process_statistics:
        messagebox.showinfo("No Data", "No process statistics available.")
        return

    if current_canvas:
        current_canvas.get_tk_widget().destroy()

    for widget in status_frame.winfo_children():
        widget.destroy()

    timestamps = [stat["timestamp"].strftime("%Y-%m-%d %H:%M:%S") for stat in process_statistics]
    total_counts = [stat["total"] for stat in process_statistics]
    all_statuses = {key for stat in process_statistics for key in stat.keys() if key not in ("timestamp", "total")}

    fig, ax = plt.subplots(figsize=(8, 5))

    ax.plot(timestamps, total_counts, label="Total Processes", color="blue")

    for status in all_statuses:
        counts = [stat.get(status, 0) for stat in process_statistics]
        ax.plot(timestamps, counts, label=status.capitalize())

    ax.set_xlabel("Time")
    ax.set_ylabel("Process Count")
    ax.set_title("Process Statistics Over Time")
    ax.legend()
    ax.grid(True)

    current_canvas = FigureCanvasTkAgg(fig, master=report_frame)
    current_canvas.get_tk_widget().pack(side=tk.TOP, fill="both", expand=True)
    current_canvas.draw()

    last_stat = process_statistics[-1]
    for status, count in last_stat.items():
        if status == "timestamp":
            continue
        status_label = tk.Label(status_frame, text=f"{status.capitalize()}: {count}", font=("Arial", 10))
        status_label.pack(anchor="w")


def search_logs():
    criteria_name = name_filter.get().strip()
    criteria_user = user_filter.get().strip()
    criteria_status = status_filter.get().strip()

    with open("3 Lab/system_audit.log", "r") as log_file:
        logs = log_file.readlines()

    filtered_logs = []
    for log in logs:
        if (criteria_name in log or not criteria_name) and \
           (criteria_user in log or not criteria_user) and \
           (criteria_status in log or not criteria_status):
            filtered_logs.append(log)

    results_listbox.delete(0, tk.END)
    if filtered_logs:
        for entry in filtered_logs:
            results_listbox.insert(tk.END, entry.strip())
        notify_event(f"Found {len(filtered_logs)} matching log entries.")
    else:
        results_listbox.insert(tk.END, "No matching logs found.")
        notify_event("No matching logs found.")


def send_log_email():
    subject = "System Audit Logs"

    log_file_path = "3 Lab/system_audit.log"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    with open(log_file_path, "rb") as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename=system_audit.log')
        msg.attach(part)

    try:
        with smtplib.SMTP('smtp.yandex.ru', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            text = msg.as_string()
            server.sendmail(sender_email, receiver_email, text)
            messagebox.showinfo("Success", "Log file has been sent successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {e}")


root = tk.Tk()
root.title("System Audit Tool")

tab_control = ttk.Notebook(root)
tab_process_tab = ttk.Frame(tab_control)
tab_report_tab = ttk.Frame(tab_control)
tab_search_tab = ttk.Frame(tab_control)

tab_control.add(tab_process_tab, text="Process Monitoring")
tab_control.add(tab_report_tab, text="Generate Report")
tab_control.add(tab_search_tab, text="Search Logs")

tab_control.pack(expand=1, fill="both")

process_frame = tk.Frame(tab_process_tab)
process_frame.pack(fill="both", expand=True)

process_listbox = tk.Listbox(process_frame, height=30, width=100)
process_listbox.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

update_button = tk.Button(process_frame, text="Update Process List", command=update_process_list)
update_button.pack(pady=5)

report_frame = tk.Frame(tab_report_tab)
report_frame.pack(fill="both", expand=True)

controls_frame = tk.Frame(report_frame)
controls_frame.pack(side=tk.TOP, fill="x", anchor="n", pady=10)

report_button = tk.Button(controls_frame, text="Show Report", command=show_report)
report_button.pack(pady=5)

status_frame = tk.Frame(controls_frame)
status_frame.pack(fill="x", anchor="n", pady=5)

search_frame = tk.Frame(tab_search_tab)
search_frame.pack(fill="both", expand=True, padx=10, pady=10)

tk.Label(search_frame, text="Filter by Name:").grid(row=0, column=0, sticky="w")
name_filter = tk.Entry(search_frame, width=20)
name_filter.grid(row=0, column=1, sticky="w", padx=5)

tk.Label(search_frame, text="Filter by User:").grid(row=1, column=0, sticky="w")
user_filter = tk.Entry(search_frame, width=20)
user_filter.grid(row=1, column=1, sticky="w", padx=5)

tk.Label(search_frame, text="Filter by Status:").grid(row=2, column=0, sticky="w")
status_filter = tk.Entry(search_frame, width=20)
status_filter.grid(row=2, column=1, sticky="w", padx=5)

search_button = tk.Button(search_frame, text="Search Logs", command=search_logs)
search_button.grid(row=3, column=0, columnspan=2, pady=10)

results_listbox = tk.Listbox(search_frame, height=30, width=100)
results_listbox.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=10)

monitor_thread = threading.Thread(target=monitor_system, daemon=True)
monitor_thread.start()

root.mainloop()
