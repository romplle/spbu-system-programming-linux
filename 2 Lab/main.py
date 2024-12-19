import os
import threading
import tkinter as tk
from tkinter import messagebox, Listbox, END
from scapy.all import sniff, IP, TCP

suspicious_ips = []
blocked_ips = []
captured_packets = []

MAX_PACKET_SIZE = 2048
SUSPICIOUS_PORTS = [21, 22, 23, 53, 80, 137, 139, 443, 445]

sniffing_active = False


def is_suspicious(packet):
    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
        if len(packet) > MAX_PACKET_SIZE or source_port in SUSPICIOUS_PORTS or dest_port in SUSPICIOUS_PORTS:
            return True
    return False


def packet_callback(packet):
    if is_suspicious(packet):
        ip_source = packet[IP].src
        if ip_source not in suspicious_ips:
            suspicious_ips.append(ip_source)
            update_suspicious_list()


def block_ip():
    try:
        selected_ip = suspicious_listbox.get(suspicious_listbox.curselection())
        if selected_ip not in blocked_ips:
            blocked_ips.append(selected_ip)
            command = f"sudo iptables -A INPUT -s {selected_ip} -j DROP"
            os.system(command)
            update_blocked_list()
            messagebox.showinfo("IP Blocked", f"IP {selected_ip} был успешно заблокирован.")
        else:
            messagebox.showwarning("Error", "IP has already been blocked.")
    except tk.TclError:
        messagebox.showwarning("Error", "The IP address is not selected for blocking.")


def unblock_ip():
    try:
        selected_ip = blocked_listbox.get(blocked_listbox.curselection())
        blocked_ips.remove(selected_ip)
        command = f"sudo iptables -D INPUT -s {selected_ip} -j DROP"
        os.system(command)
        update_blocked_list()
        messagebox.showinfo("IP Unblocked", f"IP {selected_ip} was successfully unblocked.")
    except tk.TclError:
        messagebox.showwarning("Error", "The IP for unblocking is not selected.")


def update_suspicious_list():
    suspicious_listbox.delete(0, END)
    for ip in suspicious_ips:
        suspicious_listbox.insert(END, ip)


def update_blocked_list():
    blocked_listbox.delete(0, END)
    for ip in blocked_ips:
        blocked_listbox.insert(END, ip)


def sniff_traffic():
    sniff(iface="enp0s3", prn=packet_callback, store=False, stop_filter=lambda x: not sniffing_active)


def toggle_sniffing():
    global sniffing_active
    if sniffing_active:
        sniffing_active = False
        start_sniff_button.config(text="Start Sniffing")
    else:
        sniffing_active = True
        start_sniff_button.config(text="Stop Sniffing")
        sniff_thread = threading.Thread(target=sniff_traffic)
        sniff_thread.daemon = True
        sniff_thread.start()


root = tk.Tk()
root.title("Traffic Monitor")

tk.Label(root, text="Suspicious IPs").grid(row=0, column=0, padx=5, pady=5)
suspicious_listbox = Listbox(root, width=40, height=15)
suspicious_listbox.grid(row=1, column=0, padx=5, pady=5)
block_button = tk.Button(root, text="Block", command=block_ip)
block_button.grid(row=2, column=0, pady=5)

tk.Label(root, text="Blocked IPs").grid(row=0, column=1, padx=5, pady=5)
blocked_listbox = Listbox(root, width=40, height=15)
blocked_listbox.grid(row=1, column=1, padx=5, pady=5)
unblock_button = tk.Button(root, text="Unblock", command=unblock_ip)
unblock_button.grid(row=2, column=1, pady=5)

start_sniff_button = tk.Button(root, text="Start Sniffing", command=toggle_sniffing)
start_sniff_button.grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()
