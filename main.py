import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import socket
import whois
import requests
import threading

class OSINTTool:
    def __init__(self, root):
        self.root = root
        self.root.title("ScanSentry OSINT Tool")
        self.root.geometry("650x550")
        self.root.configure(bg="#121212") # Thoda aur dark background

        # --- UI Design ---
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Heading
        self.label = tk.Label(root, text="OSINT INVESTIGATOR", fg="#00ff00", bg="#121212", font=("Courier", 20, "bold"))
        self.label.pack(pady=15)

        # Input Frame
        self.input_frame = tk.Frame(root, bg="#121212")
        self.input_frame.pack(pady=5)
        
        tk.Label(self.input_frame, text="Target Domain:", fg="#ffffff", bg="#121212", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        self.target_entry = tk.Entry(self.input_frame, width=35, font=("Consolas", 12), bg="#1e1e1e", fg="white", insertbackground="white")
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "google.com")

        # Scan Button
        self.scan_btn = tk.Button(root, text="START SCAN", command=self.start_scan_thread, bg="#0078d7", fg="white", font=("Arial", 10, "bold"), width=20, activebackground="#005a9e")
        self.scan_btn.pack(pady=15)

        # Progress Bar
        self.progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=550, mode='determinate')
        self.progress.pack(pady=5)

        # Output Area
        self.output_area = scrolledtext.ScrolledText(root, width=75, height=18, bg="#000000", fg="#00ff00", font=("Consolas", 10), padx=10, pady=10)
        self.output_area.pack(pady=10, padx=10)

    def update_output(self, text):
        """Output area mein text add karne ke liye"""
        self.output_area.insert(tk.END, text + "\n")
        self.output_area.see(tk.END)

    def start_scan_thread(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Bhai, domain name toh enter karo!")
            return
        
        # UI Reset
        self.output_area.delete('1.0', tk.END)
        self.progress['value'] = 0
        self.scan_btn.config(state=tk.DISABLED)
        
        # Threading start
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()

    def run_scan(self, target):
        try:
            self.update_output(f"[*] Starting Investigation on: {target}")
            self.update_output("-" * 50)
            
            # --- 1. DNS Lookup ---
            self.update_output("[+] Fetching DNS Info...")
            ip = socket.gethostbyname(target)
            self.update_output(f"    IP Address: {ip}")
            self.progress['value'] = 30

            # --- 2. Geo Location ---
            self.update_output("[+] Fetching Geo-Location...")
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if response['status'] == 'success':
                    self.update_output(f"    Location: {response.get('city')}, {response.get('country')}")
                    self.update_output(f"    ISP: {response.get('isp')}")
                else:
                    self.update_output("    [!] Geo-Location data not found.")
            except:
                self.update_output("    [!] Geo-Location service unreachable.")
            self.progress['value'] = 60

            # --- 3. WHOIS Lookup ---
            self.update_output("[+] Fetching WHOIS Records...")
            try:
                # Yahan ab error nahi aana chahiye
                w = whois.whois(target)
                self.update_output(f"    Registrar: {w.registrar}")
                self.update_output(f"    Creation Date: {w.creation_date}")
                self.update_output(f"    Expiration: {w.expiration_date}")
            except Exception as e:
                self.update_output(f"    [!] WHOIS Error: {str(e)}")
            
            self.progress['value'] = 100
            self.update_output("-" * 50)
            self.update_output("[!] Scan Completed Successfully.")

        except socket.gaierror:
            self.update_output("\n[!] Error: Invalid Domain ya No Internet Connection.")
        except Exception as e:
            self.update_output(f"\n[!] Unexpected Error: {str(e)}")
        
        self.scan_btn.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = OSINTTool(root)
    root.mainloop()