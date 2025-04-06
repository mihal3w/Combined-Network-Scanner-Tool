import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import subprocess
import os
import signal
import ipaddress

# Глобална променлива за процеса
process = None

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Комбиниран мрежов скенер")
        self.setup_ui()
        
    def setup_ui(self):
        # Създаване на разделителни табове
        self.tab_control = ttk.Notebook(self.root)
        
        # Създаване на табове
        self.tab_external = ttk.Frame(self.tab_control)
        self.tab_internal = ttk.Frame(self.tab_control)
        
        # Добавяне на табовете към контрола
        self.tab_control.add(self.tab_external, text="Външно сканиране")
        self.tab_control.add(self.tab_internal, text="Вътрешно сканиране")
        self.tab_control.pack(expand=1, fill="both")
        
        # Инициализация на UI за външно сканиране
        self.setup_external_scan_ui()
        
        # Инициализация на UI за вътрешно сканиране
        self.setup_internal_scan_ui()
    
    def setup_external_scan_ui(self):
        # Поле за въвеждане на целеви домейн/IP
        label_target = tk.Label(self.tab_external, text="Целеви домейн/IP:")
        label_target.grid(row=0, column=0, padx=10, pady=10)
        self.entry_external_target = tk.Entry(self.tab_external, width=40)
        self.entry_external_target.grid(row=0, column=1, padx=10, pady=10)

        # Бутон за стартиране на сканирането
        button_scan = tk.Button(self.tab_external, text="Стартирай сканирането", command=self.start_external_scan)
        button_scan.grid(row=1, column=0, padx=10, pady=10)

        # Бутон за спиране на сканирането
        self.button_stop_external = tk.Button(self.tab_external, text="Стоп", command=self.stop_scan, state=tk.DISABLED)
        self.button_stop_external.grid(row=1, column=1, padx=10, pady=10)

        # Поле за изходен текст
        self.output_text_external = scrolledtext.ScrolledText(self.tab_external, width=80, height=20)
        self.output_text_external.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        
        # Лейбъл с инструкции
        instructions_label = tk.Label(
            self.tab_external,
            text="Въведете целеви домейн или IP адрес (например example.com или 192.168.1.1)",
            fg="gray"
        )
        instructions_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10)
    
    def setup_internal_scan_ui(self):
        # Поле за въвеждане на целеви IP/диапазон
        label_target = tk.Label(self.tab_internal, text="Целеви IP/диапазон:")
        label_target.grid(row=0, column=0, padx=10, pady=10)
        self.entry_internal_target = tk.Entry(self.tab_internal, width=40)
        self.entry_internal_target.grid(row=0, column=1, padx=10, pady=10)

        # Бутон за стартиране на сканирането
        button_scan = tk.Button(self.tab_internal, text="Стартирай сканирането", command=self.start_internal_scan)
        button_scan.grid(row=1, column=0, padx=10, pady=10)

        # Бутон за спиране на сканирането
        self.button_stop_internal = tk.Button(self.tab_internal, text="Стоп", command=self.stop_scan, state=tk.DISABLED)
        self.button_stop_internal.grid(row=1, column=1, padx=10, pady=10)

        # Поле за изходен текст
        self.output_text_internal = scrolledtext.ScrolledText(self.tab_internal, width=80, height=20)
        self.output_text_internal.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        
        # Лейбъл с инструкции
        instructions_label = tk.Label(
            self.tab_internal,
            text="Въведете целеви IP адрес или мрежа (например 192.168.1.0/24) в полето за въвеждане.",
            fg="gray"
        )
        instructions_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10)
    
    def write_to_file(self, filename, content):
        with open(filename, "w") as file:
            file.write(content)
    
    # Външно сканиране функции
    def nmap_scan(self, target, output_dir):
        self.output_text_external.insert(tk.END, f"[*] Стартиране на Nmap сканиране на {target}...\n")
        command = f"nmap --top-ports 150 -T5 {target}"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_external.insert(tk.END, output)
                output_content += output
                self.output_text_external.see(tk.END)
                self.root.update()
        self.output_text_external.insert(tk.END, "[+] Nmap сканирането приключи.\n")
        self.write_to_file(f"{output_dir}/nmap_scan.txt", output_content)
    
    def nuclei_scan(self, target, output_dir):
        self.output_text_external.insert(tk.END, f"[*] Стартиране на Nuclei сканиране на {target}...\n")
        command = f"nuclei -u {target} -o {output_dir}/nuclei_scan.txt"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_external.insert(tk.END, output)
                output_content += output
                self.output_text_external.see(tk.END)
                self.root.update()
        self.output_text_external.insert(tk.END, "[+] Nuclei сканирането приключи.\n")
        self.write_to_file(f"{output_dir}/nuclei_scan.txt", output_content)
    
    def nikto_scan(self, target, output_dir):
        self.output_text_external.insert(tk.END, f"[*] Стартиране на Nikto сканиране на {target}...\n")
        command = f"nikto -h {target} -output {output_dir}/nikto_scan.txt"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_external.insert(tk.END, output)
                output_content += output
                self.output_text_external.see(tk.END)
                self.root.update()
        self.output_text_external.insert(tk.END, "[+] Nikto сканирането приключи.\n")
        self.write_to_file(f"{output_dir}/nikto_scan.txt", output_content)
    
    def amass_scan(self, target, output_dir):
        self.output_text_external.insert(tk.END, f"[*] Стартиране на Amass сканиране на {target}...\n")
        command = f"amass enum -d {target} -o {output_dir}/amass_scan.txt"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_external.insert(tk.END, output)
                output_content += output
                self.output_text_external.see(tk.END)
                self.root.update()
        self.output_text_external.insert(tk.END, "[+] Amass сканирането приключи.\n")
        self.write_to_file(f"{output_dir}/amass_scan.txt", output_content)
    
    def start_external_scan(self):
        global process
        target = self.entry_external_target.get()

        if not target:
            messagebox.showerror("Грешка", "Моля, въведете целеви домейн/IP!")
            return

        try:
            # Създаване на директория за резултати
            output_dir = "external_scan_results"
            os.makedirs(output_dir, exist_ok=True)

            # Сканиране на портове с Nmap
            self.nmap_scan(target, output_dir)

            # Сканиране на уеб уязвимости с Nuclei
            self.nuclei_scan(target, output_dir)

            # Сканиране на уеб сървъри с Nikto
            self.nikto_scan(target, output_dir)

            # Откриване на поддомейни с Amass
            self.amass_scan(target, output_dir)

            messagebox.showinfo("Готово", "Сканирането за външни мрежи приключи!")

        except Exception as e:
            messagebox.showerror("Грешка", f"Възникна грешка: {str(e)}")
    
    # Вътрешно сканиране функции
    def nmap_internal_scan(self, target, output_dir):
        self.output_text_internal.insert(tk.END, f"[*] Стартиране на Nmap сканиране на {target}...\n")
        command = f"nmap -sn {target}"  # Използваме -sn за ping сканиране (откриване на активни хостове)
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        active_ips = []

        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_internal.insert(tk.END, output)
                output_content += output
                self.output_text_internal.see(tk.END)
                self.root.update()

                # Проверка за активни IP адреси в изхода на Nmap
                if "Nmap scan report for" in output:
                    ip = output.split()[-1]  # Взимаме последния елемент, който е IP адресът
                    active_ips.append(ip)

        self.output_text_internal.insert(tk.END, "[+] Nmap сканирането приключи.\n")
        self.write_to_file(f"{output_dir}/nmap_scan.txt", output_content)
        return active_ips
    
    def smbmap_scan(self, target, output_dir):
        self.output_text_internal.insert(tk.END, f"[*] Стартиране на SMBmap сканиране на {target}...\n")
        command = f"smbmap -H {target}"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_internal.insert(tk.END, output)
                output_content += output
                self.output_text_internal.see(tk.END)
                self.root.update()
        self.output_text_internal.insert(tk.END, "[+] SMBmap сканирането приключи.\n")
        self.write_to_file(f"{output_dir}/smbmap_scan_{target}.txt", output_content)
    
    def enum4linux_scan(self, target, output_dir):
        self.output_text_internal.insert(tk.END, f"[*] Стартиране на Enum4linux сканиране на {target}...\n")
        command = f"enum4linux {target}"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_internal.insert(tk.END, output)
                output_content += output
                self.output_text_internal.see(tk.END)
                self.root.update()
        self.output_text_internal.insert(tk.END, "[+] Enum4linux сканирането приключи.\n")
        self.write_to_file(f"{output_dir}/enum4linux_scan_{target}.txt", output_content)
    
    def sniper_scan(self, target, output_dir):
        self.output_text_internal.insert(tk.END, f"[*] Стартиране на Sniper сканиране на {target}...\n")
        command = f"sniper -t {target} -o {output_dir}/sniper_scan_{target}.txt"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_internal.insert(tk.END, output)
                output_content += output
                self.output_text_internal.see(tk.END)
                self.root.update()
        self.output_text_internal.insert(tk.END, "[+] Sniper сканирането приключи.\n")
    
    def crackmapexec_scan(self, target, output_dir):
        self.output_text_internal.insert(tk.END, f"[*] Стартиране на CrackMapExec сканиране на {target}...\n")
        command = f"crackmapexec smb {target} > {output_dir}/crackmapexec_scan_{target}.txt"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_internal.insert(tk.END, output)
                output_content += output
                self.output_text_internal.see(tk.END)
                self.root.update()
        self.output_text_internal.insert(tk.END, "[+] CrackMapExec сканирането приключи.\n")
    
    def sparta_scan(self, target, output_dir):
        self.output_text_internal.insert(tk.END, f"[*] Стартиране на Sparta сканиране на {target}...\n")
        command = f"sparta -i {target} -o {output_dir}/sparta_scan_{target}"
        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_content = ""
        while True:
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_text_internal.insert(tk.END, output)
                output_content += output
                self.output_text_internal.see(tk.END)
                self.root.update()
        self.output_text_internal.insert(tk.END, "[+] Sparta сканирането приключи.\n")
    
    def start_internal_scan(self):
        global process
        target = self.entry_internal_target.get()

        if not target:
            messagebox.showerror("Грешка", "Моля, въведете целеви IP/диапазон!")
            return

        try:
            # Създаване на директория за резултати
            output_dir = "internal_scan_results"
            os.makedirs(output_dir, exist_ok=True)

            # Сканиране на целевия IP с Nmap и получаване на активни IP адреси
            active_ips = self.nmap_internal_scan(target, output_dir)

            if not active_ips:
                self.output_text_internal.insert(tk.END, "[!] Няма открити активни IP адреси.\n")
                return

            # Сканиране на всеки активен IP с всички инструменти
            for ip in active_ips:
                self.output_text_internal.insert(tk.END, f"[*] Обработка на активен IP: {ip}\n")
                self.smbmap_scan(ip, output_dir)
                self.enum4linux_scan(ip, output_dir)
                self.sniper_scan(ip, output_dir)
                self.crackmapexec_scan(ip, output_dir)
                self.sparta_scan(ip, output_dir)

            messagebox.showinfo("Готово", "Сканирането за вътрешни мрежи приключи!")

        except Exception as e:
            messagebox.showerror("Грешка", f"Възникна грешка: {str(e)}")
    
    def stop_scan(self):
        global process
        if self.process:
            try:
                # Прекратяване на процеса
                os.kill(self.process.pid, signal.SIGTERM)
                self.process = None
                messagebox.showinfo("Стоп", "Сканирането е спряно!")
            except Exception as e:
                messagebox.showerror("Грешка", f"Грешка при спиране на процеса: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScanner(root)
    root.mainloop()
