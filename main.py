import os
import sys
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import time
import platform
import ipaddress
import logging
import json
import pygame


class ASICMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ASICs monitoring")
        self.running = False  # Флаг для запуска/остановки мониторинга
        self.cyclic_beep = False  # Флаг для циклического сигнала
        self.subnets = []  # Список для хранения информации о подсетях
        self.config_file = self.get_path("asic_monitor_config.json")  # Путь к файлу конфигурации
        self.default_scan_file = self.get_path("default_scan.json")  # Путь к файлу с дефолтным сканированием
        self.current_scan_file = self.get_path("current_scan.json")  # Путь к файлу с текущим сканированием
        self.new_false_ips_file = self.get_path("new_false_ips.json")  # Путь к файлу с новыми false IP
        self.short_sound_file = self.get_path("short.mp3")  # Путь к файлу с коротким звуком
        self.long_sound_file = self.get_path("long.mp3")  # Путь к файлу с длинным звуком

        # Логирование всей информации из консоли в формате время и сообщение
        log_file_path = self.get_path("asic_checker.log")
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler()
        ])

        # Инициализация Pygame для воспроизведения звуков
        pygame.mixer.init()

        self.create_widgets()  # Создание виджетов интерфейса
        self.load_config()  # Загрузка основной конфигурации

    def get_path(self, filename):
        if getattr(sys, 'frozen', False):  # Проверка, скомпилировано ли приложение в exe
            application_path = os.path.dirname(sys.executable)
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(application_path, filename)

    # Создание виджетов интерфейса
    def create_widgets(self):
        self.add_subnet_frame = tk.Frame(self.root)
        self.add_subnet_frame.grid(row=0, column=0, columnspan=4, padx=10, pady=5)

        tk.Button(self.add_subnet_frame, text="добавить подсеть", command=self.add_subnet).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(self.add_subnet_frame, text="удалить подсеть", command=self.remove_subnet).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(self.add_subnet_frame, text="Сохранить дефолтный", command=self.save_default_scan).grid(row=0, column=2, padx=5, pady=5)

        self.canvas = tk.Canvas(self.root, width=480, height=300)
        self.canvas.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.scrollbar = tk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollbar.grid(row=1, column=3, sticky="ns")

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.subnets_frame = tk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.subnets_frame, anchor="nw")

        self.subnets_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.listbox_frame = tk.Frame(self.root)
        self.listbox_frame.grid(row=1, column=4, padx=10, pady=5)

        self.subnet_listbox = tk.Listbox(self.listbox_frame, selectmode=tk.SINGLE, height=20, width=26)
        self.subnet_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

        self.listbox_scrollbar = tk.Scrollbar(self.listbox_frame, orient="vertical")
        self.listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.subnet_listbox.configure(yscrollcommand=self.listbox_scrollbar.set)
        self.listbox_scrollbar.configure(command=self.subnet_listbox.yview)

        self.console = scrolledtext.ScrolledText(self.root, state='disabled', width=90, height=10)
        self.console.grid(row=6, column=0, columnspan=5, padx=10, pady=10)

        tk.Label(self.root, text="количество рабочих машин для короткого сигнала:").grid(row=2, column=0, padx=10, pady=5)
        self.expected_count1_entry = tk.Entry(self.root)
        self.expected_count1_entry.grid(row=2, column=1, padx=10, pady=5)

        tk.Label(self.root, text="критическое количество рабочих машин:").grid(row=3, column=0, padx=10, pady=5)
        self.expected_count2_entry = tk.Entry(self.root)
        self.expected_count2_entry.grid(row=3, column=1, padx=10, pady=5)

        tk.Label(self.root, text="раз во сколько секунд чекать:").grid(row=4, column=0, padx=10, pady=5)
        self.check_interval_entry = tk.Entry(self.root)
        self.check_interval_entry.grid(row=4, column=1, padx=10, pady=5)

        self.start_button = tk.Button(self.root, text="START", command=self.start_monitoring, width=20, height=2)
        self.start_button.grid(row=5, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(self.root, text="STOP", command=self.stop_monitoring, width=20, height=2)
        self.stop_button.grid(row=5, column=1, padx=10, pady=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # Добавление новой подсети
    def add_subnet(self, subnet=None, end_subnet=None, name=None):
        if len(self.subnets) >= 70:
            messagebox.showwarning("В бесплатной версии возможно добавить не более 70-ти подсетей!")
            return

        row = len(self.subnets)
        subnet_frame = tk.Frame(self.subnets_frame)
        subnet_frame.grid(row=row, column=0, columnspan=3, padx=0, pady=0)

        enable_var = tk.IntVar(value=1)
        enable_check = tk.Checkbutton(subnet_frame, variable=enable_var)
        enable_check.grid(row=0, column=0, padx=0, pady=0, sticky='w')

        name_label = tk.Label(subnet_frame, text="Имя:")
        name_label.grid(row=0, column=1, padx=0, pady=0)

        name_entry = tk.Entry(subnet_frame, width=14)
        name_entry.grid(row=0, column=2, padx=0, pady=0)

        name_label = tk.Label(subnet_frame, text="Начальный ip:")
        name_label.grid(row=0, column=3, padx=0, pady=0)

        start_entry = tk.Entry(subnet_frame, width=14)
        start_entry.grid(row=0, column=4, padx=0, pady=0)

        name_label = tk.Label(subnet_frame, text="Конечный ip:")
        name_label.grid(row=0, column=5, padx=0, pady=0)

        end_entry = tk.Entry(subnet_frame, width=14)
        end_entry.grid(row=0, column=6, padx=0, pady=0)

        if name:
            name_entry.insert(0, name)
        if subnet:
            start_entry.insert(0, subnet)
        if end_subnet:
            end_entry.insert(0, end_subnet)

        self.subnets.append((subnet_frame, name_entry, start_entry, end_entry, enable_var))
        self.update_subnet_listbox()

    # Обновление списка подсетей в интерфейсе
    def update_subnet_listbox(self):
        self.subnet_listbox.delete(0, tk.END)
        for _, name_entry, start_entry, end_entry, _ in self.subnets:
            name = name_entry.get()[:12]
            start_ip = start_entry.get()[:12]
            end_ip = end_entry.get()[:12]
            self.subnet_listbox.insert(tk.END, f"{name}: {start_ip} - {end_ip}")

    # Удаление выбранной подсети
    def remove_subnet(self):
        selected = self.subnet_listbox.curselection()
        if selected:
            index = selected[0]
            subnet_frame, name_entry, start_entry, end_entry, enable_var = self.subnets.pop(index)
            subnet_frame.destroy()
            self.update_subnet_listbox()

    # Начало мониторинга
    def start_monitoring(self):
        try:
            ip_ranges = []
            for _, name_entry, start_entry, end_entry, enable_var in self.subnets:
                if enable_var.get() == 0:
                    continue
                ip_start = start_entry.get()
                ip_end = end_entry.get()
                if not self.is_valid_ip(ip_start):
                    raise ValueError(f"Некорректно введен IP адрес: {ip_start}")
                if ip_end and not self.is_valid_ip(ip_end):
                    raise ValueError(f"Некорректно введен IP адрес: {ip_end}")
                self.log(f"IP start: {ip_start}")
                self.log(f"IP end: {ip_end}")
                if ip_end:
                    ip_range = self.generate_ip_range(ip_start, ip_end)
                else:
                    ip_network = ipaddress.ip_network(f"{ip_start}/24", strict=False)
                    ip_range = [str(ip) for ip in ip_network.hosts()]
                ip_ranges.append(ip_range)

            self.ip_ranges = ip_ranges
            self.log(f"IP ranges: {self.ip_ranges}")
            self.expected_count1 = int(self.expected_count1_entry.get())
            self.expected_count2 = int(self.expected_count2_entry.get())
            self.check_interval = int(self.check_interval_entry.get())
            self.log(f"Expected counts: {self.expected_count1}, {self.expected_count2}")
            self.log(f"Check interval: {self.check_interval}")

            self.running = True
            self.cyclic_beep = False
            self.monitor_thread = threading.Thread(target=self.monitor)
            self.monitor_thread.start()
        except ValueError as e:
            messagebox.showerror("ошибка ввода", str(e))
            self.log(f"Ошибка ввода: {e}")

    # Генерация диапазона IP-адресов
    def generate_ip_range(self, start_ip, end_ip):
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        if start > end:
            raise ValueError("Начальный IP должен быть меньше конечного IP")
        return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]

    # Остановка мониторинга
    def stop_monitoring(self):
        self.running = False
        self.cyclic_beep = False
        self.log("Остановка мониторинга...")
        self.log("Мониторинг остановлен.")

    # Пинг IP-адреса
    def ping_ip(self, ip):
        try:
            response = os.system(f"ping -n 1 -w 1000 {ip}") == 0
            self.log(f"Пинг {ip}: {'успешно' if response else 'неудачно'}")
            return response
        except Exception as e:
            self.log(f"Ошибка пингования {ip}: {e}")
            return False

    # Сканирование подсети
    def scan_subnet(self, ip_range):
        active_ips = []
        for ip in ip_range:
            if not self.running:
                break
            result = self.ping_ip(ip)
            self.log(f"{ip} - {result}")
            if result:
                active_ips.append(ip)
            time.sleep(0.05)  # Пауза для предотвращения перегрузки
        return active_ips

    # Мониторинг подсетей
    def monitor(self):
        try:
            while self.running:
                self.log("Сканирование началось...")
                start_time = time.time()

                threads = []
                results = []
                for ip_range in self.ip_ranges:
                    thread = threading.Thread(target=lambda q, arg1: q.append(self.scan_subnet(arg1)), args=(results, ip_range))
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()

                active_ips = [ip for sublist in results for ip in sublist]

                end_time = time.time()
                scan_duration = end_time - start_time
                asic_count = len(active_ips)
                self.log(f"найдено {asic_count} активных ASICs")
                self.log(f"Время сканирования: {scan_duration:.2f} секунд")

                self.save_scan_results(active_ips)
                self.check_for_new_false_ips()

                if asic_count < self.expected_count2:
                    self.log("длинный beep")
                    self.cyclic_beep = True
                    threading.Thread(target=self.play_cyclic_beep).start()
                elif asic_count < self.expected_count1:
                    self.log("короткий beep")
                    self.play_sound(self.short_sound_file)

                time.sleep(self.check_interval)
        except Exception as e:
            self.log(f"Ошибка в мониторинге: {e}")
        finally:
            self.log("Мониторинг завершен.")

    # Воспроизведение цикличного сигнала
    def play_cyclic_beep(self):
        while self.cyclic_beep and self.running:
            self.play_sound(self.long_sound_file)
            time.sleep(0.5)

    # Воспроизведение сигнала
    def play_sound(self, sound_file):
        self.log(f"Playing sound: {sound_file}")
        try:
            pygame.mixer.music.load(sound_file)
            pygame.mixer.music.play()
        except Exception as e:
            self.log(f"Ошибка воспроизведения звука: {e}")

    # Логирование сообщений
    def log(self, message):
        self.console.config(state='normal')
        self.console.insert(tk.END, message + '\n')
        self.console.config(state='disabled')
        self.console.yview(tk.END)
        logging.info(message)

    # Проверка валидности IP-адреса
    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    # Сохранение конфигурации
    def save_config(self):
        config = {
            "subnets": [(name_entry.get(), start_entry.get(), end_entry.get(), enable_var.get()) for _, name_entry, start_entry, end_entry, enable_var in self.subnets],
            "expected_count1": self.expected_count1_entry.get(),
            "expected_count2": self.expected_count2_entry.get(),
            "check_interval": self.check_interval_entry.get()
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
        self.log("Конфигурация сохранена.")

    # Загрузка конфигурации
    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                for name, start_subnet, end_subnet, enabled in config["subnets"]:
                    self.add_subnet(start_subnet, end_subnet, name)
                    self.subnets[-1][4].set(enabled)  # Устанавливаем значение enable_var из сохраненного состояния
                self.expected_count1_entry.insert(0, config["expected_count1"])
                self.expected_count2_entry.insert(0, config["expected_count2"])
                self.check_interval_entry.insert(0, config["check_interval"])
            self.log("Конфигурация загружена.")

    # Сохранение текущего сканирования как дефолтного
    def save_default_scan(self):
        try:
            if os.path.exists(self.default_scan_file):
                os.remove(self.default_scan_file)
            os.rename(self.current_scan_file, self.default_scan_file)
            self.log("Сканирование сохранено как дефолтное.")
        except Exception as e:
            self.log(f"Ошибка при сохранении дефолтного сканирования: {e}")

    # Сохранение результатов текущего сканирования
    def save_scan_results(self, active_ips):
        with open(self.current_scan_file, 'w') as f:
            json.dump(active_ips, f)
        self.log("Результаты текущего сканирования сохранены.")

    # Проверка на наличие новых false IP
    def check_for_new_false_ips(self):
        if not os.path.exists(self.default_scan_file):
            self.log("Файл дефолтного сканирования не найден.")
            return

        with open(self.current_scan_file, 'r') as f:
            current_scan = set(json.load(f))

        with open(self.default_scan_file, 'r') as f:
            default_scan = set(json.load(f))

        new_false_ips = default_scan - current_scan

        if new_false_ips:
            self.log("Обнаружены новые false IP адреса.")
            with open(self.new_false_ips_file, 'w') as f:
                json.dump(list(new_false_ips), f)
            self.play_sound(self.short_sound_file)
            threading.Thread(target=self.show_warning, args=("Новые false IP", "Обнаружены новые false IP адреса!")).start()
        else:
            self.log("Новых false IP адресов не обнаружено.")
            if os.path.exists(self.new_false_ips_file):
                os.remove(self.new_false_ips_file)

    # Показ предупреждающего окна
    def show_warning(self, title, message):
        messagebox.showwarning(title, message)

    # Обработка закрытия окна
    def on_closing(self):
        self.save_config()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ASICMonitorApp(root)
    root.mainloop()
