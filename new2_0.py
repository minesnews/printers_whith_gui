# language: python
# -*- coding: utf-8 -*-

"""
Профессиональная утилита для поиска и идентификации принтеров в локальной сети с GUI.

Версия 4.5.1: Финальная версия с исправлением исключения localhost.

Возможности:
- Сканирование диапазона подсетей (например, ввод '20-23' просканирует подсети 20, 21, 22, 23).
- Экспорт отчета в .xlsx файл, где каждая подсеть находится на своем листе.
- В отчет не включаются устройства, для которых не удалось получить детальную информацию.
- Исключение адреса 127.0.0.1 из результатов.
- Требуемые зависимости: PyQt6, zeroconf, pysnmp, pandas, openpyxl.
"""

import sys
import socket
import ipaddress
import threading
import time
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor

try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                                 QTableWidget, QTableWidgetItem, QPushButton, QStatusBar,
                                 QHeaderView, QMessageBox, QLabel, QLineEdit, QFileDialog)
    from PyQt6.QtCore import QObject, QThread, pyqtSignal, Qt
    PYQT6_AVAILABLE = True
except ImportError: PYQT6_AVAILABLE = False
try:
    from zeroconf import ServiceBrowser, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError: ZEROCONF_AVAILABLE = False
try:
    from pysnmp.hlapi.asyncio import *
    PYSNMP_AVAILABLE = True
except ImportError: PYSNMP_AVAILABLE = False
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError: PANDAS_AVAILABLE = False

# --- Константы ---
PRINTER_PORTS = [9100, 631, 515]
SCAN_TIMEOUT = 0.5
MDNS_SCAN_DURATION = 8
MAX_SCAN_WORKERS = 100
SNMP_TIMEOUT = 1
SNMP_RETRIES = 0
SNMP_COMMUNITY = 'public'
OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0'
OID_SERIAL_NUMBER = '1.3.6.1.2.1.43.5.1.1.17.1'
OID_DEVICE_STATUS = '1.3.6.1.2.1.25.3.2.1.5.1'
OID_PAGE_COUNT = '1.3.6.1.2.1.43.10.2.1.4.1.1'
HR_DEVICE_STATUS = {1: 'Unknown', 2: 'Running', 3: 'Warning', 4: 'Testing', 5: 'Down'}

class WorkerSignals(QObject):
    """Сигналы, передаваемые из рабочего потока в основной."""
    status_update = pyqtSignal(str)
    details_updated = pyqtSignal(str, dict)
    discovery_finished = pyqtSignal(dict)
    snmp_finished = pyqtSignal()

class ScannerWorker(QObject):
    """Класс-работник, выполняющий все сетевые операции в отдельном потоке."""
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        self.found_devices = {}

    def _get_local_ip(self):
        """Определяет локальный IP-адрес для автоопределения подсети."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except socket.error:
            return "127.0.0.1"

    def _find_printers_by_port_scan(self, target_subnets):
        """Сканирует порты в указанных подсетях."""
        if not target_subnets:
            self.signals.status_update.emit("Автоопределение и сканирование локальной подсети...")
            try:
                local_ip = self._get_local_ip()
                if local_ip.startswith('127.'):
                    self.signals.status_update.emit("Ошибка: не удалось определить IP. Автосканирование невозможно.")
                    return
                target_subnets = [f'{local_ip}/24']
            except Exception as auto_e:
                self.signals.status_update.emit(f"Ошибка автоопределения сети: {auto_e}")
                return
        
        for subnet_cidr in target_subnets:
            try:
                self.signals.status_update.emit(f"Сканирование подсети: {subnet_cidr}...")
                network = ipaddress.ip_network(subnet_cidr, strict=False)
                with ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as executor:
                    executor.map(self._scan_ip, network.hosts())
            except (ValueError, TypeError) as e:
                self.signals.status_update.emit(f"Ошибка в формате подсети {subnet_cidr}: {e}")

    def run_discovery(self, target_subnets=None):
        """Основной метод для запуска обнаружения устройств."""
        self.signals.status_update.emit("Запуск обнаружения...")
        self.found_devices.clear()
        scan_threads = [
            threading.Thread(target=self._find_printers_by_port_scan, args=(target_subnets,)),
            threading.Thread(target=self._find_printers_by_mdns)
        ]
        for t in scan_threads: t.start()
        for t in scan_threads: t.join()
        self.signals.discovery_finished.emit(self.found_devices)

    def _scan_ip(self, ip_address):
        """Проверяет открытые принтерные порты для одного IP-адреса."""
        ip = str(ip_address)
        
        if ip == '127.0.0.1':
            return
            
        if ip in self.found_devices: return
        for port in PRINTER_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(SCAN_TIMEOUT)
                    if s.connect_ex((ip, port)) == 0:
                        self.found_devices[ip] = f"Port {port}"
                        break
            except socket.error: pass

    def _find_printers_by_mdns(self):
        """Ищет устройства с помощью mDNS/Bonjour."""
        if not ZEROCONF_AVAILABLE: return
        class mDNSListener:
            def __init__(self, worker_ref): self.worker = worker_ref
            def remove_service(self, zc, type, name): pass
            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info and info.addresses:
                    ip = socket.inet_ntoa(info.addresses[0])
                    
                    if ip == '127.0.0.1':
                        return
                        
                    if ip not in self.worker.found_devices:
                        self.worker.found_devices[ip] = "mDNS/Bonjour"
        
        self.signals.status_update.emit("Поиск по mDNS...")
        zeroconf = Zeroconf()
        ServiceBrowser(zeroconf, ["_ipp._tcp.local.", "_pdl-datastream._tcp.local."], mDNSListener(self))
        time.sleep(MDNS_SCAN_DURATION)
        zeroconf.close()

    async def _get_snmp_details(self, ip):
        """Асинхронно получает детали устройства по SNMP."""
        details = {}
        snmp_engine = SnmpEngine()
        errorIndication, errorStatus, _, varBinds = await getCmd(
            snmp_engine, CommunityData(SNMP_COMMUNITY), UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES),
            ContextData(), ObjectType(ObjectIdentity(OID_SYS_DESCR)), ObjectType(ObjectIdentity(OID_SERIAL_NUMBER)),
            ObjectType(ObjectIdentity(OID_DEVICE_STATUS)), ObjectType(ObjectIdentity(OID_PAGE_COUNT))
        )
        if errorIndication: self.signals.status_update.emit(f"Ошибка SNMP для {ip}: {errorIndication}"); return ip, None
        elif errorStatus: self.signals.status_update.emit(f"Ошибка SNMP для {ip}: {errorStatus.prettyPrint()}"); return ip, None
        
        for oid, val in varBinds:
            oid_str, val_str = str(oid), str(val).strip()
            if oid_str == OID_SYS_DESCR: details['model'] = val_str
            elif oid_str == OID_SERIAL_NUMBER: details['serial'] = val_str
            elif oid_str == OID_DEVICE_STATUS: details['status'] = HR_DEVICE_STATUS.get(int(val), 'N/A')
            elif oid_str == OID_PAGE_COUNT: details['pages'] = val_str
        return ip, details

    def run_snmp_collection(self, ips_to_query):
        """Запускает сбор данных по SNMP для списка IP-адресов."""
        if not PYSNMP_AVAILABLE or not ips_to_query: self.signals.snmp_finished.emit(); return
        self.signals.status_update.emit(f"Опрос {len(ips_to_query)} устройств по SNMP...")
        
        async def main_async_task():
            return await asyncio.gather(*[self._get_snmp_details(ip) for ip in ips_to_query])
        
        try:
            results = asyncio.run(main_async_task())
            for ip, details in results:
                if details: self.signals.details_updated.emit(ip, details)
        except Exception as e:
            self.signals.status_update.emit(f"Критическая ошибка SNMP: {e}")
        
        self.signals.snmp_finished.emit()


class MainWindow(QMainWindow):
    """Главное окно приложения."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Сетевой сканер принтеров v4.5.1")
        self.setGeometry(100, 100, 1200, 600)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # --- UI Элементы ---
        self.button_panel = QHBoxLayout()
        self.scan_button = QPushButton("1. Начать сканирование")
        self.collect_button = QPushButton("2. Собрать данные (SNMP)")
        self.save_button = QPushButton("Сохранить в Excel")
        self.delete_button = QPushButton("Удалить выбранные")
        
        self.subnet_label = QLabel("Подсеть для сканирования:")
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("Авто / 192.168.1.0/24 / 20-23")
        self.subnet_input.setToolTip("Введите:\n- Пусто для автоопределения\n- CIDR (e.g., 192.168.10.0/24)\n- Диапазон 3-го октета (e.g., 20-23)")
        self.subnet_input.setFixedWidth(200)

        self.button_panel.addWidget(self.scan_button)
        self.button_panel.addWidget(self.collect_button)
        self.button_panel.addStretch(1)
        self.button_panel.addWidget(self.subnet_label)
        self.button_panel.addWidget(self.subnet_input)
        self.button_panel.addStretch(1)
        self.button_panel.addWidget(self.save_button)
        self.button_panel.addWidget(self.delete_button)
        
        self.table = QTableWidget()
        self.setStatusBar(QStatusBar(self))
        self.columns = ["IP Адрес", "Источник", "Модель", "Серийный №", "Статус", "Счетчик стр."]
        self.table.setColumnCount(len(self.columns))
        self.table.setHorizontalHeaderLabels(self.columns)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(2, 350)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        self.layout.addLayout(self.button_panel)
        self.layout.addWidget(self.table)
        
        # --- Подключение сигналов к слотам ---
        self.scan_button.clicked.connect(self.start_discovery_scan)
        self.collect_button.clicked.connect(self.start_snmp_collection)
        self.save_button.clicked.connect(self.save_report_to_excel)
        self.delete_button.clicked.connect(self.delete_selected_rows)
        
        self.thread = None
        self.worker = None
        self.set_buttons_state(is_scanning=False)

    def _parse_subnet_input(self, text):
        """Парсит ввод пользователя и возвращает список подсетей в CIDR или None при ошибке."""
        text = text.strip()
        if not text:
            return [] # Пустой список для автоопределения
        
        range_match = re.fullmatch(r'(\d{1,3})-(\d{1,3})', text)
        if range_match:
            try:
                start = int(range_match.group(1)); end = int(range_match.group(2))
                if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
                    raise ValueError("Некорректный диапазон октетов (0-255, старт <= конец).")
                
                local_ip = ScannerWorker()._get_local_ip()
                if local_ip.startswith('127.'):
                     raise ValueError("Не удалось определить локальную сеть для построения диапазона.")
                prefix = ".".join(local_ip.split('.')[:2])
                return [f"{prefix}.{i}.0/24" for i in range(start, end + 1)]
            except (ValueError, IndexError) as e:
                QMessageBox.critical(self, "Ошибка ввода", f"Не удалось обработать диапазон: {e}"); return None
        
        try:
            ipaddress.ip_network(text, strict=False)
            return [text]
        except ValueError:
            QMessageBox.critical(self, "Ошибка ввода", f"Некорректный формат подсети: '{text}'.\nИспользуйте CIDR (192.168.1.0/24) или диапазон (20-23).")
            return None

    def start_discovery_scan(self):
        """Запускает поток для обнаружения устройств."""
        subnets_to_scan = self._parse_subnet_input(self.subnet_input.text())
        if subnets_to_scan is None: return

        self.table.setRowCount(0); self.set_buttons_state(is_scanning=True)
        self.statusBar().showMessage("Подготовка к обнаружению...")
        
        self.thread = QThread(); self.worker = ScannerWorker(); self.worker.moveToThread(self.thread)
        self.thread.started.connect(lambda: self.worker.run_discovery(target_subnets=subnets_to_scan))
        self.worker.signals.status_update.connect(self.statusBar().showMessage)
        self.worker.signals.discovery_finished.connect(self.discovery_finished)
        self.thread.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def start_snmp_collection(self):
        """Запускает поток для сбора SNMP-данных."""
        ips = [self.table.item(row, 0).text() for row in range(self.table.rowCount())]
        if not ips: return
        self.set_buttons_state(is_scanning=True); self.statusBar().showMessage("Подготовка к сбору данных по SNMP...")
        self.thread = QThread(); self.worker = ScannerWorker(); self.worker.moveToThread(self.thread)
        self.thread.started.connect(lambda: self.worker.run_snmp_collection(ips))
        self.worker.signals.status_update.connect(self.statusBar().showMessage)
        self.worker.signals.details_updated.connect(self.update_printer_details)
        self.worker.signals.snmp_finished.connect(self.snmp_finished)
        self.worker.signals.snmp_finished.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def discovery_finished(self, found_devices):
        """Обрабатывает завершение сканирования: заполняет таблицу и обновляет UI."""
        self.statusBar().showMessage(f"Обнаружение завершено. Найдено устройств: {len(found_devices)}")
        self.table.setRowCount(len(found_devices))
        sorted_ips = sorted(found_devices.items(), key=lambda item: ipaddress.ip_address(item[0]))
        for row, (ip, source) in enumerate(sorted_ips):
            self.table.setItem(row, 0, QTableWidgetItem(ip)); self.table.setItem(row, 1, QTableWidgetItem(source))
        self.set_buttons_state(is_scanning=False)
        if self.thread: self.thread.quit()

    def snmp_finished(self):
        """Обрабатывает завершение сбора SNMP-данных."""
        self.statusBar().showMessage("Сбор данных по SNMP завершен"); self.set_buttons_state(is_scanning=False)

    def update_printer_details(self, ip, details):
        """Обновляет строку в таблице новыми данными от SNMP."""
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).text() == ip:
                self.table.setItem(row, 2, QTableWidgetItem(details.get('model', 'N/A')))
                self.table.setItem(row, 3, QTableWidgetItem(details.get('serial', 'N/A')))
                self.table.setItem(row, 4, QTableWidgetItem(details.get('status', 'N/A')))
                self.table.setItem(row, 5, QTableWidgetItem(details.get('pages', 'N/A')))
                self.table.resizeRowsToContents(); break
    
    def save_report_to_excel(self):
        """Сохраняет отфильтрованный отчет в многостраничный Excel файл."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "printers_report.xlsx", "Excel Files (*.xlsx)")
        if not file_name: return

        all_data = []
        for row in range(self.table.rowCount()):
            row_values = [self.table.item(row, col).text() if self.table.item(row, col) else "" for col in range(self.table.columnCount())]
            has_details = any(val and val.strip() and val.strip().lower() != 'n/a' for val in row_values[2:])
            if has_details:
                all_data.append(row_values)

        if not all_data:
            self.statusBar().showMessage("Нет данных для сохранения (все записи без деталей).", 5000)
            return
            
        try:
            df = pd.DataFrame(all_data, columns=self.columns)
            df['subnet_group'] = df['IP Адрес'].apply(lambda ip: ip.split('.')[2])
            
            with pd.ExcelWriter(file_name, engine='openpyxl') as writer:
                for group_name, df_group in df.groupby('subnet_group'):
                    sheet_name = f'Подсеть {group_name}'
                    df_group.drop('subnet_group', axis=1).to_excel(writer, sheet_name=sheet_name, index=False)
            self.statusBar().showMessage(f"Отчет успешно сохранен в {file_name}", 10000)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка сохранения", f"Не удалось сохранить Excel файл:\n{e}")

    def delete_selected_rows(self):
        """Удаляет выбранные строки из таблицы."""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows: return
        for index in sorted(selected_rows, key=lambda x: x.row(), reverse=True): self.table.removeRow(index.row())
        self.set_buttons_state(is_scanning=False)

    def set_buttons_state(self, is_scanning):
        """Управляет активностью кнопок в зависимости от состояния приложения."""
        has_results = self.table.rowCount() > 0
        self.scan_button.setEnabled(not is_scanning)
        self.subnet_input.setEnabled(not is_scanning)
        self.collect_button.setEnabled(not is_scanning and has_results)
        self.save_button.setEnabled(not is_scanning and has_results)
        self.delete_button.setEnabled(not is_scanning and has_results)
    
    def keyPressEvent(self, event):
        """Обрабатывает нажатие клавиши Delete для удаления строк."""
        if event.key() == Qt.Key.Key_Delete: self.delete_selected_rows()
        super().keyPressEvent(event)


def main():
    """Основная функция для запуска приложения."""
    app = QApplication(sys.argv)
    
    missing_deps = []
    if not PYQT6_AVAILABLE: missing_deps.append("PyQt6")
    if not ZEROCONF_AVAILABLE: missing_deps.append("zeroconf")
    if not PYSNMP_AVAILABLE: missing_deps.append("pysnmp")
    if not PANDAS_AVAILABLE: missing_deps.append("pandas openpyxl")

    if missing_deps:
        QMessageBox.critical(None, "Ошибка зависимостей", f"Не найдены библиотеки: {', '.join(missing_deps)}.\n\nУстановите их командой:\n\npip install {' '.join(missing_deps)}")
        sys.exit(1)
        
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()