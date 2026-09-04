#!/usr/bin/env python3
"""
NetCut Web Dashboard - Advanced Edition
A modern Flask-based web interface for NetCut with extended features:
- Activity logging
- Whitelist management
- MAC vendor lookup
- Port scanning
- Export capabilities
- Settings management
"""

import os
import sys
import csv
import json
import socket
import threading
import atexit
import datetime
import io
from collections import deque
from flask import Flask, render_template, jsonify, request, send_file, Response
from netcut.controller import NetCutController

app = Flask(__name__)
controller = NetCutController(attack_interval_s=2.0)
controller.initialize()

is_scanning = False
scan_lock = threading.Lock()

# ─── In-Memory Activity Log ─────────────────────────────────────────────────
activity_log = deque(maxlen=500)  # Keep last 500 events
log_lock = threading.Lock()

def add_log(action: str, ip: str, mac: str = "", message: str = "", level: str = "info"):
    """Add entry to the in-memory activity log."""
    entry = {
        "id": len(activity_log) + 1,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "ip": ip,
        "mac": mac,
        "message": message,
        "level": level   # info | success | warning | danger
    }
    with log_lock:
        activity_log.appendleft(entry)
    return entry


# ─── Whitelist ───────────────────────────────────────────────────────────────
whitelist: set = set()   # Set of IPs that cannot be cut
whitelist_lock = threading.Lock()

def is_whitelisted(ip: str) -> bool:
    with whitelist_lock:
        return ip in whitelist


# ─── Settings ────────────────────────────────────────────────────────────────
settings = {
    "attack_interval_s": 2.0,
    "scan_interval_s": 30,
    "auto_scan": True,
    "port_scan_timeout": 0.5,
    "common_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443],
}
settings_lock = threading.Lock()


# ─── MAC Vendor OUI Database (top vendors offline) ───────────────────────────
OUI_MAP = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3E": "Xen",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1A:11": "Google",
    "F4:F5:D8": "Google",
    "AC:CF:85": "Apple",
    "00:17:F2": "Apple",
    "F0:18:98": "Apple",
    "3C:15:C2": "Apple",
    "28:CF:E9": "Apple",
    "A4:C3:61": "Apple",
    "70:56:81": "Apple",
    "D8:96:95": "Samsung",
    "00:26:5A": "Samsung",
    "8C:71:F8": "Samsung",
    "00:1F:5B": "Apple",
    "00:1B:63": "Apple",
    "00:23:14": "Intel",
    "3C:F0:11": "Intel",
    "8C:EC:4B": "Intel",
    "00:50:BA": "D-Link",
    "00:1C:F0": "D-Link",
    "14:D6:4D": "D-Link",
    "00:90:4C": "Asus",
    "04:92:26": "Asus",
    "2C:4D:54": "Asus",
    "00:26:18": "Cisco",
    "58:F3:9C": "Cisco",
    "00:24:14": "Cisco",
    "80:71:7A": "TP-Link",
    "50:C7:BF": "TP-Link",
    "B0:4E:26": "TP-Link",
    "00:1D:73": "Huawei",
    "00:25:9E": "Huawei",
    "48:AD:08": "Huawei",
    "00:18:E7": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi",
    "00:22:15": "Lenovo",
    "00:1A:6B": "Lenovo",
    "00:23:AE": "Dell",
    "00:21:70": "Dell",
    "00:1E:4F": "Dell",
    "F0:DE:F1": "HP",
    "00:1A:4B": "HP",
    "3C:D9:2B": "HP",
    "00:0F:EA": "Gigabyte",
    "D4:3D:7E": "Realtek",
    "00:E0:4C": "Realtek",
}

def get_vendor(mac: str) -> str:
    """Returns vendor name from MAC OUI prefix."""
    if not mac or mac == "N/A":
        return "Unknown"
    # Normalize MAC to uppercase with colons
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    prefix = mac_clean[:8]
    return OUI_MAP.get(prefix, "Unknown")


# ─── Port Scanner ─────────────────────────────────────────────────────────────
def scan_ports(ip: str, ports: list, timeout: float = 0.5) -> list:
    """Scans common ports on a target IP. Returns list of open ports."""
    open_ports = []
    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=check_port, args=(port,))
        t.daemon = True
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=timeout + 0.2)
    return sorted(open_ports)


PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}


# ─── Background tasks ─────────────────────────────────────────────────────────
def _background_scan():
    global is_scanning
    with scan_lock:
        if is_scanning:
            return
        is_scanning = True
    try:
        add_log("SCAN", "network", message="Network scan started", level="info")
        controller.scan_targets()
        with controller._lock:
            count = len(controller.hosts)
        add_log("SCAN", "network", message=f"Scan complete – {count} host(s) discovered", level="success")
    finally:
        with scan_lock:
            is_scanning = False


# Start initial scan
threading.Thread(target=_background_scan, daemon=True).start()
atexit.register(controller.recover_all_hosts)


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Renders the main dashboard."""
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    """Returns general network & attack status."""
    l2_ready, l2_msg = controller.get_l2_status()
    with controller._lock:
        total_hosts = len(controller.hosts)
        cut_hosts = sum(1 for h in controller.hosts if h.is_cut())

    installer_path = os.path.join(os.path.dirname(__file__), "npcap-installer.exe")
    has_installer = os.path.exists(installer_path)

    with settings_lock:
        current_settings = dict(settings)

    return jsonify({
        "interface": controller.interface.name if controller.interface else "N/A",
        "local_ip": controller.interface.ip if controller.interface else "N/A",
        "netmask": controller.interface.netmask if controller.interface else "N/A",
        "gateway_ip": controller.scanner.gateway_ip or "Auto",
        "gateway_mac": controller.scanner.gateway_mac or "N/A",
        "total_hosts": total_hosts,
        "cut_hosts": cut_hosts,
        "is_scanning": is_scanning,
        "l2_ready": l2_ready,
        "l2_message": l2_msg,
        "has_installer": has_installer,
        "os": sys.platform,
        "whitelist_count": len(whitelist),
        "settings": current_settings
    })


@app.route("/api/hosts")
def api_hosts():
    """Returns list of currently discovered hosts with vendor & whitelist info."""
    with controller._lock:
        hosts_data = []
        for h in controller.hosts:
            d = h.to_dict()
            d["vendor"] = get_vendor(d.get("mac", ""))
            d["whitelisted"] = is_whitelisted(d.get("ip", ""))
            hosts_data.append(d)

    return jsonify({
        "hosts": hosts_data,
        "gateway_ip": controller.scanner.gateway_ip,
        "is_scanning": is_scanning
    })


@app.route("/api/host/<path:ip>")
def api_host_detail(ip):
    """Returns detailed info about a specific host including open ports."""
    target = controller.get_host_by_ip(ip)
    if not target:
        return jsonify({"status": "error", "message": f"Host {ip} tidak ditemukan"}), 404

    d = target.to_dict()
    d["vendor"] = get_vendor(d.get("mac", ""))
    d["whitelisted"] = is_whitelisted(ip)

    # Resolve hostname if not available
    if not d.get("hostname"):
        try:
            d["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            d["hostname"] = ""

    # Scan ports (non-blocking subset)
    with settings_lock:
        ports_to_scan = settings["common_ports"]
        timeout = settings["port_scan_timeout"]

    open_ports = scan_ports(ip, ports_to_scan, timeout=timeout)
    port_info = [{"port": p, "service": PORT_SERVICES.get(p, "Unknown")} for p in open_ports]

    # Get host's activity from log
    with log_lock:
        host_logs = [e for e in activity_log if e.get("ip") == ip][:20]

    return jsonify({
        "status": "success",
        "host": d,
        "open_ports": port_info,
        "history": host_logs
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Triggers an active network scan."""
    global is_scanning
    if not is_scanning:
        threading.Thread(target=_background_scan, daemon=True).start()
    return jsonify({"status": "scanning", "message": "Scan started in background"})


@app.route("/api/toggle/<path:ip>", methods=["POST"])
def api_toggle(ip):
    """Toggles cut/recover state for a specific IP."""
    if is_whitelisted(ip):
        return jsonify({
            "status": "error",
            "message": f"Host {ip} ada di whitelist dan tidak bisa di-cut.",
            "whitelisted": True
        }), 403

    target = controller.get_host_by_ip(ip)
    if not target:
        return jsonify({"status": "error", "message": f"Host {ip} tidak ditemukan"}), 404

    mac = target.to_dict().get("mac", "")

    if target.is_cut():
        controller.recover(target)
        add_log("RECOVER", ip, mac=mac, message=f"Host {ip} dipulihkan", level="success")
        return jsonify({"status": "success", "host": target.to_dict(), "action": "RECOVERED"})
    else:
        ok, msg = controller.attack(target)
        if not ok:
            add_log("CUT_FAILED", ip, mac=mac, message=msg, level="danger")
            return jsonify({
                "status": "error",
                "message": msg,
                "needs_npcap": not controller.get_l2_status()[0]
            }), 400
        add_log("CUT", ip, mac=mac, message=f"Host {ip} diputus koneksinya", level="danger")
        return jsonify({"status": "success", "host": target.to_dict(), "action": "CUT"})


@app.route("/api/toggle-bulk", methods=["POST"])
def api_toggle_bulk():
    """Toggle cut/recover for multiple IPs at once."""
    data = request.get_json() or {}
    ips = data.get("ips", [])
    action = data.get("action", "cut")   # "cut" or "recover"

    results = {"success": [], "failed": [], "whitelisted": []}
    for ip in ips:
        if is_whitelisted(ip):
            results["whitelisted"].append(ip)
            continue
        target = controller.get_host_by_ip(ip)
        if not target:
            results["failed"].append(ip)
            continue
        mac = target.to_dict().get("mac", "")
        if action == "cut":
            ok, msg = controller.attack(target)
            if ok:
                add_log("CUT", ip, mac=mac, message=f"Bulk cut: {ip}", level="danger")
                results["success"].append(ip)
            else:
                results["failed"].append(ip)
        else:
            controller.recover(target)
            add_log("RECOVER", ip, mac=mac, message=f"Bulk recover: {ip}", level="success")
            results["success"].append(ip)

    return jsonify({"status": "success", "results": results})


@app.route("/api/recover-all", methods=["POST"])
def api_recover_all():
    """Restores connectivity for all cut hosts."""
    controller.recover_all_hosts()
    add_log("RECOVER_ALL", "all", message="Semua koneksi host dipulihkan", level="success")
    return jsonify({"status": "success", "message": "Semua koneksi host dipulihkan"})


# ─── Whitelist ─────────────────────────────────────────────────────────────────
@app.route("/api/whitelist", methods=["GET"])
def api_whitelist_get():
    with whitelist_lock:
        return jsonify({"whitelist": list(whitelist)})


@app.route("/api/whitelist", methods=["POST"])
def api_whitelist_add():
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP diperlukan"}), 400
    with whitelist_lock:
        whitelist.add(ip)
    add_log("WHITELIST_ADD", ip, message=f"{ip} ditambahkan ke whitelist", level="info")
    return jsonify({"status": "success", "message": f"{ip} ditambahkan ke whitelist"})


@app.route("/api/whitelist/<path:ip>", methods=["DELETE"])
def api_whitelist_remove(ip):
    with whitelist_lock:
        whitelist.discard(ip)
    add_log("WHITELIST_REMOVE", ip, message=f"{ip} dihapus dari whitelist", level="warning")
    return jsonify({"status": "success", "message": f"{ip} dihapus dari whitelist"})


# ─── Logs ──────────────────────────────────────────────────────────────────────
@app.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 100))
    level_filter = request.args.get("level", "")
    with log_lock:
        logs = list(activity_log)
    if level_filter:
        logs = [l for l in logs if l.get("level") == level_filter]
    return jsonify({"logs": logs[:limit], "total": len(logs)})


@app.route("/api/export-logs")
def api_export_logs():
    """Exports activity log as CSV download."""
    with log_lock:
        logs = list(activity_log)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "timestamp", "action", "ip", "mac", "message", "level"])
    writer.writeheader()
    writer.writerows(logs)
    output.seek(0)

    filename = f"netcut_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ─── Settings ──────────────────────────────────────────────────────────────────
@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    with settings_lock:
        return jsonify(settings)


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    data = request.get_json() or {}
    with settings_lock:
        if "attack_interval_s" in data:
            val = float(data["attack_interval_s"])
            settings["attack_interval_s"] = max(0.5, min(val, 30.0))
            controller.spoofer.attack_interval_s = settings["attack_interval_s"]
        if "port_scan_timeout" in data:
            settings["port_scan_timeout"] = max(0.1, min(float(data["port_scan_timeout"]), 5.0))
        if "auto_scan" in data:
            settings["auto_scan"] = bool(data["auto_scan"])
    add_log("SETTINGS", "system", message="Settings diperbarui", level="info")
    return jsonify({"status": "success", "settings": settings})


# ─── Vendor ────────────────────────────────────────────────────────────────────
@app.route("/api/vendor/<path:mac>")
def api_vendor(mac):
    vendor = get_vendor(mac)
    return jsonify({"mac": mac, "vendor": vendor})


# ─── Npcap Installer ───────────────────────────────────────────────────────────
@app.route("/api/download-npcap")
def api_download_npcap():
    """Serves npcap-installer.exe as a browser download."""
    installer_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "npcap-installer.exe"))
    if os.path.exists(installer_path):
        return send_file(installer_path, as_attachment=True, download_name="npcap-installer.exe")
    return jsonify({"status": "error", "message": "npcap-installer.exe tidak ditemukan."}), 404


@app.route("/api/install-npcap", methods=["POST"])
def api_install_npcap():
    """Provides download URL for npcap installer."""
    installer_path = os.path.join(os.path.dirname(__file__), "npcap-installer.exe")
    if os.path.exists(installer_path):
        return jsonify({
            "status": "success",
            "message": "Silakan download installer Npcap di bawah ini.",
            "download_url": "/api/download-npcap"
        })
    return jsonify({"status": "error", "message": "npcap-installer.exe tidak ditemukan."}), 404


if __name__ == "__main__":
    print("\n[+] Starting NetCut Web Dashboard (Advanced) on http://127.0.0.1:5000 ...")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
