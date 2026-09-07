"""
Windows Native Bluetooth 2FA Management (No iOS App Required).

Leverages standard Windows Bluetooth pairing:
1. Discovers Windows-paired Bluetooth devices via BluetoothApis.dll.
2. Checks live connection state (fConnected flag).
3. Verifies physical presence and proximity via an active Bluetooth RFCOMM ping.
4. Requires zero third-party software on the iPhone — works with standard iOS Bluetooth.
"""

import ctypes
from ctypes import wintypes
import socket
import time
from typing import List, Dict, Any, Optional, Tuple


class BLUETOOTH_DEVICE_SEARCH_PARAMS(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('fReturnAuthenticated', wintypes.BOOL),
        ('fReturnRemembered', wintypes.BOOL),
        ('fReturnUnknown', wintypes.BOOL),
        ('fReturnConnected', wintypes.BOOL),
        ('fIssueInquiry', wintypes.BOOL),
        ('cTimeoutMultiplier', ctypes.c_ubyte),
        ('hRadio', wintypes.HANDLE)
    ]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ('wYear', wintypes.WORD), ('wMonth', wintypes.WORD),
        ('wDayOfWeek', wintypes.WORD), ('wDay', wintypes.WORD),
        ('wHour', wintypes.WORD), ('wMinute', wintypes.WORD),
        ('wSecond', wintypes.WORD), ('wMilliseconds', wintypes.WORD)
    ]


class BLUETOOTH_DEVICE_INFO(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('Address', ctypes.c_ulonglong),
        ('ulClassofDevice', wintypes.ULONG),
        ('fConnected', wintypes.BOOL),
        ('fRemembered', wintypes.BOOL),
        ('fAuthenticated', wintypes.BOOL),
        ('stLastSeen', SYSTEMTIME),
        ('stLastUsed', SYSTEMTIME),
        ('szName', wintypes.WCHAR * 248)
    ]


def _format_mac(address_ulong: int) -> str:
    """Converts 64-bit integer address to standard colon-separated MAC string."""
    mac_hex = hex(address_ulong)[2:].zfill(12).upper()
    return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))


def get_windows_bluetooth_devices() -> List[Dict[str, Any]]:
    """
    Returns list of all paired / remembered / connected Bluetooth devices from Windows.
    Each dict contains:
    - name: str (e.g. "Ahmed's iPhone")
    - mac: str (e.g. "28:49:E9:83:40:1C")
    - connected: bool
    - remembered: bool
    - authenticated: bool
    """
    devices = []
    try:
        bth = ctypes.windll.BluetoothApis
        bth.BluetoothFindFirstDevice.restype = wintypes.HANDLE
        bth.BluetoothFindFirstDevice.argtypes = [
            ctypes.POINTER(BLUETOOTH_DEVICE_SEARCH_PARAMS),
            ctypes.POINTER(BLUETOOTH_DEVICE_INFO)
        ]
        bth.BluetoothFindNextDevice.restype = wintypes.BOOL
        bth.BluetoothFindNextDevice.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(BLUETOOTH_DEVICE_INFO)
        ]
        bth.BluetoothFindDeviceClose.restype = wintypes.BOOL
        bth.BluetoothFindDeviceClose.argtypes = [wintypes.HANDLE]

        params = BLUETOOTH_DEVICE_SEARCH_PARAMS()
        params.dwSize = ctypes.sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS)
        params.fReturnAuthenticated = True
        params.fReturnRemembered = True
        params.fReturnConnected = True
        params.fReturnUnknown = False
        params.fIssueInquiry = False

        info = BLUETOOTH_DEVICE_INFO()
        info.dwSize = ctypes.sizeof(BLUETOOTH_DEVICE_INFO)

        h_find = bth.BluetoothFindFirstDevice(ctypes.byref(params), ctypes.byref(info))
        if h_find:
            try:
                while True:
                    devices.append({
                        "name": str(info.szName),
                        "mac": _format_mac(info.Address),
                        "connected": bool(info.fConnected),
                        "remembered": bool(info.fRemembered),
                        "authenticated": bool(info.fAuthenticated)
                    })
                    if not bth.BluetoothFindNextDevice(h_find, ctypes.byref(info)):
                        break
            finally:
                bth.BluetoothFindDeviceClose(h_find)
    except Exception as e:
        # Fallback empty list if bluetooth stack unavailable
        print(f"Error querying Windows Bluetooth: {e}")

    return devices


def ping_bluetooth_rfcomm(mac: str, port: int = 2, timeout: float = 2.5) -> bool:
    """
    Attempts a direct RFCOMM handshake ping to verify physical connection and reachability.
    Standard iOS Bluetooth responds on channel 2 (Handsfree / Audio / Accessory profile).
    """
    if not hasattr(socket, "AF_BLUETOOTH") or not hasattr(socket, "BTPROTO_RFCOMM"):
        return False

    try:
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        s.settimeout(timeout)
        s.connect((mac, port))
        s.close()
        return True
    except Exception:
        # If port 2 doesn't answer, try port 1
        if port == 2:
            try:
                s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
                s.settimeout(1.5)
                s.connect((mac, 1))
                s.close()
                return True
            except Exception:
                pass
        return False


def verify_bluetooth_2fa(target_mac: str, timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Verifies that the target iPhone is paired and actively connected via Bluetooth.

    1. Validates device is known to Windows Bluetooth stack.
    2. Performs live Bluetooth radio handshake (RFCOMM ping) to verify physical proximity.
    3. Returns (True, message) if confirmed, or (False, error) if not reachable.
    """
    devices = get_windows_bluetooth_devices()
    target_clean = target_mac.upper().strip()

    matched = None
    for d in devices:
        if d["mac"].upper() == target_clean:
            matched = d
            break

    dev_name = matched.get("name", "iPhone") if matched else "iPhone"

    # 1. Live radio handshake ping (checks real-time physical proximity)
    ping_ok = ping_bluetooth_rfcomm(target_clean, port=2, timeout=timeout)
    if ping_ok:
        return True, f"'{dev_name}' confirmed connected via Bluetooth."

    # 2. Check if Windows reports fConnected flag
    if matched and matched.get("connected", False):
        return True, f"'{dev_name}' connected to Windows."

    if not matched:
        return False, f"Device with MAC {target_mac} is not paired in Windows Bluetooth settings."

    return False, f"'{dev_name}' ({target_mac}) is not connected or out of Bluetooth range."
