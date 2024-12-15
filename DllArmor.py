import os
import time
import psutil
import ctypes
import shutil
import logging
from win32com.client import Dispatch

# Constants
SUSPICIOUS_PATHS = ["\\Temp", "\\AppData"]
WHITELIST_PATHS = ["C:\\Windows\\System32", "C:\\Program Files"]
QUARANTINE_DIR = "C:\\Quarantine"
LOG_FILE = "scanner.log"

# Setup Logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def get_loaded_dlls(pid):
    """Retrieve loaded DLLs for a given process ID using Windows API."""
    dlls = []
    try:
        h_process = ctypes.windll.kernel32.OpenProcess(0x0410, False, pid)
        if not h_process:
            return dlls
        
        modules = (ctypes.c_void_p * 1024)()
        needed = ctypes.c_ulong()
        
        if ctypes.windll.psapi.EnumProcessModules(h_process, ctypes.byref(modules), ctypes.sizeof(modules), ctypes.byref(needed)):
            count = needed.value // ctypes.sizeof(ctypes.c_void_p)
            for i in range(count):
                module_name = ctypes.create_unicode_buffer(260)
                ctypes.windll.psapi.GetModuleFileNameExW(h_process, modules[i], module_name, 260)
                dlls.append(module_name.value)
        
        ctypes.windll.kernel32.CloseHandle(h_process)
    except Exception as e:
        logging.error(f"Error retrieving DLLs for PID {pid}: {e}")
    return dlls

def is_signed(file_path):
    """Check if a file is digitally signed."""
    try:
        signer = Dispatch("Scripting.Signer")
        return signer.Verify(file_path)
    except Exception as e:
        logging.warning(f"Could not verify signature for {file_path}: {e}")
        return False

def analyze_dll(dll_path):
    """Check if the DLL is suspicious."""
    # Check against whitelist
    if any(dll_path.startswith(path) for path in WHITELIST_PATHS):
        return False
    # Check for suspicious paths
    if any(path in dll_path for path in SUSPICIOUS_PATHS):
        return True
    # Check digital signature
    if not is_signed(dll_path):
        return True
    return False

def backup_and_delete(dll_path):
    """Move the DLL to quarantine and log the action."""
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
        quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(dll_path))
        shutil.move(dll_path, quarantine_path)
        logging.info(f"Quarantined DLL: {dll_path}")
    except Exception as e:
        logging.error(f"Failed to quarantine {dll_path}: {e}")

def main():
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                dlls = get_loaded_dlls(proc.info['pid'])
                for dll in dlls:
                    if analyze_dll(dll):
                        logging.warning(f"Suspicious DLL detected: {dll}")
                        backup_and_delete(dll)
            except Exception as e:
                logging.error(f"Error processing {proc.info['name']}: {e}")
        time.sleep(10)  # Adjust as needed

if __name__ == "__main__":
    main()
