import json
import subprocess

VM_INDICATORS = [
    "virtual",
    "vmware",
    "virtualbox",
    "kvm",
    "qemu",
    "hyper-v",
    "microsoft corporation",
    "xen"
]


def _probe_wmi_manufacturer_model():
    """Return dict with Manufacturer and Model or None on failure."""
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-WmiObject -Class Win32_ComputerSystem | Select-Object Manufacturer,Model | ConvertTo-Json -Compress"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, shell=False)
        out = res.stdout.strip()
        if not out:
            return None
        data = json.loads(out)
        if isinstance(data, list) and data:
            return data[0]
        return data
    except Exception:
        return None


def get_vm_info():
    """Return the raw Manufacturer/Model dict from WMI probe, or None on failure."""
    return _probe_wmi_manufacturer_model()


def is_virtual_machine() -> bool:
    """Heuristically detect common virtual machine manufacturers/models.

    Returns True if a VM indicator is present. Returns False if not detected or on probe failure.
    """
    info = _probe_wmi_manufacturer_model()
    if not info:
        return False
    manu = (info.get("Manufacturer") or "").lower()
    model = (info.get("Model") or "").lower()
    combined = f"{manu} {model}"
    for token in VM_INDICATORS:
        if token in combined:
            return True
    return False
