"""
Backup Manager Module
~~~~~~~~~~~~~~~~~~~~~
Handles multithreaded SSH connections to network devices, running-configuration
extraction, and structured filesystem archiving.
"""

from __future__ import annotations
import os
import time
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("PyNetAudit.Backup")

import importlib

# Dynamic Netmiko import for production environments (prevents IDE missing-import linter errors)
try:
    _netmiko = importlib.import_module("netmiko")
    ConnectHandler = getattr(_netmiko, "ConnectHandler")
    _netmiko_exc = importlib.import_module("netmiko.exceptions")
    NetmikoTimeoutException = getattr(_netmiko_exc, "NetmikoTimeoutException")
    NetmikoAuthenticationException = getattr(_netmiko_exc, "NetmikoAuthenticationException")
    SSHException = getattr(_netmiko_exc, "SSHException")
    NETMIKO_AVAILABLE = True
except (ImportError, AttributeError):
    NETMIKO_AVAILABLE = False
    ConnectHandler = None
    NetmikoTimeoutException = type("NetmikoTimeoutException", (Exception,), {})
    NetmikoAuthenticationException = type("NetmikoAuthenticationException", (Exception,), {})
    SSHException = type("SSHException", (Exception,), {})


class BackupResult:
    """Represents the execution outcome for a single device backup."""
    def __init__(
        self,
        hostname: str,
        ip: str,
        success: bool,
        config: str = "",
        filepath: str = "",
        error: str = "",
        duration: float = 0.0,
    ):
        self.hostname = hostname
        self.ip = ip
        self.success = success
        self.config = config
        self.filepath = filepath
        self.error = error
        self.duration = duration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "success": self.success,
            "filepath": self.filepath,
            "error": self.error,
            "duration": round(self.duration, 2),
            "config_lines": len(self.config.splitlines()) if self.config else 0,
        }


class BackupManager:
    """Orchestrates concurrent network device configuration backups."""

    def __init__(
        self,
        backup_dir: str = "backups",
        max_workers: int = 5,
        timeout: int = 30,
        mock_mode: bool = False,
    ):
        self.backup_dir = backup_dir
        self.max_workers = max_workers
        self.timeout = timeout
        self.mock_mode = mock_mode

        # Initialize directories
        self.today_str = datetime.now().strftime("%Y-%m-%d")
        self.session_dir = os.path.join(self.backup_dir, self.today_str)
        self.latest_dir = os.path.join(self.backup_dir, "latest")
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(self.latest_dir, exist_ok=True)

    def backup_single_device(self, device: Dict[str, Any]) -> BackupResult:
        """Connects via SSH, retrieves running-config, and saves to disk."""
        hostname = device.get("hostname", device.get("ip", "unknown-device"))
        ip = device.get("ip", "0.0.0.0")
        device_type = device.get("device_type", "cisco_ios")
        start_time = time.time()

        logger.info(f"Initiating backup for {hostname} ({ip})...")

        # Mock Mode Simulation
        if self.mock_mode:
            time.sleep(0.4)  # Simulate network latency
            sample_file = (
                "samples/cisco_switch_good.cfg"
                if "core" in hostname or "leaf" in hostname or "rtr" in hostname
                else "samples/cisco_switch_vulnerable.cfg"
            )
            # Try to read local sample file
            if os.path.exists(sample_file):
                with open(sample_file, "r", encoding="utf-8") as f:
                    config = f.read()
            else:
                config = f"! Mock configuration for {hostname}\nversion 15.2\nhostname {hostname}\nend\n"

            # Customize hostname in config
            config = config.replace("sw-core-01.corp", hostname).replace("sw-access-floor1.corp", hostname)
            duration = time.time() - start_time
            filepath = self._save_config(hostname, config)
            return BackupResult(hostname=hostname, ip=ip, success=True, config=config, filepath=filepath, duration=duration)

        # Real Netmiko Execution
        if not NETMIKO_AVAILABLE:
            duration = time.time() - start_time
            return BackupResult(
                hostname=hostname,
                ip=ip,
                success=False,
                error="Netmiko library not installed. Install requirements.txt or run with --mock.",
                duration=duration,
            )

        connection_params = {
            "device_type": device_type,
            "host": ip,
            "username": device.get("username", os.getenv("NET_DEFAULT_USERNAME", "admin")),
            "password": device.get("password", os.getenv("NET_DEFAULT_PASSWORD", "")),
            "secret": device.get("secret", os.getenv("NET_DEFAULT_SECRET", "")),
            "port": device.get("port", 22),
            "timeout": self.timeout,
            "session_log": os.path.join(self.session_dir, f"{hostname}_session.log"),
        }

        try:
            with ConnectHandler(**connection_params) as net_connect:
                if connection_params.get("secret"):
                    net_connect.enable()

                # Choose appropriate backup command per vendor
                if "cisco" in device_type or "arista" in device_type:
                    cmd = "show running-config"
                elif "juniper" in device_type:
                    cmd = "show configuration"
                elif "huawei" in device_type:
                    cmd = "display current-configuration"
                else:
                    cmd = "show running-config"

                config = net_connect.send_command(cmd)
                duration = time.time() - start_time
                filepath = self._save_config(hostname, config)
                logger.info(f"Successfully backed up {hostname} in {duration:.2f}s")
                return BackupResult(hostname=hostname, ip=ip, success=True, config=config, filepath=filepath, duration=duration)

        except NetmikoTimeoutException:
            err = f"SSH Connection Timeout (Host unreachable: {ip}:22)"
            logger.error(f"Backup failed for {hostname}: {err}")
            return BackupResult(hostname=hostname, ip=ip, success=False, error=err, duration=time.time() - start_time)
        except NetmikoAuthenticationException:
            err = "Authentication Failed (Invalid SSH credentials)"
            logger.error(f"Backup failed for {hostname}: {err}")
            return BackupResult(hostname=hostname, ip=ip, success=False, error=err, duration=time.time() - start_time)
        except SSHException as e:
            err = f"SSH Protocol Error: {str(e)}"
            logger.error(f"Backup failed for {hostname}: {err}")
            return BackupResult(hostname=hostname, ip=ip, success=False, error=err, duration=time.time() - start_time)
        except Exception as e:
            err = f"Unexpected Exception: {str(e)}"
            logger.error(f"Backup failed for {hostname}: {err}")
            return BackupResult(hostname=hostname, ip=ip, success=False, error=err, duration=time.time() - start_time)

    def _save_config(self, hostname: str, config: str) -> str:
        """Saves configuration with timestamp and updates latest pointer."""
        timestamp = datetime.now().strftime("%H-%M-%S")
        filename = f"{hostname}_{timestamp}.cfg"
        filepath = os.path.join(self.session_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(config)

        # Update latest copy
        latest_path = os.path.join(self.latest_dir, f"{hostname}.cfg")
        with open(latest_path, "w", encoding="utf-8") as f:
            f.write(config)

        return filepath

    def run_all(
        self,
        devices: List[Dict[str, Any]],
        callback: Optional[Callable[[BackupResult], None]] = None,
    ) -> List[BackupResult]:
        """Executes backups across all devices concurrently via ThreadPool."""
        results: List[BackupResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(self.backup_single_device, dev): dev
                for dev in devices
            }
            for future in as_completed(future_to_device):
                result = future.result()
                results.append(result)
                if callback:
                    callback(result)

        return sorted(results, key=lambda r: r.hostname)
