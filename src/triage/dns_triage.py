import socket
import time
from typing import Tuple, List


class DNSTriage:
    """
    Automated DNS resolution diagnostic investigator.
    Determines whether failures stem from name resolution vs network reachability.
    """

    def __init__(self, timeout_seconds: float = 3.0):
        self.timeout_seconds = timeout_seconds

    def run(self, hostname: str) -> Tuple[str, bool]:
        """
        Attempts to resolve hostname to IP addresses.
        Returns (diagnostic_message, is_success).
        """
        # If hostname is already an IPv4 or IPv6 address, bypass DNS check
        if self._is_ip_address(hostname):
            return f"Target {hostname} is a direct IP address. DNS lookup bypassed.", True

        start_time = time.perf_counter()
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            resolved_ips: List[str] = list({item[4][0] for item in addr_info})

            ips_str = ", ".join(resolved_ips)
            return (
                f"Resolved {hostname} -> [{ips_str}] in {elapsed_ms}ms via system resolver.",
                True,
            )

        except socket.gaierror as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return (
                f"DNS Resolution FAILED for {hostname} ({elapsed_ms}ms): {str(exc)}. "
                "Local or upstream DNS server could not resolve hostname.",
                False,
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return (
                f"DNS lookup error ({elapsed_ms}ms): {type(exc).__name__} - {str(exc)}",
                False,
            )

    def _is_ip_address(self, value: str) -> bool:
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except (socket.error, AttributeError):
            pass
        return False
