"""
IP Whitelist Utility

Enhanced with:
- Caching (lru_cache)
- Dynamic whitelist reloading
- Environment variable configuration
- Audit logging
"""

import ipaddress
import logging
import os
from functools import lru_cache

# Default whitelisted IPs (can be overridden via environment/config)
DEFAULT_WHITELIST = {"192.168.1.1", "10.0.0.0/8", "172.16.0.0/12"}

class IPWhitelist:
    def __init__(self):
        """
        Initialize with IP whitelist from environment or defaults
        """
        self.refresh_whitelist()
    
    def refresh_whitelist(self, new_whitelist: set[str] = None):
        """
        Update whitelist dynamically
        
        Args:
            new_whitelist: Optional set of IPs to use instead of environment/defaults
        """
        if new_whitelist:
            self.whitelist = new_whitelist
        else:
            env_ips = os.getenv("IP_WHITELIST", "")
            self.whitelist = set(env_ips.split(",")) if env_ips else DEFAULT_WHITELIST
        
        # Clear cache when whitelist changes
        self.is_whitelisted.cache_clear()
        logging.info(f"IP whitelist updated: {self.whitelist}")
    
    @lru_cache(maxsize=1024)
    def is_whitelisted(self, ip: str) -> bool:
        """
        Check if IP is whitelisted (with caching)
        """
        result = self._check_whitelist(ip)
        logging.info(f"IP check - {ip}: {'ALLOWED' if result else 'DENIED'}")
        return result
    
    def _check_whitelist(self, ip: str) -> bool:
        """Internal whitelist check logic"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for ip_range in self.whitelist:
                if "/" in ip_range:  # CIDR notation
                    if ip_obj in ipaddress.ip_network(ip_range):
                        return True
                elif ip == ip_range:  # Exact match
                    return True
        except ValueError as e:
            logging.error(f"Invalid IP address {ip}: {str(e)}")
        return False

# Global instance for easy dependency injection
ip_whitelist = IPWhitelist()

from fastapi import Request

def verify_ip_whitelisted(request: Request) -> bool:
    """
    FastAPI dependency to check if the requester's IP is whitelisted.
    Usage: ip_whitelisted: bool = Depends(verify_ip_whitelisted)
    """
    ip = request.client.host if request.client else None
    return ip_whitelist.is_whitelisted(ip) if ip else False
