"""Read-only host service discovery."""

from mirage.discovery.ports import Listener, discover_proc_listeners, parse_proc_net_table

__all__ = ["Listener", "discover_proc_listeners", "parse_proc_net_table"]
