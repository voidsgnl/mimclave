"""Opt-in, loopback-only protocol transport adapters."""

from mirage.transport.http_server import HttpDecoyServer, HttpsDecoyServer
from mirage.transport.ssh_server import SSHDecoyServer

__all__ = ["HttpDecoyServer", "HttpsDecoyServer", "SSHDecoyServer"]
