"""Opt-in, loopback-only protocol transport adapters."""

from mirage.transport.http_server import HttpDecoyServer, HttpsDecoyServer

__all__ = ["HttpDecoyServer", "HttpsDecoyServer"]
