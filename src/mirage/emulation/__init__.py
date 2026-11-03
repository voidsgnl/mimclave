"""Safe, non-forwarding protocol simulation primitives."""

from mirage.emulation.http import HttpDecoy, HttpRequest, HttpResponse, RequestError

__all__ = ["HttpDecoy", "HttpRequest", "HttpResponse", "RequestError"]
