from __future__ import annotations

from typing import Any, Dict, Optional


def _encode_remove_outbound_request(tag: str) -> bytes:
    """Minimal protobuf wire encoding for RemoveOutboundRequest { string tag = 1; }."""
    tag_bytes = tag.encode('utf-8')
    if len(tag_bytes) > 127:
        raise ValueError('tag too long')
    return bytes([0x0A, len(tag_bytes)]) + tag_bytes


def remove_outbound(tag: str, api_addr: str) -> bool:
    """Best-effort RemoveOutbound via gRPC; returns True if call succeeded."""
    try:
        import grpc
    except ImportError:
        return False

    host, _, port_s = api_addr.rpartition(':')
    if not host:
        host, port_s = '127.0.0.1', api_addr
    target = f'{host}:{port_s}'
    try:
        channel = grpc.insecure_channel(target)
        stub = channel.unary_unary(
            '/xray.app.proxyman.command.HandlerService/RemoveOutbound',
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        stub(_encode_remove_outbound_request(tag), timeout=3.0)
        channel.close()
        return True
    except Exception:
        try:
            channel.close()
        except Exception:
            pass
        return False


def add_outbound_from_config(outbound: Dict[str, Any], api_addr: str) -> bool:
    """AddOutbound via gRPC is protocol-specific; not implemented without full proto stubs."""
    return False
