"""Bound both compressed wire bytes and decoded bytes before allocating a body."""

import zlib


async def bounded_body(response, limit):
    if int(response.headers.get("content-length", "0")) > limit:
        raise ValueError("response content length exceeds limit")
    encoding = response.headers.get("content-encoding", "identity").lower()
    if encoding not in {"identity", "gzip", "deflate", ""}:
        raise ValueError("unsupported response encoding")
    decoder = (
        zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
        if encoding in {"gzip", "deflate"}
        else None
    )
    wire, size = 0, 0
    try:
        async for chunk in response.aiter_raw(chunk_size=65536):
            wire += len(chunk)
            if wire > limit:
                raise ValueError("response wire body exceeds limit")
            decoded = decoder.decompress(chunk, limit - size + 1) if decoder else chunk
            size += len(decoded)
            if size > limit or decoder and decoder.unconsumed_tail:
                raise ValueError("response decoded body exceeds limit")
            yield decoded
        if decoder:
            decoded = decoder.flush(limit - size + 1)
            if size + len(decoded) > limit or not decoder.eof or decoder.unused_data:
                raise ValueError("invalid compressed response")
            yield decoded
    except zlib.error as exc:
        raise ValueError("invalid compressed response") from exc
