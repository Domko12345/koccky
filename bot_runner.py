"""JSON-lines protocol worker. This file MUST run only inside the Docker sandbox.

The parent server controls which Python file is mounted into this container.
The worker does NOT attempt to sandbox Python; the container is the security
boundary. Bot stdout/stderr cannot be used as the normal protocol channel.
"""
import importlib.util
import json
import os
import sys

_MAX_OUTPUT_BYTES = 4096
_protocol_stdout = sys.stdout

# Keep routine bot print() and exceptions out of the protocol and Docker logs.
# A malicious bot may still write to fd 1; the parent validates/bounds output.
sys.stdout = open(os.devnull, "w", encoding="utf-8")
sys.stderr = open(os.devnull, "w", encoding="utf-8")


def send(data):
    try:
        encoded = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            raise ValueError("Oversized response")
    except (TypeError, ValueError, RecursionError):
        encoded = '{"error":"Invalid bot response"}'
    _protocol_stdout.write(encoded + "\n")
    _protocol_stdout.flush()


def main():
    if len(sys.argv) != 2 or sys.argv[1] != "/sandbox/bot.py":
        send({"error": "Invalid bot path"})
        return 2

    try:
        spec = importlib.util.spec_from_file_location("participant_bot", sys.argv[1])
        if spec is None or spec.loader is None:
            raise ImportError("Unable to load bot")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not callable(getattr(module, "decide", None)):
            raise ValueError("Bot must define decide(state)")
    except Exception as exc:
        send({"error": "Bot import failed: " + type(exc).__name__})
        return 1

    send({"status": "ready"})

    for line in sys.stdin:
        try:
            state = json.loads(line)
            response = module.decide(state)
            send(response)
        except Exception as exc:
            send({"error": type(exc).__name__ + ": " + str(exc)[:120]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
