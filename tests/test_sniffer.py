import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sniffer import redact_ip, redact_payload

# ── Test IP redaction ────────────────────────────────────────
def test_redact_ip_basic():
    result = redact_ip("192.168.1.105")
    assert result == "192.168.1.xxx", f"Expected 192.168.1.xxx but got {result}"
    print("PASS: test_redact_ip_basic")

def test_redact_ip_different_address():
    result = redact_ip("10.0.0.1")
    assert result == "10.0.0.xxx", f"Expected 10.0.0.xxx but got {result}"
    print("PASS: test_redact_ip_different_address")

# ── Test payload redaction ───────────────────────────────────
def test_redact_authorization():
    payload = "GET / HTTP/1.1\nAuthorization: Bearer abc123token"
    result = redact_payload(payload)
    assert "abc123token" not in result
    assert "[REDACTED]" in result
    print("PASS: test_redact_authorization")

def test_redact_cookie():
    payload = "GET / HTTP/1.1\nCookie: session=xyz789"
    result = redact_payload(payload)
    assert "xyz789" not in result
    assert "[REDACTED]" in result
    print("PASS: test_redact_cookie")

def test_redact_email():
    payload = "user=john.doe@example.com&action=login"
    result = redact_payload(payload)
    assert "john.doe@example.com" not in result
    assert "[REDACTED_EMAIL]" in result
    print("PASS: test_redact_email")

def test_redact_password():
    payload = "username=john&password=supersecret123"
    result = redact_payload(payload)
    assert "supersecret123" not in result
    assert "[REDACTED]" in result
    print("PASS: test_redact_password")

# ── Run all tests ────────────────────────────────────────────
if __name__ == "__main__":
    test_redact_ip_basic()
    test_redact_ip_different_address()
    test_redact_authorization()
    test_redact_cookie()
    test_redact_email()
    test_redact_password()
    print("\nAll tests passed!")
    