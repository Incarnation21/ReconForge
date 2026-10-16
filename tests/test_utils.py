"""
Tests for ReconForge utility functions (network, wordlist, parse).
"""
import pytest
from reconforge.utils.net import is_ip, is_private_ip, expand_cidr, format_endpoint
from reconforge.utils.parse import extract_html_title, clean_hostname, parse_target_uri
from reconforge.utils.wordlist import load_wordlist


def test_is_ip():
    assert is_ip("192.168.1.1")
    assert is_ip("8.8.8.8")
    assert is_ip("::1")
    assert not is_ip("example.com")


def test_is_private_ip():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("172.16.0.1")
    assert is_private_ip("127.0.0.1")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("1.1.1.1")


def test_expand_cidr():
    hosts = expand_cidr("192.168.1.0/30", max_hosts=10)
    assert len(hosts) == 2
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts


def test_format_endpoint():
    assert format_endpoint("example.com", 80, "http") == "http://example.com"
    assert format_endpoint("example.com", 443, "https") == "https://example.com"
    assert format_endpoint("example.com", 8080, "http") == "http://example.com:8080"


def test_extract_html_title():
    html_doc = "<html><head><title>  Security Assessment Portal  </title></head></html>"
    assert extract_html_title(html_doc) == "Security Assessment Portal"


def test_clean_hostname():
    assert clean_hostname("*.example.com.") == "example.com"
    assert clean_hostname("SUB.EXAMPLE.COM.") == "sub.example.com"


def test_parse_target_uri():
    host, port, scheme = parse_target_uri("https://example.com:8443/login")
    assert host == "example.com"
    assert port == 8443
    assert scheme == "https"

    host2, port2, scheme2 = parse_target_uri("10.0.0.1:8080")
    assert host2 == "10.0.0.1"
    assert port2 == 8080


def test_load_wordlist_fallback():
    words = load_wordlist(None, fallback=["admin", "login"])
    assert words == ["admin", "login"]
