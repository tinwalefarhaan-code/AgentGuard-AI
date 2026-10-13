"""Comprehensive Unit & Regression Tests for the AgentGuard AI URL Threat Engine.

Covers:
1. Safe ordinary web URLs
2. Legitimate URLs containing authentication keywords (login, verify, account, signin)
3. Suspicious synthetic phishing and brand impersonation URLs
4. Direct IP-based URLs (IPv4, IPv6, Hexadecimal, Decimal DWORD, Octal)
5. Obfuscated and percent-encoded URLs (null bytes, double encoding, encoded separators)
6. Dangerous schemes (javascript:, data:, file:)
7. Suspicious open redirect query parameters
8. URL shorteners
9. Executable and archive payload downloads
10. Malformed input edge cases
"""

from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_engine import scan_url


class SafeAndLegitimateUrlTests(unittest.TestCase):
    """Verify that ordinary and legitimate websites are ALLOWED with zero or low risk."""

    def test_ordinary_safe_urls(self):
        urls = [
            "https://www.google.com",
            "https://github.com/tinwalefarhaan-code/AgentGuard-AI",
            "https://en.wikipedia.org/wiki/Computer_security",
            "https://python.org/doc",
            "https://stackoverflow.com/questions",
            "https://cloudflare.com",
        ]
        for url in urls:
            with self.subTest(url=url):
                res = scan_url(url)
                self.assertEqual(res["decision"], "ALLOW")
                self.assertLessEqual(res["risk_score"], 20)
                self.assertEqual(res["threats"], [])

    def test_legitimate_urls_with_login_and_verify_keywords(self):
        """CRITICAL: Ensure legitimate domains are NOT blocked for using 'login', 'verify', or 'account'."""
        legit_auth_urls = [
            "https://accounts.google.com/signin/v2/identifier",
            "https://github.com/login",
            "https://www.paypal.com/signin",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://auth.chase.com/verify",
            "https://appleid.apple.com/sign-in",
            "https://www.amazon.com/ap/signin",
            "https://www.netflix.com/login",
            "https://www.bankofamerica.com/login/sign-in/signOnV2Screen.go",
        ]
        for url in legit_auth_urls:
            with self.subTest(url=url):
                res = scan_url(url)
                self.assertEqual(
                    res["decision"],
                    "ALLOW",
                    f"False positive on legitimate URL: {url} (decision={res['decision']}, score={res['risk_score']}, threats={res['threats']})",
                )
                self.assertLessEqual(res["risk_score"], 20)
                self.assertNotIn("Credential Phishing Path Indicator", res["threats"])
                self.assertNotIn("Potential Brand Impersonation", res["threats"])


class PhishingAndBrandImpersonationTests(unittest.TestCase):
    """Verify detection of brand lookalikes, spoofing, and scam lures."""

    def test_paypal_brand_spoofing_with_phish_path(self):
        url = "http://paypal-security-update.account-verification.xyz/login"
        res = scan_url(url)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertGreaterEqual(res["risk_score"], 75)
        self.assertIn("Potential Brand Impersonation", res["threats"])
        self.assertIn("Suspicious / High-Abuse TLD", res["threats"])
        self.assertIn("Compound Phishing Signature", res["threats"])

    def test_chase_bank_lookalike_domain(self):
        url = "http://chase-online-banking.verify-user.top/auth"
        res = scan_url(url)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertIn("Potential Brand Impersonation", res["threats"])

    def test_delivery_smishing_lure_domain(self):
        url = "http://usps-parcel-redelivery.track-package.club/customs-fee"
        res = scan_url(url)
        self.assertIn(res["decision"], ("BLOCK", "REVIEW"))
        self.assertIn("Potential Brand Impersonation", res["threats"])

    def test_brand_in_subdomain_of_foreign_apex(self):
        url = "https://apple.com.security-verification.badsite.net/restore"
        res = scan_url(url)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertIn("Potential Brand Impersonation", res["threats"])

    def test_deceptive_userinfo_authority_spoofing(self):
        url = "https://support.apple.com@evil-phish.net/login"
        res = scan_url(url)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertIn("Embedded Credentials / Authority Spoofing", res["threats"])
        self.assertIn("Deceptive Authority Brand Spoofing", res["threats"])


class IpBasedUrlTests(unittest.TestCase):
    """Verify detection of public, private, and obfuscated numeric IP hosts."""

    def test_direct_ipv4_with_executable(self):
        url = "http://192.168.1.50:8080/invoices/document.pdf.exe"
        res = scan_url(url)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertIn("Direct IP Hostname", res["threats"])
        self.assertIn("Executable / Dangerous File Payload", res["threats"])

    def test_direct_public_ipv4(self):
        url = "http://45.33.32.156/admin"
        res = scan_url(url)
        self.assertIn("Direct IP Hostname", res["threats"])
        self.assertGreaterEqual(res["risk_score"], 30)

    def test_ipv6_literal(self):
        url = "http://[::1]:8080/dashboard"
        res = scan_url(url)
        self.assertIn("Direct IP Hostname", res["threats"])

    def test_hexadecimal_ip_obfuscation(self):
        # 0x7f000001 is 127.0.0.1
        url = "http://0x7f000001/login"
        res = scan_url(url)
        self.assertIn("Direct IP Hostname", res["threats"])

    def test_decimal_dword_ip_obfuscation(self):
        # 2130706433 is 127.0.0.1
        url = "http://2130706433/malicious"
        res = scan_url(url)
        self.assertIn("Direct IP Hostname", res["threats"])


class ObfuscationAndEncodingTests(unittest.TestCase):
    """Verify detection of encoding anomalies, evasion, and shorteners."""

    def test_null_byte_injection(self):
        url = "http://example.com/safe%00.exe"
        res = scan_url(url)
        self.assertIn("Encoding / Evasion Anomaly", res["threats"])
        self.assertTrue(any("null byte" in ind for ind in res["indicators"]))

    def test_double_percent_encoding(self):
        url = "http://example.com/path%252e%252e/admin"
        res = scan_url(url)
        self.assertIn("Encoding / Evasion Anomaly", res["threats"])

    def test_url_shorteners(self):
        short_urls = [
            "https://bit.ly/3xYzA1",
            "http://tinyurl.com/fake-login",
            "https://t.co/xyz123",
            "https://is.gd/update",
        ]
        for url in short_urls:
            with self.subTest(url=url):
                res = scan_url(url)
                self.assertEqual(res["decision"], "REVIEW")
                self.assertIn("Obfuscated / Shortened URL", res["threats"])
                self.assertGreaterEqual(res["risk_score"], 30)


class DangerousSchemesAndMalformedTests(unittest.TestCase):
    """Verify non-web schemes and malformed syntax are handled safely."""

    def test_javascript_scheme_instant_block(self):
        res = scan_url("javascript:alert(document.cookie)")
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["risk_score"], 100)
        self.assertIn("Dangerous URI Scheme", res["threats"])

    def test_data_scheme_instant_block(self):
        res = scan_url("data:text/html,<script>alert(1)</script>")
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["risk_score"], 100)

    def test_file_scheme_instant_block(self):
        res = scan_url("file:///etc/passwd")
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["risk_score"], 100)

    def test_empty_string(self):
        res = scan_url("   ")
        self.assertEqual(res["decision"], "REVIEW")
        self.assertIn("Empty / Missing URL", res["threats"])


class OpenRedirectAndPayloadTests(unittest.TestCase):
    """Verify redirection parameters and suspicious file payloads."""

    def test_open_redirect_parameter(self):
        url = "https://example.com/login?redirect=https://evil-destination.com"
        res = scan_url(url)
        self.assertIn("Potential Open Redirect Parameter", res["threats"])
        self.assertGreaterEqual(res["risk_score"], 30)

    def test_archive_download_with_invoice_lure(self):
        url = "http://unverified-site.com/downloads/invoice_october.pdf.zip"
        res = scan_url(url)
        self.assertIn("Archive File Download with Lure Context", res["threats"])


if __name__ == "__main__":
    unittest.main()
