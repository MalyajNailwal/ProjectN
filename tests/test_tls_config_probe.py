import tempfile
import unittest
from pathlib import Path

from app.tls_config_probe import parse_tls_xml


class TlsConfigTests(unittest.TestCase):
    def test_nmap_script_versions_and_weak_ciphers_are_evidence_based(self):
        xml = """<nmaprun><host><ports><port protocol="tcp" portid="443"><script id="ssl-enum-ciphers"><table key="TLSv1.0"><table key="ciphers"><table><elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem><elem key="strength">C</elem></table></table></table><table key="TLSv1.3"><table key="ciphers"><table><elem key="name">TLS_AES_128_GCM_SHA256</elem><elem key="strength">A</elem></table></table></table></script></port></ports></host></nmaprun>"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nmap.xml"
            path.write_text(xml)
            found, details = parse_tls_xml(path, "example.test", 443)
        self.assertEqual(details["observed"], 2)
        self.assertEqual({item["rule"] for item in found}, {"tls:protocol:TLSv1.0", "tls:weak-ciphers:TLSv1.0"})


if __name__ == "__main__":
    unittest.main()
