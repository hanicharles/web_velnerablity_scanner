import unittest
from unittest.mock import patch, MagicMock
from web_scanner.stage1 import get_ip_address, get_http_headers, check_robots_txt
from web_scanner.stage3 import check_missing_headers_vuln

class TestWebScanner(unittest.TestCase):

    @patch('socket.gethostbyname')
    def test_get_ip_address(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "1.2.3.4"
        ip = get_ip_address("example.com")
        self.assertEqual(ip, "1.2.3.4")

    @patch('requests.head')
    def test_get_http_headers(self, mock_head):
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'TestServer'}
        mock_head.return_value = mock_response
        headers = get_http_headers("http://example.com")
        self.assertEqual(headers['Server'], 'TestServer')

    @patch('requests.get')
    def test_check_robots_txt(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        result = check_robots_txt("http://example.com")
        self.assertEqual(result, "Found")

    def test_check_missing_headers_vuln(self):
        headers = {'Content-Type': 'text/html'} # Missing security headers
        vulns = check_missing_headers_vuln(headers)
        self.assertTrue(len(vulns) > 0)
        self.assertIn("Missing Security Header: X-Frame-Options", vulns)

if __name__ == '__main__':
    unittest.main()
