import unittest
import requests
import json

class TestMyServer(unittest.TestCase):
    BASE_URL = "http://localhost:8080"

    def test_jwks_endpoint(self):
        jwks_response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(jwks_response.status_code, 200)
        jwks_result = jwks_response.json()
        self.assertIn("keys", jwks_result)

    def test_invalid_method(self):
            # Sending a request with an invalid HTTP method 
        response = requests.put(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 405)

    def test_invalid_json_payload(self):
        # Sending a POST request with an invalid JSON payload
        response = requests.post(f"{self.BASE_URL}/register", data="invalid_data")
        self.assertEqual(response.status_code, 405)

    
  

if __name__ == "__main__":
    unittest.main()
