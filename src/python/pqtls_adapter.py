import subprocess
import json
import os
import sys
import config

class PQTLSAdapter:
    """
    Adapter to perform onboarding operations over Post-Quantum TLS
    using the PQ SDK client binary.
    """
    def __init__(self):
        self.server_ip = config.PQTLS_SERVER_IP
        self.server_port = config.PQTLS_SERVER_PORT
        self.client_binary = os.path.join(config.PQ_SDK_BUILD_PATH, "piqaso_client")
        self.temp_config = "pqtls_config.json"
        self.temp_input = "pqtls_input.txt"
        self.temp_output = "pqtls_output.txt"

    def _prepare_client_config(self):
        """Creates the config.json required by piqaso_client"""
        cfg = {
            "pq_tls_ip": self.server_ip,
            "pq_tls_port": self.server_port
        }
        with open(self.temp_config, 'w') as f:
            json.dump(cfg, f)

    def send_request(self, operation, mac_address, secret=None):
        """
        Sends an onboarding request over PQTLS.
        """
        if not os.path.exists(self.client_binary):
            return {"status": "error", "message": f"PQTLS Client binary not found at {self.client_binary}"}

        # Prepare payload
        payload = {
            "operation": operation,
            "macAddress": mac_address
        }
        if secret:
            payload["secret"] = secret

        # Write payload to temp file
        with open(self.temp_input, 'w') as f:
            f.write(json.dumps(payload))

        # Prepare client config
        self._prepare_client_config()

        try:
            # Execute the C client
            # Usage: piqaso_client <config.json> <input_file> <output_file>
            result = subprocess.run(
                [self.client_binary, self.temp_config, self.temp_input, self.temp_output],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {
                    "status": "error", 
                    "message": f"PQTLS handhake failed (code {result.returncode})",
                    "stderr": result.stderr
                }

            # Read result from output file
            if os.path.exists(self.temp_output):
                with open(self.temp_output, 'r') as f:
                    response_text = f.read()
                
                # The server bridge is expected to return JSON over the PQTLS channel
                try:
                    # Look for the internal JSON if the client binary adds headers
                    if "ACK:" in response_text:
                        # Extract the actual data if needed, or assume the bridge returns pure JSON
                        # For now we assume the bridge returns a JSON response string
                        return json.loads(response_text.split("ACK:")[1].strip())
                    return json.loads(response_text)
                except:
                    return {"status": "success", "raw_response": response_text}
            
            return {"status": "error", "message": "No output from PQTLS client"}

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "PQTLS request timed out"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            # Clean up temp files
            for f in [self.temp_config, self.temp_input, self.temp_output]:
                if os.path.exists(f):
                    os.remove(f)

    def register(self, mac_address):
        return self.send_request("register", mac_address)

    def get_credentials(self, mac_address, secret):
        return self.send_request("getCredentials", mac_address, secret)
