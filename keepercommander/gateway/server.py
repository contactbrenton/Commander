from typing import Optional

import threading

import websocket

from .. import crypto, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage


class GatewayServer:
    def __init__(self, client_id=None, private_key=None):
        self.client_id = None      # type: Optional[bytes]
        self.private_key = None    # type: Optional[EllipticCurvePrivateKey]
        if isinstance(client_id, str):
            self.client_id = utils.base64_url_decode(client_id)
        elif isinstance(client_id, bytes):
            self.client_id = client_id
        if isinstance(private_key, str):
            self.private_key = crypto.load_ec_private_key(utils.base64_url_decode(private_key))
        elif isinstance(private_key, EllipticCurvePrivateKey):
            self.private_key = private_key

        self._thread = None    # type: Optional[threading.Thread]
        self._ws_app = None    # type: Optional[websocket.WebSocketApp]

    def thread_main(self, ws_app):
        try:
            ws_app.run_forever()
        except:
            if self._ws_app:
                self._ws_app.close()
            self._ws_app = None

    def on_open(self, ws_app):
        if self._ws_app != ws_app:
            self._ws_app = ws_app

    def on_data(self, ws_app, data, data_type, continue_flag):
        pass

    def on_error(self, ws_app, error):
        if self._ws_app == ws_app:
            self._ws_app.close()
            self._ws_app = None

    def on_close(self, ws_app, close_code, close_message):
        if self._ws_app == ws_app:
            self._ws_app.close()
            self._ws_app = None

    def start(self, url):
        self.shutdown()
        ws_app = websocket.WebSocketApp(
            url, on_open=self.on_open, on_data=self.on_data, on_error=self.on_error, on_close=self.on_close)
        ws_app.header = {
            'Authentication': utils.base64_url_encode(self.client_id)
        }
        self._thread = threading.Thread(target=self.thread_main, args=(ws_app,), daemon=True)
        self._thread.start()

    def shutdown(self):
        if self._thread:
            if not self._thread.is_alive():
                self._thread = None
        if self._ws_app:
            self._ws_app.close()
            if self._thread:
                try:
                    self._thread.join(3)
                except:
                    pass
                self._thread = None
            self._ws_app = None
