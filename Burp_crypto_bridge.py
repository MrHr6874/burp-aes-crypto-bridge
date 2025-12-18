from burp import IBurpExtender, IHttpListener
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from java.util import Base64
import json

# =========================
# CRYPTO CONFIG
# NOTE:
# These values must be replaced with keys extracted
# during authorized security testing only.
# =========================
SECRET_KEY = "CHANGE_ME_SECRET_KEY"
IV = "CHANGE_ME_IV_16_BYTES"

KEY_BYTES = SECRET_KEY[:32].encode("utf-8")
IV_BYTES = IV.encode("utf-8")


def encrypt_payload(plaintext):
    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(
        Cipher.ENCRYPT_MODE,
        SecretKeySpec(KEY_BYTES, "AES"),
        IvParameterSpec(IV_BYTES)
    )
    encrypted = cipher.doFinal(plaintext.encode("utf-8"))
    return Base64.getEncoder().encodeToString(encrypted)


def decrypt_payload(ciphertext_b64):
    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(KEY_BYTES, "AES"),
        IvParameterSpec(IV_BYTES)
    )
    raw = Base64.getDecoder().decode(ciphertext_b64)
    decrypted = cipher.doFinal(raw)
    return decrypted.tostring()


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AES Crypto Bridge")
        callbacks.registerHttpListener(self)
        print("[+] AES Crypto Bridge loaded and running")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # Only Proxy traffic (on purpose)
        if toolFlag != self._callbacks.TOOL_PROXY:
            return

        helpers = self._helpers
        message = messageInfo.getRequest() if messageIsRequest else messageInfo.getResponse()
        info = helpers.analyzeRequest(messageInfo) if messageIsRequest else helpers.analyzeResponse(message)

        headers = info.getHeaders()
        url = info.getUrl()

        body_bytes = message[info.getBodyOffset():]
        body = helpers.bytesToString(body_bytes).strip()

        # Expect encrypted body like: "Base64Here=="
        if not body or not body.startswith('"') or not body.endswith('"'):
            return

        body = body[1:-1]  # remove surrounding quotes

        try:
            if messageIsRequest:
                decrypted = decrypt_payload(body)

                print("[>] URL:", url)
                print("[>] Decrypted request:", decrypted)

                # Parse + re-encrypt (allows mutation by Burp/sqlmap)
                data = json.loads(decrypted)
                plaintext = json.dumps(data, separators=(",", ":"))
                encrypted = encrypt_payload(plaintext)

                new_body = '"' + encrypted + '"'
                new_body_bytes = helpers.stringToBytes(new_body)
                new_message = helpers.buildHttpMessage(headers, new_body_bytes)

                messageInfo.setRequest(new_message)

            else:
                decrypted = decrypt_payload(body)

                print("[<] URL:", url)
                print("[<] Decrypted response:", decrypted)

                new_body_bytes = helpers.stringToBytes(decrypted)
                new_message = helpers.buildHttpMessage(headers, new_body_bytes)

                messageInfo.setResponse(new_message)

        except Exception as e:
            print("[!] Crypto bridge error:", e)
            return
