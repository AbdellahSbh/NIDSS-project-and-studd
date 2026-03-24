import base64
import hashlib
import hmac
import json
import os

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    AES = None
    PBKDF2 = None


class SecureChannel:
    # store the shared secret once when the object is created
    # convert it to bytes because crypto functions expect bytes
    # keep this class small so it is easier to explain
    # the same object can be reused for several messages
    def __init__(self, shared_secret):
        self.shared_secret = shared_secret.encode("utf-8")

    # create a random challenge for the client
    # encode it with base64 so it can be sent as normal text
    # this challenge changes every time the client connects
    # the client must answer it correctly before continuing
    def make_challenge(self):
        return base64.b64encode(os.urandom(16)).decode("ascii")

    # build the expected response for one challenge
    # use HMAC-SHA256 so the secret is not sent directly
    # encode the result with base64 for easy transport in JSON
    # both client and server can run the same calculation
    def answer_challenge(self, challenge):
        digest = hmac.new(self.shared_secret, challenge.encode("utf-8"), hashlib.sha256).digest()
        return base64.b64encode(digest).decode("ascii")

    # compare the client response with the expected one
    # use compare_digest because it is safer for secret checks
    # return True when the challenge response is correct
    # return False when the client used the wrong secret
    def check_challenge(self, challenge, response):
        expected = self.answer_challenge(challenge)
        return hmac.compare_digest(expected, response)

    # derive one AES key from the shared secret and a random salt
    # PBKDF2 makes the final key harder to guess directly
    # the salt changes per message so the key material is different each time
    # if pycryptodome is missing, stop here with a clear error
    def make_key(self, salt):
        if PBKDF2 is None:
            raise RuntimeError("pycryptodome is required for encrypted messages")

        full_key = PBKDF2(self.shared_secret, salt, dkLen=32, count=100000)
        return full_key

    # turn a normal dictionary into encrypted data
    # generate a random salt and nonce for this message
    # use AES-GCM so the message is encrypted and checked for tampering
    # return a JSON-friendly dictionary with base64 text fields
    def encrypt_message(self, data):
        if AES is None:
            raise RuntimeError("pycryptodome is required for encrypted messages")

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self.make_key(salt)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        encrypted_data, tag = cipher.encrypt_and_digest(json.dumps(data).encode("utf-8"))

        return {
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "data": base64.b64encode(encrypted_data).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }

    # take an encrypted message and turn it back into normal data
    # decode every base64 field back into bytes first
    # rebuild the same key using the saved salt
    # if the tag check fails, the message is invalid or changed
    def decrypt_message(self, encrypted_message):
        if AES is None:
            raise RuntimeError("pycryptodome is required for encrypted messages")

        salt = base64.b64decode(encrypted_message["salt"])
        nonce = base64.b64decode(encrypted_message["nonce"])
        encrypted_data = base64.b64decode(encrypted_message["data"])
        tag = base64.b64decode(encrypted_message["tag"])
        key = self.make_key(salt)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plain_text = cipher.decrypt_and_verify(encrypted_data, tag)
        return json.loads(plain_text.decode("utf-8"))
