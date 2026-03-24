import base64
import hashlib
import hmac
import json
import os
import socket

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    AES = None
    PBKDF2 = None


server_host = os.getenv("ALERT_SERVER_CONNECT_HOST", "station")
server_port = int(os.getenv("ALERT_SERVER_CONNECT_PORT", "9001"))
shared_secret = os.getenv("STATION_SHARED_SECRET", "scc439-station-secret")


# send one json message to the server
def send_json(writer, data):
    message = json.dumps(data) + "\n"
    writer.write(message.encode("utf-8"))
    writer.flush()


# read one json reply from the server
def read_json(reader):
    data = reader.readline()
    if not data:
        return None

    return json.loads(data.decode("utf-8").strip())


# build one simple test alert locally
def make_test_alert():
    alert = {
        "time": "2026-03-12T00:00:00+00:00",
        "level": "high",
        "type": "udp_dos",
        "message": "test secure alert from tester container",
        "packet": {
            "time": "2026-03-12T00:00:00+00:00",
            "src_ip": "10.0.0.10",
            "dst_ip": "10.0.0.20",
            "protocol": "UDP",
            "src_port": 12345,
            "dst_port": 9999,
            "tcp_flags": "",
            "length": 128,
            "summary": "test packet",
            "extra": {},
        },
    }
    return alert


# answer the challenge exactly like the server expects
def answer_challenge(challenge, secret_text):
    digest = hmac.new(
        secret_text.encode("utf-8"),
        challenge.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


# build the same aes key format used by the server side
def make_key(secret_text, salt):
    if PBKDF2 is None:
        raise RuntimeError("pycryptodome is required for encrypted messages")

    return PBKDF2(secret_text.encode("utf-8"), salt, dkLen=32, count=100000)


# encrypt the alert in the same format expected by the server
def encrypt_message(data, secret_text):
    if AES is None:
        raise RuntimeError("pycryptodome is required for encrypted messages")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = make_key(secret_text, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    encrypted_data, tag = cipher.encrypt_and_digest(json.dumps(data).encode("utf-8"))

    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "data": base64.b64encode(encrypted_data).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


# connect, authenticate, send one alert, and print replies
def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_host, server_port))
    reader = client.makefile("rb")
    writer = client.makefile("wb")

    try:
        first_message = read_json(reader)
        if not first_message:
            print("no response from server")
            return

        challenge = first_message["challenge"]
        response = answer_challenge(challenge, shared_secret)
        send_json(writer, {"type": "auth", "response": response})

        auth_reply = read_json(reader)
        print("auth reply:", auth_reply)
        if not auth_reply or auth_reply.get("type") != "ok":
            return

        alert = make_test_alert()
        encrypted_alert = encrypt_message(alert, shared_secret)
        print("sending alert:", alert)
        send_json(writer, {"type": "alert", "payload": encrypted_alert})

        reply = read_json(reader)
        print("server reply:", reply)

        send_json(writer, {"type": "quit"})
        print("quit reply:", read_json(reader))
    finally:
        reader.close()
        writer.close()
        client.close()


if __name__ == "__main__":
    main()
