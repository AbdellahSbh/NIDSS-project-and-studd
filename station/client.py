import json
import socket

from .alert_manager import build_alert_data
from .secure_channel import SecureChannel


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

    message = data.decode("utf-8").strip()
    if not message:
        return None

    return json.loads(message)


class AlertClient:
    # keep the server address and the shared secret together
    def __init__(self, host, port, shared_secret):
        self.host = host
        self.port = port
        self.channel = SecureChannel(shared_secret)

    # connect and do the authentication step
    def connect(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.host, self.port))
        reader = client.makefile("rb")
        writer = client.makefile("wb")

        first_message = read_json(reader)
        if not first_message:
            raise RuntimeError("no response from alert server")

        challenge = first_message["challenge"]
        response = self.channel.answer_challenge(challenge)
        send_json(writer, {"type": "auth", "response": response})

        auth_reply = read_json(reader)
        if not auth_reply or auth_reply.get("type") != "ok":
            raise RuntimeError("alert server authentication failed")

        return client, reader, writer

    # send one alert securely to the server
    def send_alert(self, alert):
        client = None
        reader = None
        writer = None

        try:
            client, reader, writer = self.connect()
            alert_data = build_alert_data(alert)
            encrypted_alert = self.channel.encrypt_message(alert_data)
            send_json(writer, {"type": "alert", "payload": encrypted_alert})
            reply = read_json(reader)
            return reply
        except Exception as error:
            print("could not send secure alert:", error)
            return None
        finally:
            if writer:
                try:
                    send_json(writer, {"type": "quit"})
                except Exception:
                    pass
                writer.close()
            if reader:
                reader.close()
            if client:
                client.close()
