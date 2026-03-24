import json
import socket
import threading

from .config import load_settings
from .secure_channel import SecureChannel


# send one json message to the client
def send_json(writer, data):
    message = json.dumps(data) + "\n"
    writer.write(message.encode("utf-8"))
    writer.flush()


# read one json message from the client
def read_json(reader):
    data = reader.readline()
    if not data:
        return None

    message = data.decode("utf-8").strip()
    if not message:
        return None

    try:
        return json.loads(message)
    except json.JSONDecodeError:
        return None


# handle one connected alert client
def handle_client(conn, addr, settings):
    channel = SecureChannel(settings["shared_secret"])
    reader = conn.makefile("rb")
    writer = conn.makefile("wb")
    print("alert client connected:", addr)

    try:
        challenge = channel.make_challenge()
        send_json(writer, {"type": "challenge", "challenge": challenge})

        reply = read_json(reader)
        if not reply or reply.get("type") != "auth":
            send_json(writer, {"type": "error", "message": "authentication failed"})
            return

        if not channel.check_challenge(challenge, str(reply.get("response", ""))):
            send_json(writer, {"type": "error", "message": "wrong secret"})
            return

        send_json(writer, {"type": "ok", "message": "client authenticated"})

        while True:
            request = read_json(reader)
            if not request:
                break

            if request.get("type") == "ping":
                send_json(writer, {"type": "pong"})

            elif request.get("type") == "alert":
                try:
                    alert_data = channel.decrypt_message(request["payload"])
                    print("[SERVER ALERT]", alert_data["type"], "-", alert_data["message"])
                    send_json(writer, {"type": "ok", "message": "alert received"})
                except Exception as error:
                    send_json(writer, {"type": "error", "message": str(error)})

            elif request.get("type") == "quit":
                send_json(writer, {"type": "bye"})
                break

            else:
                send_json(writer, {"type": "error", "message": "unknown request"})

    finally:
        reader.close()
        writer.close()
        conn.close()
        print("alert client disconnected:", addr)


# start the separate alert receiver server
def start_server(settings):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((settings["host"], settings["port"]))
    server.listen(5)

    print("alert server started on", settings["host"] + ":" + str(settings["port"]))
    print("waiting for alert clients...")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr, settings))
        thread.daemon = True
        thread.start()


# run this file as the separate server process
def main():
    settings = load_settings()
    start_server(settings)


if __name__ == "__main__":
    main()
