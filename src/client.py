import socket
import random
import os
import sys
import threading
import tty
import termios
import select
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HOST = 'localhost'
PORT = 12345


def create_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"Connected to server at {HOST}:{PORT}")
    return client_socket


def handshake(client_socket):
    # Receive DH parameters from server
    params_length = int.from_bytes(
        recv_exact(client_socket, 4), byteorder='big')
    serialized_parameters = recv_exact(client_socket, params_length)
    parameters = serialization.load_pem_parameters(serialized_parameters)

    # Generate client key pair using server's parameters
    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()

    # Receive server's public key
    pubkey_length = int.from_bytes(
        recv_exact(client_socket, 4), byteorder='big')
    server_public_key_serialized = recv_exact(client_socket, pubkey_length)
    print(
        f"Received server public key ({len(server_public_key_serialized)} bytes)")

    server_public_key = serialization.load_pem_public_key(
        server_public_key_serialized)

    # Send client's public key to server
    serialized_client_public_key = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(
        len(serialized_client_public_key).to_bytes(4, byteorder='big'))
    client_socket.sendall(serialized_client_public_key)

    # Compute shared key with SERVER's public key
    shared_key = client_private_key.exchange(server_public_key)

    print(f"Client's raw shared key: {len(shared_key)} bytes")

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print(f"Client's derived shared key: {len(derived_key)} bytes")

    # Send random data for signature
    random_data = random.randbytes(32)
    client_socket.sendall(len(random_data).to_bytes(4, byteorder='big'))
    client_socket.sendall(random_data)

    # Receive random data from server
    random_data_length = int.from_bytes(
        recv_exact(client_socket, 4), byteorder='big')
    random_data_server = recv_exact(client_socket, random_data_length)

    # Hash the random data from client and server together
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(random_data)
    hasher.update(random_data_server)
    signature_data = hasher.finalize()

    # receive public key bytes

    sign_public_key_length = int.from_bytes(
        recv_exact(client_socket, 4), byteorder='big')
    print(
        f"Expecting signature public key of length: {sign_public_key_length} bytes")
    sign_public_key = recv_exact(client_socket, sign_public_key_length)

    print(
        f"Received signature public key ({len(sign_public_key)} bytes)")

    # receive signature

    signature_length = int.from_bytes(
        recv_exact(client_socket, 4), byteorder='big')
    signature = recv_exact(client_socket, signature_length)

    # Validate the signature

    try:
        pem_sign_public_key = serialization.load_pem_public_key(
            sign_public_key)
        pem_sign_public_key.verify(
            signature,
            signature_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
        return derived_key
    except Exception as e:
        print(f"Signature verification failed: {e}")


def send_command(client_socket, command, encryptor):
    # Encrypt the command with derived_key
    msg = encryptor.update(command)

    client_socket.sendall(len(msg).to_bytes(4, byteorder='big'))
    client_socket.sendall(msg)


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def start_interactive_shell(client_socket, derived_key):
    old_settings = termios.tcgetattr(sys.stdin)

    enc_nonce = b'\x00' * 15 + b'\x02'
    dec_nonce = b'\x00' * 15 + b'\x01'
    encryptor = Cipher(algorithms.AES(derived_key), modes.CTR(
        enc_nonce), backend=default_backend()).encryptor()
    decryptor = Cipher(algorithms.AES(derived_key), modes.CTR(
        dec_nonce), backend=default_backend()).decryptor()

    def recv_loop():
        while True:
            try:
                length = int.from_bytes(recv_exact(
                    client_socket, 4), byteorder='big')
                if length == 0:
                    break
                data = recv_exact(client_socket, length)
                output = decryptor.update(data)
                sys.stdout.buffer.write(output) 
                sys.stdout.buffer.flush()
            except Exception:
                break

    try:
        tty.setraw(sys.stdin.fileno())
        threading.Thread(target=recv_loop, daemon=True).start()

        while True:
            r, _, _ = select.select([sys.stdin], [], [])
            if r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                msg = encryptor.update(data)
                client_socket.sendall(len(msg).to_bytes(4, byteorder='big'))
                client_socket.sendall(msg)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)


def run_client():
    client_socket = create_client()
    derived_key = handshake(client_socket)
    start_interactive_shell(client_socket, derived_key)
    client_socket.close()


if __name__ == "__main__":
    run_client()
