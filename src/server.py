import os
import errno
import socket
import subprocess
import random
import pty
import select
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.backends import default_backend

PORT = 12345

# Generate DH parameters once
parameters = dh.generate_parameters(generator=2, key_size=2048)
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()

# Serialize the parameters and public key
serialized_parameters = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)
serialized_public_key = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


def create_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', PORT))
    server_socket.listen(1)
    print(f"Server is listening on port {PORT}...")
    return server_socket


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def handshake(conn):
    # Performs the SSH handshake with the client

    # Send DH parameters to client
    params_length = len(serialized_parameters)
    conn.sendall(params_length.to_bytes(4, byteorder='big'))
    conn.sendall(serialized_parameters)

    # Send server public key
    pubkey_length = len(serialized_public_key)
    conn.sendall(pubkey_length.to_bytes(4, byteorder='big'))
    conn.sendall(serialized_public_key)

    # Receive client public key
    client_pubkey_length = int.from_bytes(recv_exact(conn, 4), byteorder='big')
    client_public_key_serialized = recv_exact(conn, client_pubkey_length)
    client_public_key = serialization.load_pem_public_key(
        client_public_key_serialized)

    # Compute shared key with CLIENT's public key
    shared_key = server_private_key.exchange(client_public_key)

    print(f"Client's raw shared key: {len(shared_key)} bytes")

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print(f"Server's derived shared key: {derived_key.hex()}")

    # Receive random data for signature
    random_data_length = int.from_bytes(recv_exact(conn, 4), byteorder='big')
    random_data_client = recv_exact(conn, random_data_length)

    random_data_server = random.randbytes(32)

    conn.sendall(len(random_data_server).to_bytes(4, byteorder='big'))
    conn.sendall(random_data_server)

    # Hash the random data from client and server together
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(random_data_client)
    hasher.update(random_data_server)

    signature_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    signature_public_key = signature_private_key.public_key()

    signature = signature_private_key.sign(
        hasher.finalize(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())

    public_bytes = signature_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # send public bytes
    conn.sendall(len(public_bytes).to_bytes(4, byteorder='big'))
    conn.sendall(public_bytes)

    # send signature
    conn.sendall(len(signature).to_bytes(4, byteorder='big'))
    conn.sendall(signature)

    return derived_key


def setup_remote_shell():
    master_fd, slave_fd = pty.openpty()
    shell = subprocess.Popen(
        ["/bin/bash"],  # Use "bash" in linux
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True
    )

    os.close(slave_fd)

    return shell, master_fd


def handle_client_commands(conn, master_fd, encryptor, decryptor):
    while True:
        r, _, _ = select.select([conn, master_fd], [], [])

        if conn in r:
            length = int.from_bytes(recv_exact(conn, 4), byteorder='big')
            if length == 0:
                break
            crypt = recv_exact(conn, length)
            msg = decryptor.update(crypt)
            os.write(master_fd, msg)

        if master_fd in r:
            try:
                output = os.read(master_fd, 4096)
            except OSError as e:
                if e.errno == errno.EIO:
                    break
                raise
            if not output:
                break
            output_encrypted = encryptor.update(output)
            conn.sendall(len(output_encrypted).to_bytes(4, byteorder='big'))
            conn.sendall(output_encrypted)


def run_server():
    server_socket = create_server()
    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr} has been established.")
        derived_key = handshake(conn)
        shell, master_fd = setup_remote_shell()
        enc_nonce = b'\x00' * 15 + b'\x01'
        dec_nonce = b'\x00' * 15 + b'\x02'

        encryptor = Cipher(algorithms.AES(
            derived_key), modes.CTR(enc_nonce), backend=default_backend()).encryptor()

        decryptor = Cipher(algorithms.AES(
            derived_key), modes.CTR(dec_nonce), backend=default_backend()).decryptor()

        handle_client_commands(
            conn, master_fd, encryptor, decryptor)


if __name__ == "__main__":
    run_server()
