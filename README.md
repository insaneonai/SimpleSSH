# Simple SSH

A Simple SSH-like implementation built from scratch (not entirely i indeed used cryptography and pty packages).

I also have a video recorded of me implementing this check it out: [https://www.youtube.com/watch?v=mXwZXscztyw&t=2509s](https://youtu.be/mXwZXscztyw?si=6nmAjibJduS1KZgd)

This project implements a secure client-server system with:

- key exchange
- server authentication
- encrypted communication
- remote command execution
- interactive shell using PTY

---

## Features

- Diffie-Hellman key exchange
- Server authentication (prevents MITM)
- Encrypted communication
- Remote command execution
- Interactive shell (supports `cd`, `nano`, etc.)

---

## Project Structure

```text
server.py  - SSH server
client.py  - SSH client
```

---

## How It Works

1. Client connects to server using TCP (insecure channel)
2. Handshake is performed (key exchange + authentication)
3. A shared key is established
4. All communication is encrypted
5. Client interacts with a shell running on the server

---

## Running the Project

Start the server:

```bash
python server.py
```

Start the client:

```bash
python client.py
```

You should now be able to run commands remotely.

---

## Notes

- This is a learning project, not production-ready
- Cryptographic primitives are used via libraries
- Designed to understand how SSH works internally

---

## What You Learn

- Networking (TCP sockets)
- Cryptography basics
- Protocol design
- Process and terminal handling (PTY)

---
