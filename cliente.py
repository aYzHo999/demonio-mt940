#!/usr/bin/env python3

import socket
import ssl
import sys

def enviar_archivo_mt940(archivo_path, host='localhost', puerto=8443):
    print(f"📖 Leyendo archivo: {archivo_path}")
    with open(archivo_path, 'r') as f:
        contenido = f.read()
    
    contexto = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    contexto.load_verify_locations('certs/ca.crt')
    
    print(f"🔗 Conectando a {host}:{puerto}...")
    with socket.create_connection((host, puerto)) as sock:
        with contexto.wrap_socket(sock, server_hostname=host) as ssock:
            print(f"📤 Enviando archivo...")
            ssock.sendall(contenido.encode('utf-8'))
            
            respuesta = ssock.recv(1024).decode('utf-8')
            print(f"✅ Respuesta del servidor: {respuesta}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 cliente.py <archivo_mt940>")
        print("Ejemplo: python3 cliente.py ejemplo.mt940")
        sys.exit(1)
    enviar_archivo_mt940(sys.argv[1])
