#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

class CifradorMT940:
    def __init__(self, cert_file='certs/server.crt', key_file='certs/server.key'):
        self.cert_file = cert_file
        self.key_file = key_file
        self.cargar_llaves()
    
    def cargar_llaves(self):
        """Carga las llaves SSL"""
        # Cargar llave pública (del certificado)
        with open(self.cert_file, 'rb') as f:
            cert_data = f.read()
            # Extraer llave pública del certificado
            # (Esto es simplificado, en realidad necesitas parsear el certificado)
        
        # Cargar llave privada
        with open(self.key_file, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        # Generar una llave simétrica para cifrado de archivos grandes
        self.symmetric_key = Fernet.generate_key()
        self.fernet = Fernet(self.symmetric_key)
    
    def cifrar_archivo(self, archivo_path):
        """Cifra un archivo MT940"""
        try:
            # Leer archivo
            with open(archivo_path, 'rb') as f:
                data = f.read()
            
            # Cifrar con Fernet (cifrado simétrico)
            encrypted_data = self.fernet.encrypt(data)
            
            # Guardar archivo cifrado
            encrypted_path = archivo_path + '.encrypted'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            return encrypted_path
        
        except Exception as e:
            print(f"Error cifrando: {e}")
            return None
    
    def descifrar_archivo(self, archivo_path):
        """Descifra un archivo MT940 cifrado"""
        try:
            # Leer archivo cifrado
            with open(archivo_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Descifrar
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Guardar descifrado
            decrypted_path = archivo_path.replace('.encrypted', '')
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
            
            return decrypted_path
        
        except Exception as e:
            print(f"Error descifrando: {e}")
            return None

# Ejemplo de uso
if __name__ == "__main__":
    cifrador = CifradorMT940()
    
    # Cifrar un archivo
    archivo_original = "carpetas/entrada/mi_archivo.mt940"
    archivo_cifrado = cifrador.cifrar_archivo(archivo_original)
    print(f"Archivo cifrado: {archivo_cifrado}")
    
    # Descifrar un archivo
    archivo_descifrado = cifrador.descifrar_archivo(archivo_cifrado)
    print(f"Archivo descifrado: {archivo_descifrado}")
