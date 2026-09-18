#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demonio MT940 - Procesador automático de extractos bancarios.

Modo LOCAL + inotify: Solo acepta conexiones desde la misma máquina
y usa inotify para detectar archivos sin consumir CPU innecesariamente.

Autor: CESAR ENRIQUE SANCHEZ GONZALEZ
Fecha: 2026
Versión: 2.0
"""

import os
import sys
import time
import logging
import json
import shutil
import signal
import socket
import ssl
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import configparser
from daemon import DaemonContext
import mt940
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# CONSTANTES
# ============================================================

class Config:
    """Constantes de configuración del demonio."""
    
    ARCHIVO_CONFIG = 'config.ini'
    EXTENSIONES_VALIDAS = ('.mt940', '.sta', '.txt')
    HOST_LOCAL = '127.0.0.1'
    PUERTO_SSL = 8443
    MAX_CONEXIONES = 5
    TAMANO_BUFFER = 4096
    CIPHERS_SSL = 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM'
    SEPARADOR_LARGO = "=" * 60
    SEPARADOR_CORTO = "-" * 60


# ============================================================
# CONFIGURACIÓN DE LOGGING
# ============================================================

def configurar_logging() -> logging.Logger:
    """Configura el sistema de logging del demonio."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger('DemonioMT940')


logger = configurar_logging()


# ============================================================
# MANEJADOR DE EVENTOS (inotify)
# ============================================================

class ManejadorArchivos(FileSystemEventHandler):
    """
    Maneja los eventos del sistema de archivos (inotify).
    
    Se activa cuando se crea un archivo en la carpeta vigilada.
    Solo procesa archivos con extensión válida.
    """
    
    def __init__(self, demonio):
        """
        Inicializa el manejador.
        
        Args:
            demonio: Instancia de DemonioMT940 para procesar archivos.
        """
        self.demonio = demonio
        super().__init__()
    
    def on_created(self, event):
        """
        Se ejecuta cuando se crea un archivo en la carpeta vigilada.
        
        Args:
            event: Evento con información del archivo creado.
        """
        if event.is_directory:
            return
        
        archivo = event.src_path
        if not archivo.lower().endswith(Config.EXTENSIONES_VALIDAS):
            return
        
        logger.info(f" Archivo detectado: {os.path.basename(archivo)}")
        
        # Esperar un momento para que el archivo termine de escribirse
        time.sleep(0.5)
        
        try:
            if os.path.exists(archivo):
                self.demonio.procesar_archivo_mt940(archivo)
        except Exception as e:
            logger.error(f"Error procesando archivo detectado: {e}")


# ============================================================
# CLASE PRINCIPAL: DEMONIO MT940
# ============================================================

class DemonioMT940:
    """
    Demonio para procesamiento automático de archivos MT940.
    
    Modo LOCAL + inotify: Solo acepta conexiones desde 127.0.0.1
    y usa inotify para detectar archivos sin polling.
    """
    
    def __init__(self, config_file: str = Config.ARCHIVO_CONFIG) -> None:
        """Inicializa el demonio."""
        self.config_file = config_file
        self.running = True
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.observer = None
        
        self.cargar_configuracion()
        self.setup_ssl()
        self.configurar_senales()
        
        logger.info("Demonio inicializado correctamente (modo LOCAL + inotify)")
    
    # --------------------------------------------------------
    # CONFIGURACIÓN
    # --------------------------------------------------------
    
    def cargar_configuracion(self) -> None:
        """Carga la configuración desde el archivo INI."""
        try:
            config = configparser.ConfigParser()
            
            if not os.path.exists(self.config_file):
                raise FileNotFoundError(
                    f"No se encontró el archivo: {self.config_file}"
                )
            
            config.read(self.config_file)
            
            self.carpeta_entrada = config['general']['carpeta_entrada']
            self.carpeta_procesados = config['general']['carpeta_procesados']
            self.carpeta_errores = config['general']['carpeta_errores']
            self.intervalo_escaneo = int(config['general']['intervalo_escaneo'])
            self.log_file = config['general']['log_file']
            
            self.cert_file = config['ssl']['cert_file']
            self.key_file = config['ssl']['key_file']
            self.ca_file = config['ssl']['ca_file']
            
            self._crear_carpetas_necesarias()
            
            logger.info("Configuración cargada correctamente")
            logger.info(f"Carpeta de entrada: {self.carpeta_entrada}")
            logger.info(f"Carpeta de procesados: {self.carpeta_procesados}")
            logger.info(f"Carpeta de errores: {self.carpeta_errores}")
            
        except FileNotFoundError as e:
            logger.error(f"Archivo de configuración no encontrado: {e}")
            sys.exit(1)
        except KeyError as e:
            logger.error(f"Falta una sección o clave en {self.config_file}: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error cargando configuración: {e}")
            sys.exit(1)
    
    def _crear_carpetas_necesarias(self) -> None:
        """Crea las carpetas necesarias si no existen."""
        carpetas = [
            self.carpeta_entrada,
            self.carpeta_procesados,
            self.carpeta_errores,
            os.path.dirname(self.log_file)
        ]
        
        for carpeta in carpetas:
            Path(carpeta).mkdir(parents=True, exist_ok=True)
    
    def configurar_senales(self) -> None:
        """Configura el manejo de señales del sistema."""
        signal.signal(signal.SIGTERM, self.manejar_senal)
        signal.signal(signal.SIGINT, self.manejar_senal)
    
    def manejar_senal(self, signum: int, frame: Any) -> None:
        """Maneja las señales de terminación."""
        logger.info(f"Señal {signum} recibida. Cerrando demonio...")
        self.running = False
    
    # --------------------------------------------------------
    # SSL
    # --------------------------------------------------------
    
    def setup_ssl(self) -> None:
        """Configura el contexto SSL para el servidor LOCAL."""
        try:
            self.ssl_context = ssl.create_default_context(
                ssl.Purpose.CLIENT_AUTH,
                cafile=self.ca_file
            )
            self.ssl_context.load_cert_chain(
                certfile=self.cert_file,
                keyfile=self.key_file
            )
            self.ssl_context.set_ciphers(Config.CIPHERS_SSL)
            logger.info("Contexto SSL configurado correctamente")
            logger.info(f"Modo: SOLO LOCAL ({Config.HOST_LOCAL})")
            
        except FileNotFoundError as e:
            logger.error(f"Certificado o clave no encontrada: {e}")
            self.ssl_context = None
        except ssl.SSLError as e:
            logger.error(f"Error SSL: {e}")
            self.ssl_context = None
        except Exception as e:
            logger.error(f"Error configurando SSL: {e}")
            self.ssl_context = None
    
    # --------------------------------------------------------
    # PROCESAMIENTO DE ARCHIVOS
    # --------------------------------------------------------
    
    def procesar_archivo_mt940(self, archivo_path: str) -> bool:
        """Procesa un archivo MT940 y genera su JSON."""
        try:
            logger.info(f"Procesando archivo: {archivo_path}")
            
            contenido = self._leer_archivo(archivo_path)
            transacciones = self._parsear_mt940(contenido)
            datos_extraidos = self._extraer_datos(transacciones, archivo_path)
            self._guardar_json(datos_extraidos, archivo_path)
            self._mover_a_procesados(archivo_path)
            
            logger.info(f" Archivo procesado: {os.path.basename(archivo_path)}")
            logger.info(f"   Transacciones: {datos_extraidos['resumen']['total_transacciones']}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error procesando {archivo_path}: {e}")
            self._mover_a_errores(archivo_path)
            return False
    
    def _leer_archivo(self, archivo_path: str) -> str:
        """Lee el contenido de un archivo MT940."""
        with open(archivo_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def _parsear_mt940(self, contenido: str) -> List[Any]:
        """Parsea el contenido de un archivo MT940."""
        transacciones = mt940.parse(contenido)
        
        if hasattr(transacciones, '__iter__'):
            return list(transacciones)
        return []
    
    def _extraer_datos(
        self,
        transacciones: List[Any],
        archivo_path: str
    ) -> Dict[str, Any]:
        """Extrae y estructura los datos de las transacciones."""
        datos = {
            'archivo': os.path.basename(archivo_path),
            'fecha_procesamiento': datetime.now().isoformat(),
            'transacciones': [],
            'resumen': {
                'total_transacciones': len(transacciones),
                'total_debito': 0.0,
                'total_credito': 0.0
            }
        }
        
        for transaccion in transacciones:
            try:
                datos_tx = self._extraer_transaccion(transaccion)
                datos['transacciones'].append(datos_tx)
                
                if datos_tx['tipo'] == 'CREDITO':
                    datos['resumen']['total_credito'] += datos_tx['monto']
                else:
                    datos['resumen']['total_debito'] += abs(datos_tx['monto'])
                    
            except Exception as e:
                logger.warning(f"Error procesando transacción: {e}")
                continue
        
        return datos
    
    def _extraer_transaccion(self, transaccion: Any) -> Dict[str, Any]:
        """Extrae los datos de una transacción individual."""
        if hasattr(transaccion, 'data'):
            datos_tx = transaccion.data
        elif hasattr(transaccion, 'parsed_data'):
            datos_tx = transaccion.parsed_data
        else:
            datos_tx = {}
        
        monto = self._extraer_monto(datos_tx)
        
        fecha = str(datos_tx.get('date', ''))
        descripcion = str(datos_tx.get('description', ''))
        referencia = str(datos_tx.get('reference', ''))
        
        return {
            'fecha': fecha,
            'monto': monto,
            'descripcion': descripcion,
            'referencia': referencia,
            'tipo': 'CREDITO' if monto > 0 else 'DEBITO'
        }
    
    @staticmethod
    def _extraer_monto(datos_tx: Dict[str, Any]) -> float:
        """Extrae el monto de una transacción de forma segura."""
        if 'amount' not in datos_tx:
            return 0.0
        
        monto_raw = datos_tx['amount']
        
        try:
            if hasattr(monto_raw, 'amount'):
                return float(monto_raw.amount)
            return float(monto_raw)
        except (ValueError, TypeError):
            return 0.0
    
    def _guardar_json(self, datos: Dict[str, Any], archivo_path: str) -> str:
        """Guarda los datos extraídos en un archivo JSON."""
        nombre_base = os.path.splitext(os.path.basename(archivo_path))[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nombre_json = f"{nombre_base}_{timestamp}.json"
        json_path = os.path.join(self.carpeta_procesados, nombre_json)
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=2, ensure_ascii=False)
        
        return json_path
    
    def _mover_a_procesados(self, archivo_path: str) -> None:
        """Mueve un archivo a la carpeta de procesados."""
        destino = os.path.join(
            self.carpeta_procesados,
            os.path.basename(archivo_path)
        )
        shutil.move(archivo_path, destino)
    
    def _mover_a_errores(self, archivo_path: str) -> None:
        """Mueve un archivo a la carpeta de errores."""
        try:
            destino = os.path.join(
                self.carpeta_errores,
                os.path.basename(archivo_path)
            )
            if os.path.exists(archivo_path):
                shutil.move(archivo_path, destino)
        except Exception as e:
            logger.error(f"No se pudo mover a errores: {e}")
    
    # --------------------------------------------------------
    # VIGILANCIA CON INOTIFY
    # --------------------------------------------------------
    
    def _iniciar_vigilancia(self) -> None:
        """
        Inicia la vigilancia de la carpeta usando inotify (watchdog).
        
        En lugar de escanear cada N segundos, el kernel de Linux
        notifica cuando se crea un archivo nuevo. Esto reduce el
        consumo de CPU al 0% cuando no hay actividad.
        """
        logger.info("Iniciando vigilancia con inotify...")
        logger.info(f"Vigilando carpeta: {self.carpeta_entrada}")
        
        manejador = ManejadorArchivos(self)
        
        self.observer = Observer()
        self.observer.schedule(
            manejador,
            self.carpeta_entrada,
            recursive=False
        )
        self.observer.start()
        
        logger.info(" Vigilancia activa. Esperando archivos...")
        logger.info("   (CPU en reposo: 0%)")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()
            logger.info("Vigilancia detenida")
    
    # --------------------------------------------------------
    # SERVIDOR SSL (SOLO LOCAL)
    # --------------------------------------------------------
    
    def iniciar_servidor_ssl(self) -> None:
        """Inicia el servidor SSL para recibir archivos por red LOCAL."""
        if not self.ssl_context:
            logger.warning("SSL no disponible. Servidor no iniciado.")
            return
        
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((Config.HOST_LOCAL, Config.PUERTO_SSL))
            server_socket.listen(Config.MAX_CONEXIONES)
            
            logger.info(f"Servidor SSL iniciado en {Config.HOST_LOCAL}:{Config.PUERTO_SSL}")
            logger.info("  MODO LOCAL: Solo acepta conexiones desde esta máquina")
            
            while self.running:
                try:
                    client_socket, addr = server_socket.accept()
                    logger.info(f"Conexión LOCAL desde {addr}")
                    
                    ssl_socket = self.ssl_context.wrap_socket(
                        client_socket,
                        server_side=True
                    )
                    
                    threading.Thread(
                        target=self.manejar_conexion_ssl,
                        args=(ssl_socket, addr),
                        daemon=True
                    ).start()
                    
                except ssl.SSLError as e:
                    logger.error(f"Error SSL en conexión: {e}")
                except Exception as e:
                    if self.running:
                        logger.error(f"Error aceptando conexión: {e}")
                        
        except OSError as e:
            logger.error(f"No se pudo iniciar servidor SSL: {e}")
        except Exception as e:
            logger.error(f"Error inesperado en servidor: {e}")
    
    def manejar_conexion_ssl(self, ssl_socket: ssl.SSLSocket, addr: tuple) -> None:
        """Maneja una conexión SSL entrante (LOCAL)."""
        try:
            logger.info(f"Manejando conexión LOCAL desde {addr}")
            
            data = ssl_socket.recv(Config.TAMANO_BUFFER).decode('utf-8')
            
            if not data:
                logger.warning("No se recibieron datos")
                return
            
            archivo_path = self._guardar_archivo_recibido(data)
            exito = self.procesar_archivo_mt940(archivo_path)
            
            respuesta = (
                "Archivo recibido y procesado correctamente"
                if exito else
                "Error al procesar el archivo"
            )
            ssl_socket.sendall(respuesta.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error manejando conexión SSL: {e}")
            self._enviar_error_ssl(ssl_socket, str(e))
        finally:
            ssl_socket.close()
            logger.info(f"Conexión cerrada con {addr}")
    
    def _guardar_archivo_recibido(self, data: str) -> str:
        """Guarda un archivo recibido por SSL."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nombre_archivo = f"recibido_{timestamp}.mt940"
        archivo_path = os.path.join(self.carpeta_entrada, nombre_archivo)
        
        with open(archivo_path, 'w', encoding='utf-8') as f:
            f.write(data)
        
        return archivo_path
    
    @staticmethod
    def _enviar_error_ssl(ssl_socket: ssl.SSLSocket, mensaje: str) -> None:
        """Envía un mensaje de error por SSL (silencioso si falla)."""
        try:
            ssl_socket.sendall(f"Error: {mensaje}".encode('utf-8'))
        except Exception:
            pass
    
    # --------------------------------------------------------
    # EJECUCIÓN PRINCIPAL
    # --------------------------------------------------------
    
    def ejecutar(self) -> None:
        """Ejecuta el demonio con vigilancia inotify."""
        self._mostrar_banner_inicio()
        self._iniciar_servidor_ssl_en_hilo()
        self._iniciar_vigilancia()
        self._mostrar_banner_fin()
    
    def _mostrar_banner_inicio(self) -> None:
        """Muestra el banner de inicio del demonio."""
        logger.info(Config.SEPARADOR_LARGO)
        logger.info("DEMONIO MT940 INICIADO (LOCAL + inotify)")
        logger.info(f"Hora de inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(Config.SEPARADOR_LARGO)
    
    def _mostrar_banner_fin(self) -> None:
        """Muestra el banner de fin del demonio."""
        logger.info(Config.SEPARADOR_LARGO)
        logger.info("DEMONIO MT940 TERMINADO")
        logger.info(f"Hora de finalización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(Config.SEPARADOR_LARGO)
    
    def _iniciar_servidor_ssl_en_hilo(self) -> None:
        """Inicia el servidor SSL en un hilo daemon."""
        hilo_ssl = threading.Thread(
            target=self.iniciar_servidor_ssl,
            daemon=True
        )
        hilo_ssl.start()


# ============================================================
# FUNCIONES DE ENTRADA
# ============================================================

def ejecutar_como_demonio() -> None:
    """Ejecuta el demonio en segundo plano."""
    contexto = DaemonContext(
        working_directory='.',
        umask=0o002,
        pidfile=None
    )
    
    demonio = DemonioMT940()
    
    with contexto:
        demonio.ejecutar()


def main() -> None:
    """Función principal del programa."""
    modo_prueba = len(sys.argv) > 1 and sys.argv[1] == '--no-daemon'
    
    if modo_prueba:
        print("Ejecutando en modo prueba (primer plano)...")
        print("Presiona Ctrl+C para detener\n")
        demonio = DemonioMT940()
        demonio.ejecutar()
    else:
        print("Iniciando demonio en segundo plano...")
        print("(usa --no-daemon para ver los logs en pantalla)")
        ejecutar_como_demonio()


if __name__ == "__main__":
    main()