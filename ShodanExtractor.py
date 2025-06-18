#!/usr/bin/env python3


import os
import re
import sqlite3
import requests
import argparse
from urllib.parse import urljoin, urlparse
from ftplib import FTP
from shodan import Shodan
from concurrent.futures import ThreadPoolExecutor, as_completed

RUTA_BASE_DATOS = 'Fugas_Shodan.db'
RESULTADOS_POR_PAGINA = 100
TAM_MAX_DESCARGA = 20 * 1024 * 1024  # 20 MB tamaño maximo de descarga
CARPETA_DESCARGAS = "Fugas_Shodan"

SECTORES_CLAVE = {
    'energía': ['energia', 'oil', 'gas', 'power'],
    'sanidad': ['health', 'hospital', 'clinic', 'medical'],
    'educación': ['school', 'university', 'college', 'edu'],
    'finanzas': ['bank', 'finance', 'investment', 'accounting']
}

EXTENSIONES_VALIDAS = [
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx','.txt', '.csv', '.zip', '.rar', '.7z', '.exe',
    '.sql', '.json', '.xml', '.yaml','.pem', '.key', '.crt', '.conf', '.cfg', '.ini',
    '.bak', '.png', '.jpg', '.jpeg', '.html', '.php', '.db', 
]

EXTENSIONES_RIESGOSAS = [
    '.key', '.pem', '.crt', '.conf', '.cfg', '.ini', '.bak', '.sql',
    '.json', '.yaml', '.xml', '.db', '.p12'
]

PALABRAS_CLAVE_RIESGO = [
    'password', 'passwd', 'backup',
    'confidential', 'secret', 'secrets',
    'db', 'database', 'private', 'privado',
    'config', 'cert', 'credentials', 'admin', 'contraseñas', 'dni', 'pasaporte'
]

def inicializar_base_datos(ruta):
    conexion = sqlite3.connect(ruta)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fugas (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            sector TEXT,
            extension TEXT,
            indice_riesgo INTEGER DEFAULT 0,
            fecha_descubrimiento DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conexion.commit()
    return conexion

def categorizar(url):
    u = url.lower()
    for sector, claves in SECTORES_CLAVE.items():
        for clave in claves:
            if clave in u:
                return sector
    return 'Desconocido'

def calcular_indice_riesgo(url):
    nombre = url.lower()
    extension = os.path.splitext(nombre)[1]
    if extension in EXTENSIONES_RIESGOSAS:
        return 1
    for palabra in PALABRAS_CLAVE_RIESGO:
        if palabra in nombre:
            return 1
    return 0

def escanear_ftp(host, puerto=21):
    encontrados = []
    try:
        ftp = FTP()
        ftp.connect(host, puerto, timeout=4)
        ftp.encoding = 'latin-1'
        ftp.login()
        for nombre in ftp.nlst():
            nombre_bajo = nombre.lower()
            if any(nombre_bajo.endswith(ext) for ext in EXTENSIONES_VALIDAS):
                encontrados.append(f'ftp://{host}/{nombre}')
        ftp.quit()
    except Exception as excepcion:
        print(f"[!] Error escaneando FTP {host}: {excepcion}")
    return encontrados

def escanear_http(url):
    documentos = []
    try:
        respuesta = requests.get(url, timeout=4)
        respuesta.raise_for_status()
        for enlace in re.findall(r'href="([^"]+)"', respuesta.text, re.IGNORECASE):
            enlace_bajo = enlace.lower()
            if any(enlace_bajo.endswith(ext) for ext in EXTENSIONES_VALIDAS):
                documentos.append(urljoin(url, enlace))
    except (requests.RequestException, ValueError):
        pass
    return documentos

def buscar_shodan(consulta, api_key, max_paginas, resultados_pagina):
    api = Shodan(api_key)
    todos_los_resultados = []
    for pagina in range(1, max_paginas+1):
        try:
            print(f"Buscando pagina {pagina}/{max_paginas} en Shodan para '{consulta}'…")
            resultados = api.search(consulta, page=pagina, limit=resultados_pagina)
            coincidencias = resultados.get('matches', [])
            if not coincidencias:
                break
            todos_los_resultados.extend(coincidencias)
        except Exception as e:
            print(f"  [!] Error en la pagina {pagina}: {e}")
            break
    return todos_los_resultados

def descargar_archivo(url, carpeta_destino=CARPETA_DESCARGAS):
    try:
        os.makedirs(carpeta_destino, exist_ok=True)
        nombre_fichero = os.path.basename(urlparse(url).path)
        ruta_fichero = os.path.join(carpeta_destino, nombre_fichero)

        if os.path.exists(ruta_fichero):
            print(f" [!] Ya existe: {nombre_fichero}, no se descarga de nuevo.")
            return

        respuesta = requests.get(url, stream=True, timeout=5)
        respuesta.raise_for_status()
        tamano = int(respuesta.headers.get('Content-Length', 0))
        if tamano > TAM_MAX_DESCARGA:
            print(f" [!] {nombre_fichero} demasiado grande ({tamano} bytes), cambiar tamaño maximo en variable global.")
            return

        with open(ruta_fichero, 'wb') as f:
            for parte in respuesta.iter_content(chunk_size=8192):
                f.write(parte)
        print(f" [+] Descargado: {nombre_fichero}")

    except Exception as e:
        print(f" [!] Error descargando {url}: {e}")

def main():

    parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    usage=argparse.SUPPRESS
)

    parser.add_argument('--max-paginas', '-p', type=int, default=10, help="  Numero maximo de páginas de resultados de Shodan a procesar (10 por defecto)")
    parser.add_argument('--por-pagina', type=int, default=RESULTADOS_POR_PAGINA, help="  Numero de resultados por pagina en Shodan (100 por defecto)")
    parser.add_argument('--filtro-riesgo', '-r', type=int, choices=[0,1], help="  Filtrar resultados por indice de riesgo: 0 (bajo) o 1 (alto)")
    parser.add_argument('--extension', '-e', action='append', help="  Filtrar por extensiones específicas de archivo")
    parser.add_argument('--palabra-clave', '-k', type=str, help="  Buscar archivos que contengan ciertas palabras clave (separadas por comas)")
    parser.add_argument('--descargar', '-d', action='store_true', help="  Descargar automaticamente los archivos encontrados")
    parser.add_argument('--base-datos', '-D', type=str, default=RUTA_BASE_DATOS, help="  Ruta del archivo SQLite donde guardar los resultados")

    args = parser.parse_args()

    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        print("Error: debes definir la variable de entorno SHODAN_API_KEY en tu shell.")
        return

    conexion = inicializar_base_datos(args.base_datos)
    cursor = conexion.cursor()
    ejecutor = ThreadPoolExecutor(max_workers=20)

    #1 FTP
    hosts_ftp = buscar_shodan('port:21 ftp', api_key, args.max_paginas, args.por_pagina)
    futuros_ftp = {ejecutor.submit(escanear_ftp, h.get('ip_str')): h for h in hosts_ftp}

    for futuro in as_completed(futuros_ftp):
        for enlace in futuro.result() or []:
            extension = os.path.splitext(enlace)[1].lower()
            riesgo = calcular_indice_riesgo(enlace)
            if args.filtro_riesgo is not None and riesgo != args.filtro_riesgo:
                continue
            if args.extension and extension not in [e.lower() for e in args.extension]:
                continue
            if args.palabra_clave:
                palabras = [k.strip().lower() for k in args.palabra_clave.split(',')]
                if not any(p in enlace.lower() for p in palabras):
                    continue

            sector = categorizar(enlace)
            try:
                cursor.execute(
                    "INSERT INTO fugas (url, sector, extension, indice_riesgo) VALUES (?, ?, ?, ?)",
                    (enlace, sector, extension, riesgo)
                )
                if args.descargar:
                    descargar_archivo(enlace)
            except sqlite3.IntegrityError:
                pass

    #2 HTTP "Index of"
    hosts_http = buscar_shodan('http.title:"Index of"', api_key, args.max_paginas, args.por_pagina)
    futuros_http = {ejecutor.submit(escanear_http, f"http://{h.get('ip_str')}:{h.get('port')}/"): h for h in hosts_http}

    for futuro in as_completed(futuros_http):
        for enlace in futuro.result() or []:
            extension = os.path.splitext(enlace)[1].lower()
            riesgo = calcular_indice_riesgo(enlace)
            if args.filtro_riesgo is not None and riesgo != args.filtro_riesgo:
                continue
            if args.extension and extension not in [e.lower() for e in args.extension]:
                continue
            if args.palabra_clave:
                palabras = [k.strip().lower() for k in args.palabra_clave.split(',')]
                if not any(p in enlace.lower() for p in palabras):
                    continue

            sector = categorizar(enlace)
            try:
                cursor.execute(
                    "INSERT INTO fugas (url, sector, extension, indice_riesgo) VALUES (?, ?, ?, ?)",
                    (enlace, sector, extension, riesgo)
                )
                if args.descargar:
                    descargar_archivo(enlace)
            except sqlite3.IntegrityError:
                pass

    conexion.commit()
    conexion.close()
    print("Escaneo terminado, consulta los datos en:", args.base_datos)

if __name__ == '__main__':
    main()        