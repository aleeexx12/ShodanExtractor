# ShodanExtractor
Extractor de archivos en Shodan mediante FTP y cabeceras HTTP

| Opción                          | Descripción |
|---------------------------------|-------------|
| `--max-paginas`, `-p`           | Nº máximo de páginas de resultados de Shodan (por defecto: 10) |
| `--por-pagina`                  | Nº de resultados por página (por defecto: 100) |
| `--filtro-riesgo`, `-r`         | Filtrar por índice de riesgo: `0` (bajo) o `1` (alto) |
| `--extension`, `-e`             | Filtrar por extensión de archivo específica (se puede repetir) |
| `--palabra-clave`, `-k`         | Filtrar por palabras clave en el nombre del archivo (separadas por comas) |
| `--descargar`, `-d`             | Descargar automáticamente los archivos encontrados |
| `--base-datos`, `-D`            | Ruta del archivo SQLite a usar (por defecto: `Fugas_Shodan.db`) |
