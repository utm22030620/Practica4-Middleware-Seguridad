import re
import datetime

PATRON_SQLI_KEYWORDS = re.compile(
    r"\b(select|drop|insert|delete|update|union|exec|truncate|alter)\b", 
    re.IGNORECASE
)

PATRON_SQLI_TAUTOLOGY = re.compile(
    r"(\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|/\*|\*/|;)", 
    re.IGNORECASE
)

PATRON_XSS = re.compile(
    r"(<script.*?>|javascript:|on\w+\s*=)", 
    re.IGNORECASE
)

def registrar_alerta(ip_origen: str, mensaje_original: str, motivo: str, ruta_log: str = "alertas_seguridad.txt") -> None:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea_log = (
        f"[{timestamp}] | IP: {ip_origen} | MOTIVO: {motivo} | "
        f"MENSAJE: \"{mensaje_original}\"\n"
    )
    with open(ruta_log, "a", encoding="utf-8") as archivo:
        archivo.write(linea_log)

def analizar_mensaje(mensaje: str, ip_origen: str = "192.168.1.100") -> tuple[bool, str, int]:
    mensaje_limpio = mensaje.lower()

    if PATRON_SQLI_KEYWORDS.search(mensaje_limpio):
        motivo = "Bloqueo por Regex SQLi: Comando DDL/DML detectado"
        registrar_alerta(ip_origen, mensaje, motivo)
        return False, f"403 Forbidden - {motivo}", 403

    if PATRON_SQLI_TAUTOLOGY.search(mensaje_limpio):
        motivo = "Bloqueo por Regex SQLi: Tautología o sintaxis de comentario detectada"
        registrar_alerta(ip_origen, mensaje, motivo)
        return False, f"403 Forbidden - {motivo}", 403

    if PATRON_XSS.search(mensaje_limpio):
        motivo = "Bloqueo por Regex XSS: Inyección de scripts/eventos DOM"
        registrar_alerta(ip_origen, mensaje, motivo)
        return False, f"403 Forbidden - {motivo}", 403

    return True, "200 OK - Mensaje Seguro", 200

if __name__ == "__main__":
    bateria_pruebas = [
        "Hola, quiero ayuda con mi cuenta",
        "Mi número de folio es 1234",
        "Necesito información sobre la selección de personal",
        "¿Cuáles son los horarios de atención al cliente?",
        "Quiero cancelar mi suscripción y desasociar mi correo",
        "SELECT * FROM usuarios;",
        "admin' OR 1=1 --",
        "DROP TABLE clientes;",
        "<script>alert('XSS_Hacked')</script>",
        "user'; EXEC xp_cmdshell('dir'); --"
    ]

    print("=" * 80)
    print("EJECUTANDO PRUEBAS DEL MIDDLEWARE DE SEGURIDAD - DATADEFEND CORP")
    print("=" * 80)

    for i, msg in enumerate(bateria_pruebas, 1):
        es_seguro, estado, codigo = analizar_mensaje(msg, ip_origen=f"192.168.1.{10 + i}")
        etiqueta = "[PASÓ]" if es_seguro else "[BLOQUEADO]"
        print(f"Prueba {i:02d} {etiqueta} | Código: {codigo}")
        print(f"  Entrada: \"{msg}\"")
        print(f"  Estado : {estado}")
        print("-" * 80)