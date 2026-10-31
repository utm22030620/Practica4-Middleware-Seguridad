# Practica4-Middleware-Seguridad

## 📌 Descripción del Proyecto
Este proyecto implementa un prototipo de middleware en Python diseñado para interceptar, sanitizar y analizar los mensajes enviados por los usuarios antes de que lleguen a la base de datos o al modelo de Machine Learning. El objetivo principal es bloquear vectores de ataque conocidos como **Inyección SQL (SQLi)** y **Cross-Site Scripting (XSS)** en tiempo real.

## 📂 Archivos del Repositorio
* **`middleware_seguridad.py`**: Código fuente con la lógica de sanitización, reglas Regex compiladas y batería de pruebas.
* **`alertas_seguridad.txt`**: Registro de auditoría (logging) generado automáticamente al detectar solicitudes maliciosas.
* **`Reporte_Practica4_Middleware.pdf`**: Documento con la justificación técnica de las reglas, prevención de falsos positivos y análisis de complejidad $O(N)$.

## 🛡️ Reglas de Seguridad Implementadas
1. **Comandos SQL DDL/DML:** Detección de palabras clave reservadas (`SELECT`, `DROP`, `DELETE`, etc.) utilizando límites de palabra (`\b`) para evitar falsos positivos.
2. **Tautologías y Comentarios SQL:** Bloqueo de patrones lógicos destructivos (ej. `' OR 1=1`) y caracteres de comentario (`--`, `;`).
3. **Inyección XSS:** Intercepción de etiquetas `<script>`, esquemas `javascript:` y controladores de eventos HTML inline.
   
## 📊 Evidencia de Ejecución
A continuación se muestra el resultado del script procesando 10 mensajes (5 legítimos y 5 intentos de ataque):
![Evidencia de Terminal](assets/evidencia_terminal.png)
