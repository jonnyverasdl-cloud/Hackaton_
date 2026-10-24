# Lecciones de la práctica (para no repetir)

## Proceso
- **Inglés desde el primer archivo.** IDs, etiquetas, fixtures, docs. Migrar costó una tarde.
- **Un solo `.venv`, desde el primer comando.** CC tocó el Python global una vez; costó deshacerlo.
- **Yo hago los push.** CC commitea, yo subo. Evita problemas de credenciales y es más seguro.
- **El `.env.example` nunca lleva valores.** Revisar antes del primer push.
- **Las claves de API, probadas la noche anterior** con una llamada mínima. El día del evento no
  hay tiempo para pelear con Google Cloud.
- **Log de IA en el momento**, no al final.
- **Pedir auditoría a CC después de cada bloque.** Encontró 9 fallos reales en el esqueleto.

## Producto
- **Cada caso de la demo con su evidencia propia.** Capturas repetidas, SHA iguales, textos con
  argumentos falsos: los jueces lo notan.
- **El puntaje no debe estar siempre al tope.** Pesos ajustados para que haya gradación.
- **La IA nunca decide.** El footer de la página de laboratorio hizo que dijera "legit".
  Esa anécdota es el mejor argumento del enfoque Audit-First; úsala si preguntan.
- **Datos en `replay` para lo que no puede ser real, en vivo para lo que sí.** Y decirlo.
- **Un comando levanta todo** (`run_demo.ps1`) con calentamiento de la IA. Sin eso, la primera
  llamada en frío tarda 20+ s y parece fallo.
- **Estado de progreso visible** mientras el sistema trabaja. 17 segundos en silencio parecen un error.

## Pitch
- Abrir con mi experiencia real (L2, 40 minutos por correo). Eso no se cuestiona.
- Cifras medidas, no estimadas (regla 6). El benchmark da el número.
- Narrar lo que aparece en pantalla, no lo que planeaba.
- La novedad no está en la idea sino en el encuadre: "un analista automatizó su propio dolor y lo
  hizo auditable", no "una plataforma SOC autónoma".

## Equipo
- Si voy solo, el alcance es más chico. A las 14:00 se congela.
- Si en el check-in hay gente sin equipo: útil para panel o write-up, pero el plan no depende de eso.
