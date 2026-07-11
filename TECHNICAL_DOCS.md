# IA ORCHESTRATOR — JW Solutions
## Documentación Técnica y Arquitectura del Sistema

> **Archivo vivo.** Actualizar esta sección al cierre de cada sesión de desarrollo.
> Formato de changelog al final del documento.

---

## 1. Resumen del Proyecto

**IA ORCHESTRATOR - JW Solutions** es una SPA (*Single Page Application*) cliente-only que orquesta 4 modelos de lenguaje en paralelo a través de la API de OpenRouter. No requiere backend, servidor de aplicaciones, build tools ni frameworks. Toda la lógica vive en dos archivos: `index.html` y `app.js`.

| Atributo            | Valor                                          |
|---------------------|------------------------------------------------|
| Tipo                | SPA cliente-only, sin backend                  |
| Servidor de archivos | `System.Net.HttpListener` (.NET, via PowerShell) |
| Dependencia externa  | Tailwind CSS via CDN (solo estilos)            |
| API de IA           | OpenRouter (`/api/v1/chat/completions`)        |
| Protocolo de stream | SSE (Server-Sent Events) via `fetch` + `ReadableStream` |
| Cifrado             | AES-GCM 256-bit + PBKDF2 (200k iter, SHA-256) via WebCrypto API |
| Almacenamiento      | `localStorage` solo para datos cifrados y preferencias |
| Módulos JS          | ES Modules (`type="module"`) — scope aislado   |

### Por qué necesita `http://localhost`
`type="module"` + WebCrypto API requieren origen HTTP seguro. No funciona desde `file://`.

---

## 2. Archivos del Proyecto

```
D:\PROYECTOS\Navegador IA\
├── index.html          # UI completa: HTML + CSS (Tailwind + custom) + referencias
├── app.js              # Toda la lógica JS (~2845 líneas)
├── iniciar.bat         # Launcher de producción (servidor oculto + Edge app mode)
├── debug.bat           # Launcher de diagnóstico (PowerShell visible con logs HTTP)
├── Navegador IA.vbs    # Script WSH intermediario — abre iniciar.bat sin ventana negra
├── CLAUDE.md           # Instrucciones para Claude Code (este proyecto)
├── TECHNICAL_DOCS.md   # Este archivo
└── architecture_spec.md # Spec arquitectural previo (obsoleto, referencia histórica)
```

### Cómo ejecutar

```
Doble clic en "Navegador IA.vbs"   ← Producción limpia. Zero ventanas de consola.
iniciar.bat                         ← Producción directa desde consola
debug.bat                           ← Diagnóstico: PowerShell visible con logs HTTP
```

El `.vbs` usa `WshShell.Run(..., 0)` para invocar `iniciar.bat` completamente oculto.

---

## 3. Arquitectura UI

### Layout general

```
┌─────────────────────────────────────────────────────┐
│  NAVBAR: Logo | Buscador+Selector tareas | Botones  │
├──────────────────────────┬──────────────────────────┤
│  Q1 — Optimizador        │  Q2 — Motor Avanzado      │
│  (Azul, siempre activo)  │  (Verde, Claude/GPT)      │
├──────────────────────────┼──────────────────────────┤
│  Q3 — Alternativa Libre  │  Q4 — Motor de Velocidad  │
│  (Púrpura, DeepSeek/Qwen)│  (Naranja, Llama/Gemini)  │
│                          │  📝Código | 👁️Vista Previa│
├──────────────────────────┴──────────────────────────┤
│  SYNTHESIS PANEL (colapsable, post-ejecución)       │
├─────────────────────────────────────────────────────┤
│  FOOTER: 📎 Adj | Textarea | Ejecutar Orquestación  │
└─────────────────────────────────────────────────────┘
```

### Cuadrantes

| ID  | Color    | Clase CSS      | Rol principal             | Modelo default          |
|-----|----------|----------------|---------------------------|-------------------------|
| Q1  | Azul     | `.quad-blue`   | Compresor/Optimizador     | `gemini-2.5-flash:free` |
| Q2  | Verde    | `.quad-green`  | Motor principal de calidad| `claude-3.5-sonnet`     |
| Q3  | Púrpura  | `.quad-purple` | Alternativa libre/rápida  | `deepseek-chat`         |
| Q4  | Naranja  | `.quad-orange` | Velocidad + Renderizador  | `llama-3.1-70b`         |

**Q4 tiene pestaña dual**: `📝 Código` (texto del modelo) / `👁️ Vista Previa` (render SVG/HTML en iframe sandboxed).

### Temas visuales
- Oscuro por defecto (`html.dark`). Toggle claro añade/quita `body.light-theme`.
- Persistido en `localStorage` bajo clave `navia_theme`.
- Los colores personalizados de cuadrante se guardan como `navia_q1_color`…`navia_q4_color`.

---

## 4. Mapa de Módulos en `app.js`

| Línea aprox. | Módulo / Constante         | Responsabilidad                                              |
|--------------|----------------------------|--------------------------------------------------------------|
| 8            | `AppState`                 | Pool de keys en RAM. Nunca a disco en texto plano.           |
| 16–29        | Constantes globales        | `STORAGE_KEY`, `PBKDF2_ITERATIONS`, límites adjuntos         |
| 44           | `Crypto`                   | AES-GCM 256 + PBKDF2 via WebCrypto API                       |
| 100          | `Storage`                  | Leer/guardar blob cifrado en localStorage                    |
| 110          | `LockScreen`               | Pantalla de desbloqueo con callback `_onUnlock`              |
| 219          | `SettingsModal`            | Modal 2 pisos: Piso 1 libre (tema+colores), Piso 2 protegido |
| 632          | `UI`                       | Toast, actualización botón ajustes                           |
| 674–684      | Constantes API             | `OPENROUTER_URL`, `RETRYABLE_CODES`, `MODEL_404_FALLBACKS`   |
| 686–693      | System prompts             | `SYSTEM_Q1`, `SYSTEM_ANTI_FLUFF`, `SYSTEM_COMPACTOR`         |
| 700          | `QuadrantState`            | Estado por cuadrante: `keyIndex`, `controller`, `history[]`  |
| 712          | `LED`                      | Semáforos visuales + click handler de rotación manual        |
| 761          | `Output`                   | Render de burbujas (streaming), mensajes de error/warn       |
| 853          | `fetchStreamForQuadrant`   | Fetch SSE, retry 429/402, fallback 404, `_DevSim` hook       |
| 1045         | `Memory`                   | Ventana móvil: trigger=10, compacta 8, preserva 2            |
| 1170         | `Pipeline`                 | Flag `active` + botón Cancelar                               |
| 1203         | `Orchestrator`             | Fase 1 (Q1 secuencial) → Fase 2 (Q2/Q3/Q4 paralelo)         |
| 1452         | `TASK_MATRIX`              | 49 entradas (`default` + `'1'`…`'48'`), 4 grupos            |
| 2128         | `TaskRouter`               | Aplica TASK_MATRIX al DOM: títulos, selects, `.quad-star`    |
| 2204         | `QuadrantColors`           | Colores personalizados — inline style con `!important`       |
| 2228         | `Theme`                    | Toggle claro/oscuro — `body.light-theme`                     |
| 2294         | `Synthesis`                | Panel post-ejecución: comparativa + copy report              |
| 2388         | `Q4Preview`                | Renderizador SVG/HTML en iframe sandboxed + pestañas         |
| 2479         | `downloadQ4Render`         | Exportación SVG → PNG/JPG (canvas x2 High-DPI)              |
| 2556         | `FileAttachments`          | Lectura FileReader UTF-8, badges, drag & drop, inject prompt |
| 2643         | `newConversation()`        | Reset total: historiales, outputs, LEDs, adjuntos, preview   |
| 2695         | `DOMContentLoaded`         | Init de todos los módulos y event bindings                   |

---

## 5. Flujo de Datos del Pipeline

```
rawPrompt
  │
  ├─ FileAttachments.buildContext()          ← adjuntos staged → markdown blocks
  │    └─ augmentedPrompt = fileCtx + "\n\n" + rawPrompt
  │         └─ FileAttachments.clear()       ← se vacía tras capturar
  │
  ├─ [si task-select === "auto"]
  │    └─ Orchestrator._autoDetect(prompt)   ← mini-fetch no-streaming gemini-2.5-flash:free
  │         └─ detecta tarea 1-48 → TaskRouter.apply(n)
  │
  ├─ Pipeline.active = true
  │
  ╔══════════════════════════════════════╗
  ║  FASE 1 — Q1 (bloqueante)            ║
  ║  Memory.push(1, 'user', augmented)   ║
  ║  fetchStreamForQuadrant(1, history)  ║
  ║    → Output.appendToken(1, token)    ║  SSE stream token a token
  ║    → fullText acumulado              ║
  ║  Memory.push(1, 'assistant', text)   ║
  ║  Memory.compact(1) si trigger        ║  fire-and-forget
  ╚══════════════════════════════════════╝
  │
  ├─ optimizedText (o prompt original si Q1 falla)
  │
  ╔═══════════════════════════════════════════════════════════╗
  ║  FASE 2 — Q2, Q3, Q4 en paralelo (Promise.allSettled)    ║
  ║                                                           ║
  ║  [override Q4 system prompt si tarea tiene q4SystemPrompt]║
  ║                                                           ║
  ║  Para cada qId activo:                                    ║
  ║    Memory.push(qId, 'user', finalPrompt)                  ║
  ║    fetchStreamForQuadrant(qId, history)                   ║
  ║      → Output.appendToken(qId, token)   SSE stream        ║
  ║    Memory.push(qId, 'assistant', response)                ║
  ║    Memory.compact(qId) si trigger       fire-and-forget   ║
  ║    [si qId===4] Q4Preview.render(response)                ║
  ╚═══════════════════════════════════════════════════════════╝
  │
  └─ Synthesis.render(downstream, finalPrompt)   ← panel post-ejecución
```

---

## 6. Sistema de Seguridad

### Claves API

```
Flujo de setup:
  Usuario → SettingsModal (Piso 2) → ingresa keys + master password
  → Crypto.encrypt(keys, password)  → { salt, iv, data } en Base64
  → localStorage[STORAGE_KEY]       ← NUNCA texto plano

Flujo de uso:
  DOMContentLoaded o SettingsModal unlock
  → Crypto.decrypt(blob, password)
  → AppState.apiKeys[]               ← solo en RAM de sesión
  → masterPassword NUNCA almacenada  ← solo para derivar clave AES
```

### Reglas absolutas
- `maskKey(key)` → `…XXXX` — SIEMPRE al referenciar keys en logs
- `element.textContent +=` — NUNCA `innerHTML` para output de LLMs (anti-XSS)
- `iframe sandbox="allow-scripts"` — render SVG/HTML aislado del DOM padre
- `IS_PRODUCTION = false` — cambiar a `true` antes de deploy (deshabilita DevSim)

### SettingsModal — arquitectura de 2 pisos

| Piso | Acceso | Contenido |
|------|--------|-----------|
| Piso 1 | Libre (sin contraseña) | Toggle tema + paleta 2×2 de colores de cuadrante |
| Piso 2 | Protegido (master password) | Keys de API + gestión de contraseña maestra |

- Piso 2 **siempre empieza bloqueado** al abrir el modal, aunque `AppState.isUnlocked = true`
- `SettingsModal._currentPwd` se limpia al cerrar el modal
- `AppState.apiKeys` persiste en RAM mientras la sesión esté abierta (el pipeline sigue funcionando)

---

## 7. Módulos Clave — Detalles

### Rotación de keys (429/402)
```
fetchStreamForQuadrant:
  attemptsLeft = total de keys
  loop:
    key = AppState.apiKeys[QuadrantState[qId].keyIndex]
    fetch → 429 o 402:
      LED.set(qId, 'error')
      keyIndex = (keyIndex + 1) % total
      delay 400ms
      continue  ← no decrementa attemptsLeft en 404
    fetch → 404 (modelo no encontrado):
      _modelFbIdx++ → MODEL_404_FALLBACKS[qId][nextIdx]
      continue (NO rota key, rota modelo)
    fetch → 200 → SSE stream
```

### Memoria de ventana móvil
```
history[qId] = [
  { role: 'system', content: SYSTEM_PROMPT },   ← siempre índice 0
  { role: 'user',   content: '...' },
  { role: 'assistant', content: '...' },
  ... hasta 10 mensajes
]

Trigger: history.length >= 10
  → envía history[0..7] a Q1 (no-streaming, stream:false)
  → recibe summary
  → history = [{ role:'system', content:'[Contexto Compactado]: ...' }, msg8, msg9]

Flag _compacting[qId] previene race conditions
compact() se llama sin await (fire-and-forget)
```

### Sistema de Adjuntos (FileAttachments)
```
Extensiones permitidas: .txt .csv .md .py .dax .sql .json .js .html .css
Tamaño máximo: 2 MB por archivo
Lectura: FileReader.readAsText(file, 'UTF-8')
Entrada: click en 📎 o drag & drop sobre el textarea

Formato de inyección al inicio del prompt:
  ---
  [ARCHIVO ADJUNTO: nombre.py]
  ```py
  (contenido del archivo)
  ```
  ---

Limpieza: tras cada pipeline start + botón Nueva Conversación
```

### Q4 Preview (Renderizador SVG/HTML)
```
Detección regex (prioridad):
  1. ```svg ... ```  o  ```html ... ```  (bloque fenceado)
  2. <svg ...>...</svg>  (SVG raw en la respuesta)
  3. <!DOCTYPE html...  o  <html>...</html>  (documento completo)

Render:
  - SVG suelto → envuelto en HTML centrado sobre fondo blanco
  - HTML parcial → envuelto en documento minimal
  - HTML completo → inyectado as-is

iframe sandbox="allow-scripts"
  → JS interno puede ejecutarse (animaciones SVG, charts interactivos)
  → NO tiene acceso al DOM padre
  → NO tiene acceso a localStorage / cookies del padre

Descarga:
  Q4Preview._svgCode  →  Blob SVG  →  Image()  →  Canvas ×2
  Canvas.toDataURL('image/png') o ('image/jpeg', 0.95)
  → link temporal → .click() → URL.revokeObjectURL()
```

---

## 8. TASK_MATRIX — Sistema de Enrutamiento por Tarea

### Estructura de una entrada
```js
'17': {
  q1Title: '⚡ Sintetizador KPI',     // título del h2 de Q1
  q2: { title: '...', models: [{id, label}, ...] },
  q3: { title: '...', models: [{id, label}, ...] },
  q4: { title: '...', models: [{id, label}, ...] },
  q4SystemPrompt: '...',              // opcional — override del system prompt de Q4
  star: 2,                            // qId del "Top Pick" (borde dorado .quad-star)
}
```

### Grupos de tareas
| Grupo | Tareas | Dominio |
|-------|--------|---------|
| 1 | 1–10, 44 | Desarrollo y Automatización (Python, APIs, SQL, Docker, Video) |
| 2 | 11–20 | Análisis de Datos y BI (DAX, Pandas, Power BI, Monte Carlo) |
| 3 | 21–30, 48 | Pymes y Gestión (Sheets, ISO, Seguros, Agenda) |
| 4 | 31–47 | Contenido, Gaming, Redacción, IA Visual (SVG, Storyboard) |

**Total: 48 tareas + `default` + `auto` (detección semántica) = 50 entradas en el selector.**

### Auto-detección semántica (`value="auto"`)
- Mini-fetch no-streaming a `google/gemini-2.5-flash:free`
- System prompt: lista completa 1-48 + instrucción "responde solo con el número"
- Respuesta parseada como `parseInt` → `TaskRouter.apply(n)`
- Si falla: fallback a `'default'`, toast de aviso
- Se ejecuta ANTES del pipeline pero DESPUÉS de `Pipeline.active = true`

### q4SystemPrompt override
Tareas con instrucciones especiales para Q4 (fuerzan formato SVG en código markdown):
- **Tarea 17** — Informes y Dashboards → obliga bloque ` ```svg/html ``` ` sin texto adicional
- **Tarea 43** — Prompt Engineering para Imágenes IA → ídem

---

## 9. Buscador Predictivo de Tareas

```html
<input id="task-search" placeholder="🔍 Filtrar tarea…">
<select id="task-select">
  <option value="auto">🤖 Auto-detectar Tarea por IA</option>
  <option value="">── Selecciona manualmente (48 tareas) ──</option>
  <optgroup label="⚙️ Grupo 1..."> ... </optgroup>
  ...
</select>
```

Lógica en DOMContentLoaded:
- `option.hidden = true/false` por texto (case-insensitive)
- `optgroup.hidden = true/false` si todos sus hijos están ocultos
- Las opciones `auto` y `""` siempre visibles
- Sin dependencias externas — vanilla JS puro

---

## 10. Estado Actual del Proyecto (Julio 2025)

### ✅ Funciona en producción

| Característica | Estado | Notas |
|----------------|--------|-------|
| Pipeline 4 cuadrantes | ✅ Estable | Fase 1 bloqueante + Fase 2 paralelo |
| Stream SSE token a token | ✅ Estable | `ReadableStream` + buffer de chunks parciales |
| Rotación de keys 429/402 | ✅ Estable | Independiente por cuadrante |
| Fallback de modelos 404 | ✅ Estable | `MODEL_404_FALLBACKS` por cuadrante |
| Cifrado AES-GCM keys | ✅ Estable | PBKDF2 200k iter, salt+IV por save |
| SettingsModal 2 pisos | ✅ Estable | Piso 2 siempre relockea al abrir |
| Memoria ventana móvil | ✅ Estable | Trigger 10, compacta 8, preserva 2 |
| TASK_MATRIX 48 tareas | ✅ Completo | 4 grupos, modelos óptimos por tarea |
| Buscador predictivo | ✅ Completo | Filtra options/optgroups en tiempo real |
| Auto-detect semántico | ✅ Completo | gemini-2.5-flash → tarea 1-48 |
| Adjuntos de archivo | ✅ Completo | FileReader UTF-8, drag & drop, badges |
| Síntesis post-ejecución | ✅ Completo | Colapsable, copy to clipboard |
| Nueva Conversación | ✅ Completo | Reset total sin tocar keys/prefs |
| Temas claro/oscuro | ✅ Completo | Persistido, overrides `!important` |
| Colores por cuadrante | ✅ Completo | `el.style.setProperty(..., 'important')` |
| Q4 Vista Previa SVG/HTML | ✅ Completo | iframe sandboxed, 3 patrones regex |
| Descarga PNG/JPG High-DPI | ✅ Completo | Canvas ×2, fondo blanco JPG, revokeURL |
| q4SystemPrompt por tarea | ✅ Completo | Override en run, restaura ANTI_FLUFF |
| Launcher VBS silencioso | ✅ Completo | Sin ventana negra, `WshShell.Run(..., 0)` |
| DevSim (entorno dev) | ✅ Dev only | `window.simulateNetworkError(qId, 429/402)` |

### ⚠️ Conocido / Pendiente

| Item | Detalle |
|------|---------|
| `IS_PRODUCTION = false` | Cambiar a `true` antes de cualquier deploy |
| Scope aislado (módulo) | `AppState` etc. no accesibles desde DevTools (por diseño) |
| Tailwind via CDN | En producción real considerar bundle local para offline |
| iframe `sandbox` | Sin `allow-same-origin` → scripts del iframe no pueden acceder a parent |
| Auto-detect costo | Consume tokens en cada run con `value="auto"` — usar con criterio |

---

## 11. Constantes y localStorage

### Claves de localStorage

| Clave | Tipo | Descripción |
|-------|------|-------------|
| `nav_ia_keys_enc` | JSON `{salt, iv, data}` Base64 | Keys cifradas AES-GCM |
| `navia_theme` | `'light'` \| `'dark'` | Tema activo |
| `navia_q1_color` … `navia_q4_color` | `#rrggbb` | Color personalizado de cuadrante |

### Variables globales volátiles (RAM)

| Variable | Tipo | Descripción |
|----------|------|-------------|
| `AppState.apiKeys` | `string[]` | Keys descifradas (solo sesión) |
| `AppState.isUnlocked` | `bool` | Estado de autenticación |
| `AppState.currentTask` | `string` | Tarea activa (`'default'`, `'1'`…`'48'`) |
| `stagedFiles` | `Object[]` | Adjuntos pendientes `{name, ext, size, content}` |
| `QuadrantState[1..4].history` | `Object[]` | Historial OpenAI-compatible por cuadrante |
| `QuadrantState[1..4].keyIndex` | `number` | Índice de key activa por cuadrante |
| `Q4Preview._svgCode` | `string\|null` | SVG string para exportación |

---

## 12. System Prompts

```
SYSTEM_Q1 (Compresor):
  "Eres un Compresor de Prompts de IA. Tu única tarea es analizar la petición
   del usuario, eliminar saludos, cortesías y redundancias, y reescribir la
   instrucción en formato puramente técnico. Devuelve SOLO la instrucción
   optimizada, sin preámbulos."

SYSTEM_ANTI_FLUFF (Q2, Q3, Q4 por defecto):
  "Sé directo y conciso. Omite saludos, introducciones y conclusiones amables.
   Ve directo al grano. Si generas bloques de código, incluye únicamente
   comentarios inline esenciales."

SYSTEM_COMPACTOR (Compactador semántico de fondo):
  "Analiza el siguiente fragmento de historial de chat. Extrae y resume en un
   solo párrafo ultra-denso los hechos clave, variables definidas, tecnologías
   acordadas, código generado y el estado actual del problema."

q4SystemPrompt — Tareas 17 y 43 (override visual):
  "Genera exclusivamente el [mockup SVG / elemento visual] solicitado.
   REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque
   Markdown (```svg ... ``` o ```html ... ```). Sin texto introductorio,
   sin explicaciones, sin conclusiones."
```

---

## 13. Antes de Deploy a Producción

```js
// app.js línea ~24:
const IS_PRODUCTION = false;  // ← cambiar a true

// Efecto:
// - _DevSim desactivado (window.simulateNetworkError no existe)
// - Todos los fetch son reales (sin intercepción)
```

Checklist:
- [ ] `IS_PRODUCTION = true`
- [ ] Verificar que ninguna key de API esté hardcodeada
- [ ] Considerar bundle local de Tailwind (CDN puede no estar disponible offline)
- [ ] Revisar `iniciar.bat`: `PROJECT_DIR` apunta a la ruta correcta

---

## 14. Changelog

### v1.3.0 — Julio 2025 *(sesión actual)*
- **[NEW]** Descarga SVG → PNG/JPG desde Q4 (canvas ×2 High-DPI, fondo blanco JPG)
- **[NEW]** Panel flotante de herramientas de descarga en Q4 Vista Previa (oculto hasta detección SVG)
- **[NEW]** `q4SystemPrompt` por tarea: override del system prompt de Q4 en runtime
  - Tareas 17 y 43 fuerzan formato SVG en bloque Markdown
  - Se restaura `SYSTEM_ANTI_FLUFF` al cambiar de tarea (sin `newConversation`)
- **[FIX]** `#q4-preview-container` marcado como `relative` para contener tools flotantes
- **[IMPROVE]** Botones de descarga con `backdrop-filter: blur` — legibles sobre cualquier SVG

### v1.2.0 — Julio 2025
- **[NEW]** Q4 Vista Previa: pestaña `📝 Código` / `👁️ Vista Previa` con iframe sandboxed
- **[NEW]** Módulo `Q4Preview`: detección regex SVG/HTML, `_wrap()`, `switchTab()`, `reset()`
- **[NEW]** Auto-switch a pestaña Vista Previa al detectar SVG/HTML en respuesta Q4
- **[NEW]** Mini-pestañas con estilos naranja activo / gris inactivo
- **[NEW]** CSS `pulse-dot` para indicador de contenido listo en pestaña Vista Previa

### v1.1.0 — Julio 2025
- **[NEW]** Sistema de Adjuntos de Archivo: botón 📎, drag & drop, FileReader UTF-8
- **[NEW]** Validación: extensiones whitelist + límite 2 MB por archivo
- **[NEW]** Badges interactivos con × en `#attachments-preview`
- **[NEW]** Inyección al inicio del prompt como bloques Markdown estructurados
- **[NEW]** Limpieza automática post-pipeline + en Nueva Conversación

### v1.0.0 — Junio 2025 (baseline)
- **[NEW]** Buscador predictivo de tareas (filtro `option.hidden` en tiempo real)
- **[NEW]** Tareas 43-48 (Multimedia, Cotidianas, Creatividad)
- **[NEW]** Auto-detect semántico (`value="auto"` → mini-fetch → tarea 1-48)
- **[NEW]** SettingsModal 2 pisos (Piso 1 libre / Piso 2 protegido con password inline)
- **[NEW]** Panel de Síntesis post-ejecución con copy report
- **[NEW]** Botón Nueva Conversación (reset sin tocar keys/preferencias)
- **[NEW]** `QuadrantColors` con inline `!important` para sobrepasar tema claro
- **[NEW]** `MODEL_404_FALLBACKS` por cuadrante con retry de modelo
- **[NEW]** Launcher VBS silencioso (`Navegador IA.vbs`)
- **[FIX]** `iniciar.bat` sin `pause` en error handlers (no cuelga el proceso oculto)
- **[FIX]** `<main>` con `min-h-0` en lugar de altura hardcodeada

---

*Documentación generada: Julio 2025 — JW Solutions*
*Próxima actualización: al cierre de la siguiente sesión de desarrollo*
