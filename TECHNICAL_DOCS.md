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
├── app.js              # Toda la lógica JS (~4850 líneas)
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
| 8            | `AppState`                 | Pool de keys en RAM + `pipelineMode` activo. Nunca a disco.  |
| 16–29        | Constantes globales        | `STORAGE_KEY`, `PBKDF2_ITERATIONS`, límites adjuntos         |
| 45           | `Crypto`                   | AES-GCM 256 + PBKDF2 via WebCrypto API                       |
| 101          | `Storage`                  | Leer/guardar blob cifrado en localStorage                    |
| 111          | `LockScreen`               | Pantalla de desbloqueo con callback `_onUnlock`              |
| 220          | `SettingsModal`            | Modal 2 pisos: Piso 1 libre (tema+colores), Piso 2 protegido |
| 633          | `UI`                       | Toast, actualización botón ajustes                           |
| 675–685      | Constantes API             | `OPENROUTER_URL`, `RETRYABLE_CODES`, `MODEL_404_FALLBACKS`   |
| 688–696      | System prompts             | `SYSTEM_Q1`, `SYSTEM_ANTI_FLUFF`, `SYSTEM_COMPACTOR`, `CHAIN_FAILURE_PREFIX` |
| 706          | `QuadrantState`            | Estado por cuadrante: `keyIndex`, `controller`, `history[]`  |
| 718          | `LED`                      | Semáforos visuales + click handler de rotación manual        |
| 767          | `Output`                   | Render de burbujas (streaming), mensajes de error/warn       |
| 859          | `fetchStreamForQuadrant`   | Fetch SSE, retry 429/402, fallback 404, `_DevSim` hook, alimenta `RunLog` |
| 1060         | `Memory`                   | Ventana móvil: trigger=10, compacta 8, preserva 2            |
| 1185         | `Pipeline`                 | Flag `active` + botón Cancelar                               |
| 1205         | `RunLog`                   | Bitácora técnica de la ejecución en curso (errores, modelos, keys) |
| 1293         | `downloadTechnicalReport()`| Descarga la bitácora de `RunLog` como archivo `.md`          |
| 1337         | `Orchestrator`             | Fase 1 (Q1) → bifurca Fase 2 en `_runParallel` / `_runChain` según `pipelineMode` |
| 1676         | `TASK_MATRIX`              | 58 entradas (`default` + `'1'`…`'56'`), 5 grupos             |
| 4273         | `TaskRouter`               | Aplica TASK_MATRIX al DOM: títulos, selects, `.quad-star`, badge de modo |
| 4368         | `QuadrantColors`           | Colores personalizados — inline style con `!important`       |
| 4392         | `Theme`                    | Toggle claro/oscuro — `body.light-theme`                     |
| 4458         | `Synthesis`                | Panel post-ejecución: comparativa + copy report               |
| 4552         | `Q4Preview`                | Renderizador SVG/HTML en iframe sandboxed + pestañas         |
| 4643         | `downloadQ4Render`         | Exportación SVG → PNG/JPG (canvas x2 High-DPI)              |
| 4720         | `FileAttachments`          | Lectura FileReader UTF-8, badges, drag & drop, inject prompt |
| 4807         | `newConversation()`        | Reset total: historiales, outputs, LEDs, adjuntos, preview, `RunLog` |
| 4852         | `DOMContentLoaded`         | Init de todos los módulos y event bindings                   |

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
  │         └─ detecta tarea 1-56 → TaskRouter.apply(n)
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
  ├─ activeTask = TASK_MATRIX[AppState.currentTask] ?? TASK_MATRIX.default
  ├─ mode = activeTask.pipelineMode ?? 'parallel'
  │
  ├─[mode === 'parallel']──────────────────────────────────────┐
  │  ╔═══════════════════════════════════════════════════════╗ │
  │  ║  _runParallel — Q2, Q3, Q4 en paralelo (allSettled)  ║ │
  │  ║  [override Q4 system prompt si activeTask.q4SystemPrompt]║ │
  │  ║  Para cada qId activo:                                 ║ │
  │  ║    Memory.push(qId, 'user', finalPrompt)               ║ │
  │  ║    fetchStreamForQuadrant(qId, history)  → SSE stream  ║ │
  │  ║    Memory.push(qId, 'assistant', response)             ║ │
  │  ║    Memory.compact(qId) si trigger    fire-and-forget   ║ │
  │  ║    [si qId===4] Q4Preview.render(response)             ║ │
  │  ╚═══════════════════════════════════════════════════════╝ │
  └──────────────────────────────────────────────────────────────┘
  │
  ├─[mode === 'chain']─────────────────────────────────────────┐
  │  ╔═══════════════════════════════════════════════════════╗ │
  │  ║  _runChain — Q2 → Q3 → Q4 secuencial, contexto acumulado║ │
  │  ║  accumulatedContext = finalPrompt                       ║ │
  │  ║  for qId of downstream (en orden):                      ║ │
  │  ║    aplica qConf.chainSystemPrompt a history[0]          ║ │
  │  ║    Memory.push(qId, 'user', accumulatedContext)         ║ │
  │  ║    fetchStreamForQuadrant(qId, history)  → SSE stream   ║ │
  │  ║    éxito: Memory.push assistant + acumula               ║ │
  │  ║      accumulatedContext = originalPrompt +               ║ │
  │  ║        [OUTPUT CUADRANTE n] por cada output previo       ║ │
  │  ║    fallo: revierte push, nota de fallo en el contexto    ║ │
  │  ║      del siguiente cuadrante (degradación elegante)      ║ │
  │  ╚═══════════════════════════════════════════════════════╝ │
  └──────────────────────────────────────────────────────────────┘
  │
  └─ Synthesis.render(downstream, finalPrompt)   ← panel post-ejecución
```

`pipelineMode` no es un toggle manual — lo fuerza la tarea seleccionada en `TASK_MATRIX`.
`TaskRouter.apply()` actualiza `AppState.pipelineMode` y el badge `#pipeline-mode-badge`
(🔗 Cadena / ⚡ Paralelo) puramente como indicador visual.

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
'1': {
  pipelineMode: 'chain',              // 'chain' | 'parallel' — fuerza el modo de ejecución
  chainContext: 'full',               // 'full' — cada Q recibe prompt original + outputs previos
  q1Title: '⚡ Filtro de Sintaxis',    // título del h2 de Q1
  q2: {
    title: '...', models: [{id, label}, ...],
    role: 'Descripción corta del rol en la cadena',
    chainSystemPrompt: '...',         // system prompt de Q2 en modo chain (reemplaza SYSTEM_ANTI_FLUFF)
  },
  q3: { title: '...', models: [...], role: '...', chainSystemPrompt: '...' },
  q4: { title: '...', models: [...], role: '...', chainSystemPrompt: '...' },
  q4SystemPrompt: '...',              // opcional — override legacy de Q4, solo aplica en modo parallel
  star: 3,                            // qId del "Top Pick" (borde dorado .quad-star)
}
```

`chainSystemPrompt` sustituye a `SYSTEM_ANTI_FLUFF` en `history[0]` **únicamente** cuando
`pipelineMode === 'chain'`; en modo `parallel` se ignora. El campo `default` mantiene
`pipelineMode: 'parallel'` (estado genérico sin tarea seleccionada).

### Grupos de tareas
| Grupo | Tareas | Dominio |
|-------|--------|---------|
| 1 | 1–10, 44 | Desarrollo y Automatización (Python, APIs, SQL, Docker, Video) |
| 2 | 11–20 | Análisis de Datos y BI (DAX, Pandas, Power BI, Monte Carlo) |
| 3 | 21–30, 48 | Pymes y Gestión (Sheets, ISO, Seguros, Agenda) |
| 4 | 31–47 | Contenido, Gaming, Redacción, IA Visual (SVG, Storyboard) |
| 5 | 49–56 | Flujos Avanzados de Orquestación (ensemble, RAG simulado, LLMOps, agentes) |

**Total: 56 tareas + `default` + `auto` (detección semántica) = 58 entradas en el selector.**
Todas las tareas 1–56 usan `pipelineMode: 'chain'`; `default` usa `pipelineMode: 'parallel'`.

### Auto-detección semántica (`value="auto"`)
- Mini-fetch no-streaming a `google/gemini-2.5-flash:free`
- System prompt: lista completa 1-56 + instrucción "responde solo con el número"
- Respuesta parseada como `parseInt` → `TaskRouter.apply(n)`
- Si falla: fallback a `'default'`, toast de aviso
- Se ejecuta ANTES del pipeline pero DESPUÉS de `Pipeline.active = true`

### q4SystemPrompt override (legado, solo modo parallel)
Tareas con instrucciones especiales para Q4 (fuerzan formato SVG en código markdown),
usadas cuando `Orchestrator._runParallel()` procesa la tarea:
- **Tarea 17** — Informes y Dashboards → obliga bloque ` ```svg/html ``` ` sin texto adicional
- **Tarea 43** — Prompt Engineering para Imágenes IA → ídem

En modo `chain` (el caso de estas dos tareas, como todas las 1–56), el system prompt de Q4
lo controla `q4.chainSystemPrompt` dentro de `Orchestrator._runChain()`, con el mismo contenido.

---

## 8bis. RunLog — Reporte Técnico de Diagnóstico

Botón `🩺 Generar Reporte Técnico` en el panel de Síntesis, junto a `📋 Copiar Reporte`.
Distinto del reporte de Síntesis: **no incluye las respuestas de los modelos**, solo
metadata de diagnóstico pensada para entregar al equipo técnico cuando algo falla.

```
RunLog.reset(prompt, taskKey, taskLabel, mode, downstream)   ← al iniciar Orchestrator.run()
  → limpia entries[], guarda meta { rawPrompt, taskKey, taskLabel, pipelineMode, startedAt }

fetchStreamForQuadrant() reporta a RunLog.log(qId, level, message) en cada evento:
  · éxito (modelo + índice de llave usados)
  · rotación de llave por 429/402
  · fallback de modelo por 404
  · error HTTP no recuperable
  · error de red / stream interrumpido
  · pool de llaves agotado

_runChain() además registra la nota de degradación cuando un cuadrante
falla y el siguiente continúa con el mejor contexto disponible.

RunLog.finish()   ← al terminar run() (éxito, cancelación o fallo de Q1)
RunLog.build()    ← arma el .md: header (tarea, modo, duración, prompt original)
                    + una sección por cuadrante con estado final y eventos cronológicos
downloadTechnicalReport()  ← dispara la descarga como reporte-tecnico_navia_<timestamp>.md
```

Las llaves nunca aparecen en texto plano en el reporte — los mensajes ya usan el
índice 1-based (`Llave 2/3`), nunca el valor real, igual que en el resto de la app.

`RunLog.clear()` se llama en `newConversation()` — el reporte técnico es por-sesión-de-run,
no persiste entre conversaciones nuevas.

---

## 9. Buscador Predictivo de Tareas

```html
<input id="task-search" placeholder="🔍 Filtrar tarea…">
<select id="task-select">
  <option value="auto">🤖 Auto-detectar Tarea por IA</option>
  <option value="">── Selecciona manualmente (56 tareas) ──</option>
  <optgroup label="⚙️ Grupo 1..."> ... </optgroup>
  ...
  <optgroup label="🧠 Grupo 5 — Flujos Avanzados de Orquestación"> ... </optgroup>
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
| TASK_MATRIX 56 tareas | ✅ Completo | 5 grupos, modelos óptimos por tarea |
| Pipeline en Cadena | ✅ Completo | `_runChain()`: Q2→Q3→Q4 secuencial, contexto acumulado, degradación elegante en fallo |
| Buscador predictivo | ✅ Completo | Filtra options/optgroups en tiempo real |
| Auto-detect semántico | ✅ Completo | gemini-2.5-flash → tarea 1-56 |
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
| `AppState.currentTask` | `string` | Tarea activa (`'default'`, `'1'`…`'56'`) |
| `AppState.pipelineMode` | `'parallel'` \| `'chain'` | Modo de la tarea activa, lo fija `TaskRouter.apply()` |
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

q4SystemPrompt — Tareas 17 y 43 (override visual, legado modo parallel):
  "Genera exclusivamente el [mockup SVG / elemento visual] solicitado.
   REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque
   Markdown (```svg ... ``` o ```html ... ```). Sin texto introductorio,
   sin explicaciones, sin conclusiones."

CHAIN_FAILURE_PREFIX (reservado para uso futuro en chainSystemPrompt de Q3/Q4):
  "[NOTA DEL PIPELINE]: El cuadrante anterior no produjo output.
   Trabaja con el mejor contexto disponible e indica al inicio de tu
   respuesta qué información te faltó para completar tu rol óptimamente."

chainSystemPrompt — una entrada por Q2/Q3/Q4 en cada una de las 56 tareas:
  Reemplaza a SYSTEM_ANTI_FLUFF en modo 'chain'. Define el rol específico
  del cuadrante dentro de la cadena (ej. "Arquitecto" → "Implementador" → "QA").
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

### v1.4.1 — Julio 2026 *(sesión actual)*
- **[NEW]** Botón `🩺 Generar Reporte Técnico` en el panel de Síntesis
  - Módulo `RunLog`: bitácora de eventos de diagnóstico por cuadrante durante cada ejecución
    (rotaciones de key, fallbacks de modelo, errores HTTP/red, degradación de cadena, éxitos)
  - `fetchStreamForQuadrant()` y `_runChain()` alimentan `RunLog.log()` en cada punto de fallo/éxito existente
  - `downloadTechnicalReport()`: descarga el reporte como `.md`, sin incluir las respuestas
    completas de los modelos (eso lo sigue cubriendo `📋 Copiar Reporte` de `Synthesis`)
  - `RunLog.clear()` integrado en `newConversation()`
- **[FIX]** `qwen/qwen-2.5-coder-72b:free` (ID de modelo inválido, causaba HTTP 400 en Q3 de
  las 56 tareas nuevas) corregido a `qwen/qwen-2.5-coder-32b-instruct:free`
- **[FIX]** `iniciar.bat` / `debug.bat`: `PROJECT_DIR` corregido de `D:\PROYECTOS\Navegador IA`
  (no existía) a `D:\PROYECTOS\P005-Navegador_multi_IA`

### v1.4.0 — Julio 2026
- **[NEW]** Rediseño arquitectural: Pipeline en Cadena Multi-Rol Especializado
  - `pipelineMode` (`'chain'` | `'parallel'`) por tarea en `TASK_MATRIX`; `default` sigue en `'parallel'`
  - `Orchestrator._runChain()`: ejecuta Q2 → Q3 → Q4 secuencialmente, cada uno recibe
    el prompt original + todos los outputs previos acumulados (`chainContext: 'full'`)
  - `Orchestrator._runParallel()`: el comportamiento original (Promise.allSettled) extraído sin cambios funcionales
  - `Orchestrator.run()` bifurca la Fase 2 según `activeTask.pipelineMode`
  - Degradación elegante: si un cuadrante falla en la cadena, el siguiente recibe una nota
    explícita del fallo y continúa con el mejor contexto disponible en vez de abortar
  - `chainSystemPrompt` por Q2/Q3/Q4 en cada tarea — reemplaza `SYSTEM_ANTI_FLUFF` solo en modo `chain`
  - Constante `CHAIN_FAILURE_PREFIX` añadida junto a `SYSTEM_COMPACTOR`
- **[NEW]** 8 tareas nuevas (49–56): Investigación Predictiva/Ensemble, Auditoría de Código
  Multi-Capa, Contenido Estratégico Multi-Canal, RAG Simulado, Prompt Engineering Colaborativo,
  Diseño de Agentes Autónomos, LLMOps/Auditoría de Costos IA, Fine-Tuning Strategy
  — nuevo optgroup "🧠 Grupo 5 — Flujos Avanzados de Orquestación" en `index.html`
- **[NEW]** Badge `#pipeline-mode-badge` en la navbar junto al selector de tareas — indicativo,
  no es un toggle manual; `TaskRouter.apply()` lo actualiza junto con `AppState.pipelineMode`
- **[UPDATE]** `Orchestrator._autoDetect()`: `TASK_LIST` incluye tareas 49–56, rango de validación 1-48 → 1-56
- **[UPDATE]** `TASK_MATRIX` completa: 56 tareas (todas en modo `chain`) + `default` (`parallel`) = 57 entradas de configuración, 58 en el selector con `auto`

### v1.3.0 — Julio 2025
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
