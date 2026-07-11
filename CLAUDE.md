# IA ORCHESTRATOR - JW Solutions

SPA cliente-only que orquesta 4 LLMs en paralelo vía OpenRouter. Sin build tools. Sin backend. Sin framework.

## Cómo ejecutar

```
iniciar.bat   # Producción: servidor oculto + Edge modo app
debug.bat     # Diagnóstico: ventana PowerShell visible con logs HTTP
```

El proyecto requiere `http://localhost:8000` — no funciona desde `file://` porque WebCrypto API y ES Modules (`type="module"`) exigen origen HTTP.

El servidor es `System.Net.HttpListener` de .NET incrustado en un PS1 generado al vuelo por el bat. No necesita Python, Node ni ninguna otra dependencia.

## Antes de hacer deploy

Cambiar en [app.js:24](app.js):
```js
const IS_PRODUCTION = false;  // ← cambiar a true
```
Efecto: desactiva `_DevSim`, elimina `window.simulateNetworkError` del scope global y fuerza todos los fetch reales.

## Estructura de app.js (~1955 líneas)

| Línea | Módulo | Responsabilidad |
|-------|--------|-----------------|
| 1 | `AppState` | Pool de keys descifradas (solo en memoria RAM) |
| 39 | `Crypto` | AES-GCM 256 + PBKDF2 (200k iter, SHA-256) vía WebCrypto |
| 105 | `LockScreen` | Pantalla de desbloqueo con contraseña maestra |
| 202 | `SettingsModal` | Modal de ajustes: onboarding link, keys, 🎲 pwd gen, color pickers |
| 441 | Constantes API | `OPENROUTER_URL`, `RETRYABLE_CODES`, system prompts |
| 458 | `QuadrantState` | Estado por cuadrante: `keyIndex`, `controller`, `history[]` |
| 470 | `LED` | Semáforos visuales + click handler de rotación manual de key |
| 519 | `Output` | Render de burbujas de texto (streaming token a token) |
| 640 | `fetchStreamForQuadrant` | Fetch SSE con rotación 429/402 + `_DevSim` hook |
| 784 | `Memory` | Ventana móvil: trigger=10, compacta 8, preserva 2 |
| 909 | `Pipeline` | Flag `active` + botón Cancelar |
| 942 | `Orchestrator` | Fase 1 (Q1 secuencial) → Fase 2 (Q2/Q3/Q4 paralelo) |
| 1062 | `TASK_MATRIX` | 49 entradas (`default` + `'1'`…`'48'`), grupos 1-4 |
| 1654 | `TaskRouter` | Aplica TASK_MATRIX al DOM: títulos, selects, `.quad-star` |
| 1776 | `QuadrantColors` | Colores personalizados por cuadrante — guardados en localStorage |
| 1806 | `Theme` | Toggle claro/oscuro — `body.light-theme` — guardado en localStorage |
| 1875 | `DOMContentLoaded` | Init: Settings, LEDs, Theme, QuadrantColors, TaskRouter, Memory |

## Reglas de seguridad (no negociables)

- **Nunca** imprimir una API key en console.log. Usar siempre `maskKey(key)` → devuelve `…XXXX` (últimos 4 chars).
- **Nunca** `innerHTML` para output de LLMs. Usar `element.textContent +=` para prevenir XSS.
- `AppState.apiKeys[]` es el único lugar donde las keys viven en texto plano. Solo en RAM de sesión.
- localStorage solo contiene `{ salt, iv, data }` en Base64 (keys cifradas) + preferencias no sensibles (`navia_theme`, `navia_q1_color`…`navia_q4_color`). Nunca keys en claro.

## Flujo de datos (Pipeline)

```
rawPrompt
  → Memory.push(1, 'user')
  → Q1 (SSE stream, modelo free: gemini-2.5-flash)   ← FASE 1, bloqueante
  → optimizedText
  → Memory.push(1, 'assistant') + compact() en bg

  → Promise.allSettled([Q2, Q3, Q4])                  ← FASE 2, paralelo
      cada uno: Memory.push(qId, 'user', optimizedText)
               → fetch SSE
               → Memory.push(qId, 'assistant', response)
               → compact() en bg si shouldCompact()
```

`Memory.compact()` se llama **sin await** (fire-and-forget). Si falla, el historial queda intacto y se reintenta en el turno que vuelva a superar el trigger.

## Memoria de ventana móvil

- Trigger: `history.length >= 10`
- Compacta: mensajes [0…7] enviados al modelo de Q1 como texto plano (no-streaming, `stream: false`)
- Resultado: `[{ role:'system', content:'[Contexto Compactado]: …' }, msg8, msg9]`
- El flag `_compacting[qId]` previene race conditions si el trigger se supera antes de que acabe el fetch.

## Rotación de keys (429/402)

`fetchStreamForQuadrant` implementa retry independiente por cuadrante:
```
RETRYABLE_CODES = { 429, 402 }
→ nextKeyIdx = (keyIdx + 1) % total
→ delay 400ms
→ reintentar con mismo payload
```
Cada cuadrante lleva su propio `keyIndex` en `QuadrantState[qId].keyIndex`. El click en el LED rota la key manualmente.

## DevSim (solo IS_DEV)

Para testear rotación sin gastar saldo real:
```js
window.simulateNetworkError(quadrantId, 429)  // simula Rate Limit
window.simulateNetworkError(quadrantId, 402)  // simula Sin Saldo
```
El siguiente fetch de ese cuadrante recibe la respuesta sintética y ejecuta la lógica de rotación completa.

## Personalización UX (persistida en localStorage)

| Clave | Tipo | Descripción |
|-------|------|-------------|
| `navia_theme` | `'light'` \| `'dark'` | Tema actual. El módulo `Theme` lo aplica en `init()`. |
| `navia_q1_color` … `navia_q4_color` | hex `#rrggbb` | Color personalizado de cada cuadrante. `QuadrantColors.load()` los aplica como inline style al arrancar. Si no existen, los defaults del CSS (`.quad-blue` etc.) permanecen intactos. |

El módulo `Theme` añade/quita `body.light-theme`. El CSS de `index.html` tiene todos los overrides de `!important` necesarios para que el tema claro funcione correctamente sobre las clases Tailwind hardcodeadas.

El módulo `QuadrantColors` usa `el.style.borderColor` y `el.style.backgroundColor` (inline style). Cuando un cuadrante tiene `.quad-star`, el `border-color: !important` del CSS gana para el borde dorado, pero el `backgroundColor` del color personalizado sigue visible.

## Gotchas frecuentes

- **Scope isolation**: `type="module"` en index.html aísla todo el scope de app.js. `AppState`, `QuadrantState`, etc. no son accesibles desde DevTools console. Esto es intencional (seguridad).
- **`reader.cancel()` no `releaseLock()`**: cancel() cierra el stream TCP. releaseLock() solo libera el lock de JS.
- **`Memory.init()` obligatorio en DOMContentLoaded**: sin él, los historiales están vacíos y las llamadas fallan.
- **`TaskRouter` es data-driven**: no tiene keys hardcodeadas. Solo opera sobre `TASK_MATRIX[key]`. Nuevas tareas solo requieren añadir entrada al objeto.
- **Q4 inactivo por defecto**: el checkbox `active-4` empieza desmarcado. El Orchestrator lo respeta: solo incluye Q4 en `downstream` si el checkbox está marcado.
