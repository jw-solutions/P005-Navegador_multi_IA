// app.js — IA ORCHESTRATOR - JW Solutions
// BLOQUE 1: Sistema de Seguridad y Gestión de API Keys
// BLOQUE 2: Orquestador OpenRouter y Streamers en Paralelo

// ============================================================
// ESTADO GLOBAL (nunca serializado a disco en texto plano)
// ============================================================
const AppState = {
  apiKeys: [],      // Keys descifradas, solo en memoria de sesión
  isUnlocked: false,
  pipelineMode: 'parallel', // 'parallel' | 'chain' — se actualiza en TaskRouter.apply()
};

// ============================================================
// CONSTANTES — BLOQUE 1
// ============================================================
const STORAGE_KEY       = 'nav_ia_keys_enc';
const PBKDF2_ITERATIONS = 200_000;
const MIN_KEYS          = 3;
const TOTAL_KEY_SLOTS   = 5;

// ── Entorno ────────────────────────────────────────────────────
// Cambiar a `true` antes de cualquier despliegue a producción.
// Efecto: deshabilita DevSim, no expone herramientas de test en `window`.
const IS_PRODUCTION = false;
const IS_DEV        = !IS_PRODUCTION;

// ── Adjuntos de archivo (volátil — se vacía tras cada ejecución) ──
const VALID_ATTACH_EXT = new Set(['.txt','.csv','.md','.py','.dax','.sql','.json','.js','.html','.css']);
const MAX_ATTACH_BYTES = 2 * 1024 * 1024; // 2 MB
let stagedFiles = [];

// ── Helper de seguridad ────────────────────────────────────────
// Nunca imprimir llaves completas en logs. Usar SIEMPRE esta función
// si algún path de error necesita referenciar una key.
// Devuelve "…XXXX" (últimos 4 chars) o "…[vacía]" si la key no existe.
function maskKey(key) {
  if (!key || key.length < 5) return '…[vacía]';
  return `…${key.slice(-4)}`;
}

// ============================================================
// MÓDULO CRYPTO — WebCrypto API / AES-GCM 256 + PBKDF2
// ============================================================
const Crypto = {
  randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  },

  toBase64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },

  fromBase64(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  },

  async deriveKey(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encrypt(plaintext, password) {
    const salt = this.randomBytes(16);
    const iv   = this.randomBytes(12);
    const key  = await this.deriveKey(password, salt);
    const ct   = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    return { salt: this.toBase64(salt), iv: this.toBase64(iv), data: this.toBase64(ct) };
  },

  // Lanza excepción si la contraseña es incorrecta (AES-GCM verifica integridad automáticamente)
  async decrypt(stored, password) {
    const salt = this.fromBase64(stored.salt);
    const iv   = this.fromBase64(stored.iv);
    const ct   = this.fromBase64(stored.data);
    const key  = await this.deriveKey(password, salt);
    const pt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  },
};

// ============================================================
// MÓDULO STORAGE
// ============================================================
const Storage = {
  hasKeys()   { return localStorage.getItem(STORAGE_KEY) !== null; },
  save(data)  { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); },
  load()      { const r = localStorage.getItem(STORAGE_KEY); return r ? JSON.parse(r) : null; },
  clear()     { localStorage.removeItem(STORAGE_KEY); },
};

// ============================================================
// PANTALLA DE BLOQUEO
// ============================================================
const LockScreen = {
  el: null,
  _onUnlock: null,

  show(onUnlock = null) {
    this._onUnlock = onUnlock;
    if (this.el) return;
    this.el = document.createElement('div');
    this.el.id = 'lock-screen';
    this.el.className = [
      'fixed inset-0 z-50 flex items-center justify-center',
      'bg-gray-950/95 backdrop-blur-sm',
    ].join(' ');
    this.el.innerHTML = `
      <div class="bg-gray-900 border border-gray-700 rounded-2xl p-8 w-full max-w-sm shadow-2xl flex flex-col items-center space-y-5">
        <div class="text-5xl select-none">🔐</div>
        <div class="text-center space-y-1">
          <h2 class="text-base font-bold text-gray-100">Sesión Protegida</h2>
          <p class="text-xs text-gray-400 leading-relaxed">
            Tus llaves de API están cifradas con AES-256.<br>
            Ingresa tu Contraseña Maestra para continuar.
          </p>
        </div>
        <div class="w-full space-y-2">
          <input
            id="lock-pwd"
            type="password"
            placeholder="Contraseña Maestra..."
            autocomplete="current-password"
            class="w-full bg-gray-950 border border-gray-700 rounded-xl px-4 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-purple-500 transition"
          />
          <p id="lock-error" class="text-xs text-red-400 hidden text-center">
            Contraseña incorrecta. Intenta de nuevo.
          </p>
        </div>
        <button id="lock-submit" class="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold px-6 py-2.5 rounded-xl text-sm transition shadow-md">
          Desbloquear
        </button>
        <button id="lock-reset" class="text-xs text-gray-700 hover:text-red-500 transition mt-1">
          Olvidé mi contraseña · Borrar todo y empezar de nuevo
        </button>
      </div>
    `;
    document.body.appendChild(this.el);

    const input = this.el.querySelector('#lock-pwd');
    input.focus();
    input.addEventListener('keydown', e => { if (e.key === 'Enter') this._submit(); });
    this.el.querySelector('#lock-submit').addEventListener('click', () => this._submit());
    this.el.querySelector('#lock-reset').addEventListener('click', () => this._reset());
  },

  async _submit() {
    const input = document.getElementById('lock-pwd');
    const errEl = document.getElementById('lock-error');
    const btn   = document.getElementById('lock-submit');
    const pwd   = input.value;

    if (!pwd) { input.focus(); return; }

    btn.textContent = 'Descifrando…';
    btn.disabled = true;
    errEl.classList.add('hidden');

    try {
      const stored = Storage.load();
      const plain  = await Crypto.decrypt(stored, pwd);
      AppState.apiKeys    = JSON.parse(plain);
      AppState.isUnlocked = true;
      const cb = this._onUnlock;
      this._onUnlock = null;
      this._destroy();
      UI.updateSettingsBtn();
      if (cb) cb();
    } catch {
      errEl.classList.remove('hidden');
      input.value = '';
      input.focus();
      btn.textContent = 'Desbloquear';
      btn.disabled = false;
    }
  },

  _reset() {
    if (!confirm('⚠ Esto eliminará TODAS las llaves guardadas de forma permanente. ¿Continuar?')) return;
    Storage.clear();
    AppState.apiKeys    = [];
    AppState.isUnlocked = false;
    this._destroy();
    UI.updateSettingsBtn();
    UI.toast('🗑 Llaves borradas. Configura nuevas desde ⚙️ Ajustes.');
  },

  _destroy() {
    this.el?.remove();
    this.el = null;
  },
};

// ============================================================
// MODAL DE AJUSTES — Arquitectura de Dos Pisos
//
// Piso 1 (libre): Tema + Colores de cuadrantes en rejilla 2×2
// Piso 2 (protegido): API Keys + Contraseña — requiere auth inline
//
// El Piso 2 siempre arranca BLOQUEADO al abrir el modal.
// La autenticación es local al modal: AppState.apiKeys y
// AppState.isUnlocked permanecen en RAM para el pipeline activo.
// ============================================================
const SettingsModal = {
  el:          null,
  _currentPwd: null, // contraseña activa, sólo en memoria del modal

  open() {
    if (this.el) return;
    const isFirstTime = !Storage.hasKeys();

    this.el = document.createElement('div');
    this.el.id = 'settings-modal';
    this.el.className = 'fixed inset-0 z-40 flex items-center justify-center bg-black/60 backdrop-blur-sm';
    this.el.innerHTML = this._buildHTML(isFirstTime);

    document.body.appendChild(this.el);
    this._bindFloor1();
    this._bindFloor2Unlock(isFirstTime);

    // Primera vez: Piso 2 abierto de inmediato (nada que descifrar)
    if (isFirstTime) {
      this._revealFloor2(isFirstTime);
      this._bindFloor2Save(isFirstTime);
      this._validate();
    }
  },

  // ── HTML ──────────────────────────────────────────────────────
  _buildHTML(isFirstTime) {
    const isLight = document.body.classList.contains('light-theme');

    // Slots de API keys
    const keySlots = Array.from({ length: TOTAL_KEY_SLOTS }, (_, i) => {
      const n   = i + 1;
      const req = n <= MIN_KEYS;
      return `
        <div class="flex items-center space-x-2">
          <span class="text-[10px] font-bold w-4 text-center ${req ? 'text-blue-400' : 'text-gray-700'} shrink-0">${n}</span>
          <input id="key-${n}" type="password"
            placeholder="sk-or-v1-… ${req ? '(requerida)' : '(opcional)'}"
            autocomplete="off" spellcheck="false"
            class="flex-1 min-w-0 bg-gray-950 border ${req ? 'border-gray-600' : 'border-gray-800'} rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-700 focus:outline-none focus:border-blue-500 transition font-mono" />
          <button class="key-eye shrink-0 text-gray-700 hover:text-gray-300 text-sm transition select-none"
            data-for="key-${n}" title="Mostrar/ocultar">👁</button>
        </div>`;
    }).join('');

    // Piso 2 — sección bloqueada (no visible en primera vez)
    const f2LockedUI = isFirstTime ? '' : `
      <div id="f2-locked-ui" class="space-y-2.5">
        <div class="bg-gray-950/60 border border-gray-800 rounded-xl px-4 py-3.5 space-y-3">
          <p class="text-xs text-gray-500 leading-relaxed">
            Introduce tu Contraseña Maestra para acceder a tus llaves de API.
          </p>
          <div class="flex space-x-2">
            <input id="f2-unlock-pwd" type="password" placeholder="Contraseña Maestra…"
              autocomplete="current-password"
              class="flex-1 bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500 transition" />
            <button id="f2-unlock-btn"
              class="shrink-0 bg-purple-700 hover:bg-purple-600 text-white font-bold px-3 py-2 rounded-lg text-xs transition">
              Desbloquear
            </button>
          </div>
          <p id="f2-unlock-err" class="text-xs text-red-400 hidden">
            Contraseña incorrecta. Intenta de nuevo.
          </p>
        </div>
      </div>`;

    // Piso 2 — sección desbloqueada
    const pwdLabel = isFirstTime
      ? '🔑 Crea una Contraseña Maestra para cifrar tus llaves.'
      : '🔑 Cambiar contraseña (opcional — vacío = mantener la actual):';

    const f2UnlockedUI = `
      <div id="f2-unlocked-ui" class="${isFirstTime ? '' : 'hidden'} space-y-3">
        <div class="bg-blue-950/30 border border-blue-900/30 rounded-xl px-3 py-2.5 text-xs text-gray-400 leading-relaxed">
          Necesitas al menos ${MIN_KEYS} llaves de API de OpenRouter para comenzar.<br>
          <a href="https://openrouter.ai/settings/keys" target="_blank" rel="noopener noreferrer"
            class="text-blue-400 hover:text-blue-300 underline underline-offset-2 font-medium transition">
            → Obtener llaves en openrouter.ai/settings/keys ↗
          </a>
        </div>
        <div class="space-y-2">${keySlots}</div>
        <p id="modal-key-hint" class="text-xs text-yellow-500 hidden">
          ⚠ Necesitas al menos ${MIN_KEYS} llaves para guardar.
        </p>
        <div class="border-t border-gray-700 pt-3 space-y-2">
          <p class="text-xs text-gray-500">${pwdLabel}</p>
          <div class="flex items-center space-x-2">
            <input id="f2-pwd-new" type="password"
              placeholder="${isFirstTime ? 'Nueva Contraseña Maestra (mín. 8 caracteres)…' : 'Nueva contraseña (vacío = sin cambios)…'}"
              autocomplete="new-password"
              class="flex-1 bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500 transition" />
            <button id="modal-pwd-gen" title="Generar contraseña segura de 16 caracteres"
              class="shrink-0 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 hover:text-white px-2.5 py-2 rounded-lg text-sm transition select-none">🎲</button>
          </div>
          ${isFirstTime ? `
          <input id="f2-pwd-confirm" type="password" placeholder="Confirmar Contraseña Maestra…"
            autocomplete="new-password"
            class="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500 transition" />` : ''}
        </div>
        <p id="modal-error" class="text-xs text-red-400 hidden"></p>
        <button id="modal-save"
          class="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold px-4 py-2.5 rounded-xl text-xs transition opacity-40 cursor-not-allowed"
          disabled>🔒 Guardar Cifrado</button>
      </div>`;

    return `
      <div class="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-lg shadow-2xl flex flex-col overflow-hidden" style="max-height:90vh">

        <!-- Cabecera -->
        <div class="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-800 shrink-0">
          <div>
            <h2 class="text-sm font-bold text-gray-100">⚙️ Ajustes</h2>
            <p class="text-xs text-gray-600 mt-0.5">IA ORCHESTRATOR — JW Solutions</p>
          </div>
          <button id="modal-x" class="text-gray-600 hover:text-gray-200 text-lg leading-none transition px-1">✕</button>
        </div>

        <!-- Cuerpo desplazable -->
        <div class="overflow-y-auto flex-1">

          <!-- ══════════════════════════════════════════════════════
               PISO 1 — Apariencia y Preferencias  (sin contraseña)
               ══════════════════════════════════════════════════ -->
          <div class="px-6 py-5 space-y-4">
            <p class="text-[10px] font-bold uppercase tracking-widest text-gray-600">
              🎨 Piso 1 — Apariencia y Preferencias
            </p>

            <!-- Tema -->
            <div class="space-y-1.5">
              <p class="text-xs text-gray-400">Tema de la interfaz</p>
              <div class="grid grid-cols-2 gap-2">
                <button id="modal-theme-light"
                  class="py-2 rounded-xl text-xs font-semibold transition border
                    ${isLight
                      ? 'bg-amber-50 text-amber-800 border-amber-300'
                      : 'bg-gray-800 text-gray-400 border-gray-700 hover:bg-gray-700'}">
                  ☀️ Claro
                </button>
                <button id="modal-theme-dark"
                  class="py-2 rounded-xl text-xs font-semibold transition border
                    ${!isLight
                      ? 'bg-gray-700 text-blue-300 border-gray-600'
                      : 'bg-gray-800 text-gray-400 border-gray-700 hover:bg-gray-700'}">
                  🌙 Oscuro
                </button>
              </div>
            </div>

            <!-- Colores 2×2 (misma topología que la interfaz principal) -->
            <div class="space-y-1.5">
              <p class="text-xs text-gray-400">Color de cuadrantes</p>
              <div class="grid grid-cols-2 gap-2.5">
                ${[[1,'⚡ Optimizador'],[2,'🤖 Motor Avanzado'],[3,'💡 Alternativa'],[4,'🚀 Velocidad']].map(([qId, label]) => `
                <div class="flex items-center space-x-2.5 bg-gray-800/50 border border-gray-700/60 rounded-xl px-3 py-2.5">
                  <input type="color" id="color-q${qId}"
                    class="w-8 h-8 rounded-lg cursor-pointer p-0.5 bg-gray-900 border border-gray-700 shrink-0" />
                  <div class="min-w-0">
                    <span class="block text-[11px] font-semibold text-gray-300 truncate">${label}</span>
                    <span class="block text-[10px] text-gray-600">Cuadrante ${qId}</span>
                  </div>
                </div>`).join('')}
              </div>
            </div>
          </div>

          <!-- ══════════════════════════════════════════════════════
               PISO 2 — Seguridad y API Keys  (requiere contraseña)
               ══════════════════════════════════════════════════ -->
          <div class="border-t border-gray-800 px-6 py-5 space-y-3">
            <div class="flex items-center justify-between">
              <p class="text-[10px] font-bold uppercase tracking-widest text-gray-600">
                🔐 Piso 2 — Seguridad y API Keys
              </p>
              <span id="f2-badge"
                class="text-[10px] px-2 py-0.5 rounded-full border
                  ${isFirstTime
                    ? 'bg-green-900/30 text-green-400 border-green-800/40'
                    : 'bg-red-900/30   text-red-400   border-red-800/40'}">
                ${isFirstTime ? '🔓 PRIMERA VEZ' : '🔒 BLOQUEADO'}
              </span>
            </div>
            ${f2LockedUI}
            ${f2UnlockedUI}
          </div>

        </div>
      </div>`;
  },

  // ── Piso 1: tema + colores (siempre disponibles) ──────────────
  _bindFloor1() {
    const el = this.el;

    el.querySelector('#modal-x')
      ?.addEventListener('click', () => this.close());
    el.addEventListener('click', e => { if (e.target === el) this.close(); });

    // Botones de tema
    el.querySelector('#modal-theme-light')?.addEventListener('click', () => {
      Theme._set('light');
      this._syncThemeButtons();
    });
    el.querySelector('#modal-theme-dark')?.addEventListener('click', () => {
      Theme._set('dark');
      this._syncThemeButtons();
    });

    // Color pickers: carga valores y persiste cambios en tiempo real
    [1, 2, 3, 4].forEach(qId => {
      const picker = el.querySelector(`#color-q${qId}`);
      if (!picker) return;
      picker.value = localStorage.getItem(`navia_q${qId}_color`) ?? QuadrantColors.defaults[qId];
      picker.addEventListener('input', () => {
        QuadrantColors.apply(qId, picker.value);
        localStorage.setItem(`navia_q${qId}_color`, picker.value);
      });
    });
  },

  // Sincroniza el estado activo de los botones de tema tras cambio
  _syncThemeButtons() {
    const el      = this.el;
    const isLight = document.body.classList.contains('light-theme');
    if (!el) return;
    const lBtn = el.querySelector('#modal-theme-light');
    const dBtn = el.querySelector('#modal-theme-dark');
    if (lBtn) lBtn.className = `py-2 rounded-xl text-xs font-semibold transition border ${isLight ? 'bg-amber-50 text-amber-800 border-amber-300' : 'bg-gray-800 text-gray-400 border-gray-700 hover:bg-gray-700'}`;
    if (dBtn) dBtn.className = `py-2 rounded-xl text-xs font-semibold transition border ${!isLight ? 'bg-gray-700 text-blue-300 border-gray-600' : 'bg-gray-800 text-gray-400 border-gray-700 hover:bg-gray-700'}`;
  },

  // ── Piso 2: formulario de desbloqueo ─────────────────────────
  _bindFloor2Unlock(isFirstTime) {
    if (isFirstTime) return; // primera vez: sin bloqueo

    const el        = this.el;
    const unlockBtn = el.querySelector('#f2-unlock-btn');
    const unlockPwd = el.querySelector('#f2-unlock-pwd');

    unlockPwd?.addEventListener('keydown', e => {
      if (e.key === 'Enter') this._unlockFloor2(isFirstTime);
    });
    unlockBtn?.addEventListener('click', () => this._unlockFloor2(isFirstTime));
  },

  async _unlockFloor2(isFirstTime) {
    const el        = this.el;
    const unlockPwd = el.querySelector('#f2-unlock-pwd');
    const unlockErr = el.querySelector('#f2-unlock-err');
    const unlockBtn = el.querySelector('#f2-unlock-btn');
    const pwd       = unlockPwd?.value ?? '';

    if (!pwd) { unlockPwd?.focus(); return; }

    if (unlockBtn) { unlockBtn.textContent = 'Verificando…'; unlockBtn.disabled = true; }
    if (unlockErr) unlockErr.classList.add('hidden');

    try {
      const plain = await Crypto.decrypt(Storage.load(), pwd);
      AppState.apiKeys    = JSON.parse(plain);
      AppState.isUnlocked = true;
      this._currentPwd    = pwd;

      this._revealFloor2(isFirstTime);

      // Poblar inputs con las keys actuales
      AppState.apiKeys.forEach((k, i) => {
        const inp = el.querySelector(`#key-${i + 1}`);
        if (inp) inp.value = k;
      });

      this._bindFloor2Save(isFirstTime);
      this._validate();
      UI.updateSettingsBtn();
    } catch {
      if (unlockBtn) { unlockBtn.textContent = 'Desbloquear'; unlockBtn.disabled = false; }
      if (unlockErr) unlockErr.classList.remove('hidden');
      if (unlockPwd) { unlockPwd.value = ''; unlockPwd.focus(); }
    }
  },

  _revealFloor2(isFirstTime) {
    const el          = this.el;
    const lockedUI    = el.querySelector('#f2-locked-ui');
    const unlockedUI  = el.querySelector('#f2-unlocked-ui');
    const badge       = el.querySelector('#f2-badge');

    if (lockedUI)   lockedUI.style.display = 'none';
    if (unlockedUI) unlockedUI.classList.remove('hidden');
    if (badge) {
      badge.textContent = '🔓 DESBLOQUEADO';
      badge.className   = 'text-[10px] px-2 py-0.5 rounded-full border bg-green-900/30 text-green-400 border-green-800/40';
    }
  },

  // ── Piso 2: save + eye toggles + generador (post-desbloqueo) ──
  _bindFloor2Save(isFirstTime) {
    const el = this.el;

    // 👁 Mostrar / ocultar keys
    el.querySelectorAll('.key-eye').forEach(btn => {
      btn.addEventListener('click', () => {
        const inp = el.querySelector(`#${btn.dataset.for}`);
        if (!inp) return;
        inp.type        = inp.type === 'password' ? 'text' : 'password';
        btn.textContent = inp.type === 'password' ? '👁' : '🙈';
      });
    });

    // Validar al escribir en cualquier key input
    Array.from({ length: TOTAL_KEY_SLOTS }, (_, i) =>
      el.querySelector(`#key-${i + 1}`)
    ).filter(Boolean).forEach(inp => inp.addEventListener('input', () => this._validate()));

    // 🎲 Generador de contraseña
    el.querySelector('#modal-pwd-gen')?.addEventListener('click', () => {
      const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=?';
      const bytes   = crypto.getRandomValues(new Uint8Array(16));
      const pwd     = Array.from(bytes).map(b => charset[b % charset.length]).join('');
      const input   = el.querySelector('#f2-pwd-new');
      if (!input) return;
      input.value = pwd;
      input.type  = 'text';
      navigator.clipboard.writeText(pwd).catch(() => {});
      UI.toast('🎲 Contraseña generada y copiada al portapapeles');
    });

    el.querySelector('#modal-save')
      ?.addEventListener('click', () => this._save(isFirstTime));
  },

  // ── Validación del botón Guardar ──────────────────────────────
  _getFilledKeys() {
    return Array.from({ length: TOTAL_KEY_SLOTS }, (_, i) =>
      (this.el?.querySelector(`#key-${i + 1}`)?.value ?? '').trim()
    ).filter(v => v.length > 0);
  },

  _validate() {
    const filled  = this._getFilledKeys();
    const saveBtn = this.el?.querySelector('#modal-save');
    const hint    = this.el?.querySelector('#modal-key-hint');
    const enough  = filled.length >= MIN_KEYS;

    if (saveBtn) {
      saveBtn.disabled = !enough;
      saveBtn.classList.toggle('opacity-40',          !enough);
      saveBtn.classList.toggle('cursor-not-allowed',  !enough);
      saveBtn.classList.toggle('hover:from-blue-500',  enough);
      saveBtn.classList.toggle('hover:to-purple-500',  enough);
    }
    if (hint) hint.classList.toggle('hidden', filled.length === 0 || enough);
  },

  // ── Guardar (cifrar y persistir) ─────────────────────────────
  async _save(isFirstTime) {
    const el      = this.el;
    const errEl   = el.querySelector('#modal-error');
    const saveBtn = el.querySelector('#modal-save');
    const newPwd  = el.querySelector('#f2-pwd-new')?.value  ?? '';
    const confirm = el.querySelector('#f2-pwd-confirm')?.value ?? '';

    if (errEl) errEl.classList.add('hidden');

    let pwdToUse;
    if (isFirstTime) {
      if (newPwd.length < 8)     return this._showError('La contraseña debe tener al menos 8 caracteres.');
      if (newPwd !== confirm)    return this._showError('Las contraseñas no coinciden.');
      pwdToUse = newPwd;
    } else if (newPwd.length > 0) {
      if (newPwd.length < 8)     return this._showError('La nueva contraseña debe tener al menos 8 caracteres.');
      pwdToUse = newPwd;
    } else {
      pwdToUse = this._currentPwd;
    }

    if (!pwdToUse) return this._showError('Error: contraseña no disponible.');

    const keys = this._getFilledKeys();
    if (saveBtn) { saveBtn.textContent = 'Cifrando…'; saveBtn.disabled = true; }

    try {
      const encrypted = await Crypto.encrypt(JSON.stringify(keys), pwdToUse);
      Storage.save(encrypted);
      AppState.apiKeys    = keys;
      AppState.isUnlocked = true;
      this.close();
      UI.updateSettingsBtn();
      UI.toast(`✅ ${keys.length} llaves cifradas y guardadas con AES-256.`);
    } catch {
      this._showError('Error durante el cifrado. Intenta de nuevo.');
      if (saveBtn) { saveBtn.textContent = '🔒 Guardar Cifrado'; saveBtn.disabled = false; }
    }
  },

  _showError(msg) {
    const errEl = this.el?.querySelector('#modal-error');
    if (!errEl) return;
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
  },

  close() {
    this._currentPwd = null; // borrar contraseña de memoria del modal
    this.el?.remove();
    this.el = null;
  },
};

// ============================================================
// MÓDULO UI — UTILIDADES
// ============================================================
const UI = {
  updateSettingsBtn() {
    const btn = document.getElementById('btn-settings');
    if (!btn) return;
    const ok = AppState.isUnlocked && AppState.apiKeys.length >= MIN_KEYS;
    btn.classList.toggle('text-green-400',  ok);
    btn.classList.toggle('border-green-800', ok);
    btn.classList.toggle('text-gray-300',  !ok);
    btn.classList.toggle('border-gray-700', !ok);
    btn.title = ok
      ? `${AppState.apiKeys.length} llaves cargadas en memoria · Haz clic para editar`
      : 'Configura tus llaves de OpenRouter';
  },

  toast(msg, duration = 3500) {
    const t = document.createElement('div');
    t.className = [
      'fixed bottom-24 left-1/2 -translate-x-1/2 z-[60]',
      'bg-gray-800 border border-gray-700 text-xs text-gray-100',
      'px-5 py-2.5 rounded-xl shadow-xl',
      'opacity-0 transition-opacity duration-300 pointer-events-none whitespace-nowrap',
    ].join(' ');
    t.textContent = msg;
    document.body.appendChild(t);
    requestAnimationFrame(() => t.classList.replace('opacity-0', 'opacity-100'));
    setTimeout(() => {
      t.classList.replace('opacity-100', 'opacity-0');
      setTimeout(() => t.remove(), 350);
    }, duration);
  },
};


// ============================================================
// ============================================================
// BLOQUE 2: Orquestador OpenRouter y Streamers en Paralelo
// ============================================================
// ============================================================

// ============================================================
// CONSTANTES DE RED
// ============================================================
const OPENROUTER_URL   = 'https://openrouter.ai/api/v1/chat/completions';
const RETRYABLE_CODES  = new Set([429, 402]);

// Modelos de fallback por cuadrante cuando el modelo preferido devuelve 404.
// El orden importa: se prueban de izquierda a derecha hasta encontrar uno activo.
const MODEL_404_FALLBACKS = {
  1: ['google/gemini-2.0-flash-exp:free', 'meta-llama/llama-3.1-70b-instruct', 'deepseek/deepseek-chat'],
  2: ['deepseek/deepseek-chat', 'meta-llama/llama-3.1-70b-instruct'],
  3: ['meta-llama/llama-3.1-8b-instruct:free', 'qwen/qwen-2.5-72b-instruct:free'],
  4: ['meta-llama/llama-3.1-8b-instruct:free', 'deepseek/deepseek-chat'],
};

// System prompt inyectado en Q1 (Compresor de Prompt)
const SYSTEM_Q1 = `Eres un Compresor de Prompts de IA. Tu única tarea es analizar la petición del usuario, eliminar saludos, cortesías y redundancias, y reescribir la instrucción en un formato puramente técnico, directo y optimizado para que otros LLMs lo entiendan con el menor consumo de tokens posible. Devuelve SOLO la instrucción optimizada, sin preámbulos.`;

// System prompt inyectado en Q2, Q3, Q4 (Anti-Fluff en la salida)
const SYSTEM_ANTI_FLUFF = `Sé directo y conciso. Omite saludos, introducciones y conclusiones amables. Ve directo al grano. Si generas bloques de código, incluye únicamente comentarios inline esenciales.`;

// System prompt inyectado en el Compactador semántico de fondo
const SYSTEM_COMPACTOR = `Analiza el siguiente fragmento de historial de chat. Extrae y resume en un solo párrafo ultra-denso los hechos clave, variables definidas, tecnologías acordadas, código generado y el estado actual del problema. Evita preámbulos, ve directo a los datos técnicos. Tu resumen mantendrá la continuidad del chat.`;

// Prefijo inyectado en chainSystemPrompt de Q3 y Q4 cuando el cuadrante anterior falló
const CHAIN_FAILURE_PREFIX = `[NOTA DEL PIPELINE]: El cuadrante anterior no produjo output.
Trabaja con el mejor contexto disponible e indica al inicio de tu respuesta
qué información te faltó para completar tu rol óptimamente.\n\n`;

// ============================================================
// ESTADO POR CUADRANTE
// keyIndex    : índice actual en AppState.apiKeys para ESTE cuadrante (rotación independiente)
// controller  : AbortController del fetch en curso (para cancelar si llega nueva orquestación)
// ============================================================
const QuadrantState = {
  1: { keyIndex: 0, controller: null, history: [] },
  2: { keyIndex: 0, controller: null, history: [] },
  3: { keyIndex: 0, controller: null, history: [] },
  4: { keyIndex: 0, controller: null, history: [] },
};

const delay = ms => new Promise(r => setTimeout(r, ms));

// ============================================================
// MÓDULO LED — Semáforo visual por cuadrante
// ============================================================
const LED = {
  // Cambia clase CSS del LED según estado
  set(qId, state) {
    const el = document.getElementById(`led-${qId}`);
    if (!el) return;
    el.className = 'h-2 w-2 rounded-full cursor-pointer';
    switch (state) {
      case 'idle':      el.classList.add('bg-green-500',  'animate-pulse'); break;
      case 'loading':   el.classList.add('bg-blue-400',   'animate-pulse'); break;
      case 'streaming': el.classList.add('bg-green-400',  'animate-pulse'); break;
      case 'done':      el.classList.add('bg-green-500');                   break;
      case 'waiting':   el.classList.add('bg-yellow-400', 'animate-pulse'); break;
      case 'error':     el.classList.add('bg-red-500',    'animate-pulse'); break;
      case 'off':       el.classList.add('bg-gray-500');                    break;
    }
  },

  // Clic sobre el LED → rotación manual de llave para ese cuadrante
  bindClick(qId) {
    const el = document.getElementById(`led-${qId}`);
    if (!el) return;
    el.addEventListener('click', () => {
      const total = AppState.apiKeys.length;
      if (!AppState.isUnlocked || total === 0) {
        UI.toast('⚠ No hay llaves cargadas. Configura tus llaves primero.');
        return;
      }
      const prevIdx = QuadrantState[qId].keyIndex;
      QuadrantState[qId].keyIndex = (prevIdx + 1) % total;
      const newIdx = QuadrantState[qId].keyIndex;

      console.log(
        `%c[NavIA] Salto manual de llave en Cuadrante ${qId}. Pasando de Llave index ${prevIdx} a index ${newIdx}`,
        'color:#a78bfa; font-weight:bold'
      );

      // Destello amarillo 700ms → restaura estilo previo
      const saved = el.className;
      el.className = 'h-2 w-2 rounded-full cursor-pointer bg-yellow-400 animate-ping';
      setTimeout(() => { el.className = saved; }, 700);

      UI.toast(`🔄 Cuadrante ${qId}: ahora usa llave ${newIdx + 1}/${total}`);
    });
  },
};

// ============================================================
// MÓDULO OUTPUT — Renderizado de tokens y mensajes de estado
// ============================================================
const Output = {
  // Borra el área de salida antes de una nueva respuesta
  clear(qId) {
    const el = document.getElementById(`output-${qId}`);
    if (el) el.innerHTML = '';
  },

  // Añade un token al burbuja de respuesta activa del cuadrante.
  // La primera llamada crea la burbuja; las siguientes concatenan.
  appendToken(qId, token) {
    const el = document.getElementById(`output-${qId}`);
    if (!el) return;

    let bubble = el.querySelector('.stream-bubble');
    if (!bubble) {
      bubble = document.createElement('div');
      bubble.className = 'stream-bubble bg-gray-900/40 p-3 rounded-lg border border-gray-800 text-gray-300 text-xs leading-relaxed whitespace-pre-wrap break-words';
      el.appendChild(bubble);
    }
    bubble.textContent += token;
    // Auto-scroll al fondo
    el.scrollTop = el.scrollHeight;
  },

  // Nota temporal (4 s) al pie del cuadrante cuando se compacta su historial
  renderCompactionNote(qId) {
    const el = document.getElementById(`output-${qId}`);
    if (!el) return;
    const note = document.createElement('div');
    note.className = 'text-[10px] text-teal-400/50 mt-2 px-1 animate-pulse select-none';
    note.textContent = '🧹 Memoria optimizada para ahorrar tokens...';
    el.appendChild(note);
    setTimeout(() => note.remove(), 4000);
  },

  // Muestra el estado de espera durante la Fase 1 del pipeline
  renderWaiting(qId) {
    const el = document.getElementById(`output-${qId}`);
    if (!el) return;
    el.innerHTML = '';
    const div = document.createElement('div');
    div.className = 'waiting-msg flex items-center space-x-2 text-xs text-yellow-600/60 p-2 mt-1';
    div.innerHTML = '<span class="animate-pulse text-base">⏳</span><span>Esperando optimización de prompt…</span>';
    el.appendChild(div);
  },

  // Muestra un mensaje de estado/error debajo del stream
  renderMsg(qId, text, type = 'info') {
    const el = document.getElementById(`output-${qId}`);
    if (!el) return;
    const palette = {
      info:  'text-gray-500  bg-gray-900/30   border-gray-800',
      warn:  'text-yellow-400 bg-yellow-900/20 border-yellow-800/30',
      error: 'text-red-400   bg-red-900/20    border-red-800/30',
    };
    const div = document.createElement('div');
    div.className = `text-xs rounded p-2 border mt-1 ${palette[type] ?? palette.info}`;
    div.textContent = text;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
  },
};

// ============================================================
// FETCH CON STREAMING + BUCLE DE REINTENTOS POR CÓDIGO HTTP
// ============================================================

function getModelId(qId) {
  return document.getElementById(`model-${qId}`)?.value ?? '';
}

/**
 * Realiza la petición a OpenRouter para el cuadrante indicado.
 *
 * Flujo de reintentos:
 *  1. Toma la llave en QuadrantState[qId].keyIndex.
 *  2. Si la respuesta es 429 o 402 → LED rojo, imprime aviso, rota el índice
 *     solo para ESTE cuadrante, descuenta un intento, espera 400ms y reintenta.
 *  3. Si se agotan todas las llaves del pool → error crítico.
 *  4. Si la respuesta es 200 → comienza lectura SSE fragmento a fragmento.
 *
 * El buffer acumula bytes parciales entre chunks para que ninguna línea SSE
 * quede truncada al cruzar el límite de un chunk de red.
 */
/**
 * Realiza la petición streaming para un cuadrante y devuelve:
 *   · string  — el texto completo acumulado (éxito, puede estar vacío)
 *   · null    — error de red, HTTP no recuperable, pool agotado, o abort
 *
 * El valor de retorno es consumido por el Orquestador del Pipeline para
 * decidir si puede avanzar a la Fase 2 (con el prompt optimizado de Q1).
 */
async function fetchStreamForQuadrant(qId, messages) {
  const total = AppState.apiKeys.length;
  if (total === 0) {
    Output.renderMsg(qId, '❌ Sin llaves de API. Configura al menos 3 en ⚙️ Ajustes.', 'error');
    RunLog.log(qId, 'error', '❌ Sin llaves de API configuradas.');
    LED.set(qId, 'error');
    return null;
  }

  // Cancela cualquier fetch previo de este cuadrante
  QuadrantState[qId].controller?.abort();

  Output.clear(qId);
  LED.set(qId, 'loading');

  // Acumulador: construye el texto completo mientras llegan los tokens
  let fullText     = '';
  let attemptsLeft = total;
  let _modelFbIdx  = -1; // -1 = modelo del <select>; >=0 = MODEL_404_FALLBACKS[qId][idx]

  while (attemptsLeft > 0) {
    const keyIdx  = QuadrantState[qId].keyIndex;
    const key     = AppState.apiKeys[keyIdx];
    const _fbs    = MODEL_404_FALLBACKS[qId] ?? [];
    const model   = (_modelFbIdx >= 0 && _fbs[_modelFbIdx])
                    ? _fbs[_modelFbIdx]
                    : getModelId(qId);

    const controller = new AbortController();
    QuadrantState[qId].controller = controller;

    // ── Petición HTTP ──────────────────────────────────────────
    // [DEV] Si hay un error simulado pendiente lo usamos sin llamar a la red real.
    const _simCode = _DevSim.consume(qId);
    let response;
    if (_simCode !== null) {
      response = { ok: false, status: _simCode, statusText: 'Simulado por DevTools' };
    } else {
      try {
        response = await fetch(OPENROUTER_URL, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${key}`,
            'Content-Type':  'application/json',
            'HTTP-Referer':  window.location.origin,
            'X-Title':       'IA ORCHESTRATOR - JW Solutions',
          },
          body: JSON.stringify({ model, messages, stream: true }),
          signal: controller.signal,
        });
      } catch (err) {
        if (err.name === 'AbortError') return null; // cancelado intencionalmente por Pipeline.abort()
        LED.set(qId, 'error');
        Output.renderMsg(qId, `❌ Error de red: ${err.message}`, 'error');
        RunLog.log(qId, 'error', `❌ Error de red: ${err.message}`);
        return null;
      }
    }

    // ── 429 Rate Limit / 402 Sin Saldo → rotar llave ──────────
    if (RETRYABLE_CODES.has(response.status)) {
      const reason = response.status === 429 ? 'Rate Limit (429)' : 'Sin Saldo (402)';
      const nextKeyIdx = (keyIdx + 1) % total;
      console.log(
        `%c[NavIA] Q${qId} ❌ ${reason} — Llave ${keyIdx + 1} falló → rotando a Llave ${nextKeyIdx + 1}`,
        'color:#ef4444; font-weight:bold'
      );
      Output.renderMsg(qId, `⚠ Llave ${keyIdx + 1}: ${reason}. Rotando automáticamente…`, 'warn');
      RunLog.log(qId, 'warn', `⚠ Llave ${keyIdx + 1}: ${reason}. Rotando a llave ${nextKeyIdx + 1}. Modelo: ${model}`);
      LED.set(qId, 'error');

      QuadrantState[qId].keyIndex = (keyIdx + 1) % total;
      attemptsLeft--;

      if (attemptsLeft > 0) {
        await delay(400);
        LED.set(qId, 'loading');
      }
      continue;
    }

    // ── 404 Modelo no encontrado → intentar modelo alternativo ───
    if (response.status === 404) {
      const nextIdx = _modelFbIdx + 1;
      if (_fbs[nextIdx] !== undefined) {
        _modelFbIdx = nextIdx;
        Output.renderMsg(qId, `⚠ Modelo no disponible (404). Probando alternativo: ${_fbs[nextIdx]}…`, 'warn');
        RunLog.log(qId, 'warn', `⚠ Modelo ${model} no disponible (404). Probando alternativo: ${_fbs[nextIdx]}`);
        await delay(400);
        LED.set(qId, 'loading');
        continue; // no decrementa attemptsLeft — el problema es el modelo, no la llave
      }
      LED.set(qId, 'error');
      Output.renderMsg(qId, `❌ Modelo no encontrado (404) y sin más alternativas para Q${qId}.`, 'error');
      RunLog.log(qId, 'error', `❌ Modelo no encontrado (404) y sin más alternativas. Último intento: ${model}`);
      return null;
    }

    // ── Otro error HTTP no recuperable ─────────────────────────
    if (!response.ok) {
      LED.set(qId, 'error');
      Output.renderMsg(qId, `❌ HTTP ${response.status}: ${response.statusText}`, 'error');
      RunLog.log(qId, 'error', `❌ HTTP ${response.status}: ${response.statusText} — modelo: ${model}, llave ${keyIdx + 1}/${total}`);
      return null;
    }

    // ── Streaming SSE exitoso ──────────────────────────────────
    LED.set(qId, 'streaming');
    console.log(
      `%c[NavIA] Q${qId} ▶ Stream iniciado — modelo: ${model} — Llave ${keyIdx + 1}/${total}`,
      'color:#22c55e; font-weight:bold'
    );
    const reader  = response.body.getReader();
    const decoder = new TextDecoder();

    // buffer acumula bytes parciales entre chunks para no partir líneas SSE
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // La última línea del split puede estar incompleta → vuelve al buffer
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data:')) continue;

          const payload = trimmed.slice(5).trim();
          if (payload === '[DONE]') { buffer = ''; break; }

          try {
            const parsed = JSON.parse(payload);
            const token  = parsed.choices?.[0]?.delta?.content ?? '';
            if (token) {
              Output.appendToken(qId, token);
              fullText += token; // ← acumular para retorno al pipeline
            }
          } catch {
            // Chunk JSON malformado, se omite silenciosamente
          }
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        Output.renderMsg(qId, `⚠ Stream interrumpido: ${err.message}`, 'warn');
        RunLog.log(qId, 'error', `⚠ Stream interrumpido: ${err.message} — modelo: ${model}`);
      }
      return null;
    } finally {
      // reader.cancel() libera el lock Y envía la señal de cierre al ReadableStream,
      // cerrando la conexión TCP/HTTP subyacente sin esperar al garbage collector.
      // Es equivalente a releaseLock() + body.cancel() en una sola llamada async.
      reader.cancel().catch(() => {});
    }

    LED.set(qId, 'done');
    RunLog.log(qId, 'info', `✅ Éxito — modelo: ${model}, llave ${keyIdx + 1}/${total}`);
    return fullText; // ✅ Éxito — devuelve el texto completo al orquestador
  }

  // Pool agotado: ninguna llave funcionó
  LED.set(qId, 'error');
  Output.renderMsg(
    qId,
    `❌ Pool agotado: las ${total} llaves fallaron con 429/402. Añade llaves nuevas en ⚙️ Ajustes.`,
    'error'
  );
  RunLog.log(qId, 'error', `❌ Pool agotado: las ${total} llaves fallaron con 429/402.`);
  return null;
}

// ============================================================
// ============================================================
// BLOQUE 5: Memoria Persistente de Ventana Móvil
// ============================================================
// ============================================================

// ============================================================
// MÓDULO MEMORY — Historial conversacional por cuadrante
//                 + Compactación semántica en segundo plano
//
// Estructura del historial (OpenAI-compatible):
//   [
//     { role: 'system',    content: <system_prompt> },   ← siempre primero
//     { role: 'user',      content: <prompt_turno_1> },
//     { role: 'assistant', content: <respuesta_turno_1> },
//     { role: 'user',      content: <prompt_turno_2> },
//     ...
//   ]
//
// Al alcanzar TRIGGER mensajes:
//   · Se toman los primeros (TRIGGER - KEEP) = 8 → se resumen en Q1
//   · Los últimos KEEP = 2 se preservan íntegros
//   · El historial pasa de 10 mensajes a 3 (1 compactado + 2 recientes)
// ============================================================
const Memory = {
  TRIGGER: 10, // longitud del array que activa la compactación
  KEEP:     2, // mensajes recientes que se preservan sin tocar

  // Flags anti-doble-compactación por cuadrante (evita race conditions)
  _compacting: { 1: false, 2: false, 3: false, 4: false },

  // Inicializa (o reinicia) los historiales con el system prompt base de cada cuadrante.
  // Se llama en DOMContentLoaded; puede llamarse de nuevo para empezar sesión nueva.
  init() {
    QuadrantState[1].history = [{ role: 'system', content: SYSTEM_Q1         }];
    QuadrantState[2].history = [{ role: 'system', content: SYSTEM_ANTI_FLUFF }];
    QuadrantState[3].history = [{ role: 'system', content: SYSTEM_ANTI_FLUFF }];
    QuadrantState[4].history = [{ role: 'system', content: SYSTEM_ANTI_FLUFF }];
  },

  // Devuelve el array de historial de un cuadrante (referencia directa)
  get(qId) {
    return QuadrantState[qId].history ?? [];
  },

  // Añade un mensaje al historial
  push(qId, role, content) {
    QuadrantState[qId].history?.push({ role, content });
  },

  // True cuando el historial ha crecido lo suficiente para compactar
  shouldCompact(qId) {
    return (
      !this._compacting[qId] &&
      (QuadrantState[qId].history?.length ?? 0) >= this.TRIGGER
    );
  },

  /**
   * Compactación semántica en segundo plano.
   *
   * 1. Extrae los primeros (TRIGGER - KEEP) mensajes del array (los más antiguos).
   * 2. Los envía al modelo del Q1 como texto plano (una llamada no-streaming directa).
   * 3. Con el resumen recibido, reconstruye el historial:
   *      [{ system: '[Contexto Compactado]: …resumen…' }, …2_recientes… ]
   * 4. Si la llamada falla, el historial queda intacto y se reintenta en el
   *    próximo turno que supere TRIGGER.
   *
   * Se llama sin await para no bloquear el pipeline principal.
   */
  async compact(qId) {
    if (this._compacting[qId]) return;
    this._compacting[qId] = true;

    const history = QuadrantState[qId].history;
    const batchSize = this.TRIGGER - this.KEEP; // 8

    const batch  = history.slice(0, batchSize); // los 8 más antiguos
    const recent = history.slice(batchSize);    // los 2 más recientes

    Output.renderCompactionNote(qId);

    const summary = await this._callCompactor(batch);

    if (summary !== null) {
      // Sustituir historial: contexto compactado + 2 recientes
      QuadrantState[qId].history = [
        {
          role:    'system',
          content: `[Contexto Semántico Compactado de la Sesión]: ${summary}`,
        },
        ...recent,
      ];
    }
    // Si summary === null (fallo de red / API), el historial queda como estaba

    this._compacting[qId] = false;
  },

  /**
   * Llamada directa NO-STREAMING a OpenRouter para generar el resumen.
   * Usa el modelo activo en Q1 y la llave actual del pool.
   *
   * Los mensajes del batch se serializan como texto plano (un único mensaje de
   * usuario) para evitar conflictos de roles múltiples con la API.
   *
   * Retorna: string (resumen) | null (si falló)
   */
  async _callCompactor(batch) {
    const key   = AppState.apiKeys[QuadrantState[1].keyIndex];
    const model = getModelId(1);
    if (!key || !model) return null;

    // Serializar el batch como bloque de texto legible
    const historyText = batch
      .map(m => `[${m.role.toUpperCase()}]:\n${m.content}`)
      .join('\n\n---\n\n');

    try {
      const res = await fetch(OPENROUTER_URL, {
        method:  'POST',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type':  'application/json',
          'HTTP-Referer':  window.location.origin,
          'X-Title':       'IA ORCHESTRATOR - JW Solutions',
        },
        body: JSON.stringify({
          model,
          stream:   false, // tarea de fondo: solo necesitamos el JSON final
          messages: [
            { role: 'system', content: SYSTEM_COMPACTOR },
            { role: 'user',   content: historyText },
          ],
        }),
      });

      if (!res.ok) return null;
      const data = await res.json();
      return data.choices?.[0]?.message?.content?.trim() ?? null;
    } catch {
      return null;
    }
  },
};

// ============================================================
// PIPELINE — Estado y cancelación del pipeline completo
// ============================================================
const Pipeline = {
  active: false,

  // Aborta todos los streams activos (Q1-Q4) y marca el pipeline como inactivo.
  // Llamado al hacer clic en "⛔ Cancelar" durante cualquier fase.
  abort() {
    this.active = false;
    [1, 2, 3, 4].forEach(qId => QuadrantState[qId].controller?.abort());
  },
};

// ============================================================
// RUNLOG — Bitácora técnica de la ejecución en curso
//
// Recopila, sin exponer keys en texto plano (solo índice 1-based),
// los eventos de diagnóstico de cada cuadrante durante un run del
// pipeline: rotaciones de key, fallbacks de modelo, errores HTTP/red,
// interrupciones de stream y éxitos. Alimenta el botón
// "🩺 Generar Reporte Técnico" del panel de Síntesis.
// ============================================================
const RunLog = {
  entries: [],
  meta: null,

  reset(rawPrompt, taskKey, taskLabel, pipelineMode, downstream) {
    this.entries = [];
    this.meta = {
      rawPrompt,
      taskKey,
      taskLabel,
      pipelineMode,
      downstream: [...downstream],
      startedAt: new Date(),
      finishedAt: null,
    };
  },

  log(qId, level, message) {
    if (!this.meta) return; // sin run activo (p.ej. mini-fetch de compactación)
    this.entries.push({ qId, level, message, ts: new Date() });
  },

  finish() {
    if (this.meta) this.meta.finishedAt = new Date();
  },

  clear() {
    this.entries = [];
    this.meta = null;
  },

  // Construye el reporte técnico en texto plano (Markdown-friendly).
  // Deliberadamente NO incluye las respuestas completas de los modelos —
  // eso ya lo cubre "📋 Copiar Reporte" (Synthesis). Este es solo diagnóstico.
  build() {
    if (!this.meta) return '';
    const { rawPrompt, taskKey, taskLabel, pipelineMode, downstream, startedAt, finishedAt } = this.meta;
    const line = '─'.repeat(52);
    const durationSec = finishedAt ? ((finishedAt - startedAt) / 1000).toFixed(1) : '—';
    const fmtTime = d => d ? d.toLocaleString('es-MX') : '—';

    const header = [
      '=== REPORTE TÉCNICO DE DIAGNÓSTICO — IA ORCHESTRATOR - JW Solutions ===',
      `Fecha de inicio: ${fmtTime(startedAt)}`,
      `Duración total: ${durationSec}s`,
      `Tarea activa: ${taskLabel} (key: ${taskKey})`,
      `Modo de pipeline: ${pipelineMode === 'chain' ? '🔗 Cadena' : '⚡ Paralelo'}`,
      `Cuadrantes activos: ${downstream.map(id => `Q${id}`).join(', ') || 'ninguno'}`,
      line,
      'Prompt original del usuario:',
      `"${rawPrompt}"`,
      line,
    ].join('\n');

    const allQuadrants = [1, ...downstream];
    const sections = allQuadrants.map(qId => {
      const qEntries = this.entries.filter(e => e.qId === qId);
      const titleEl  = document.getElementById(`title-${qId}`);
      const title    = titleEl?.textContent?.trim() ?? `Cuadrante ${qId}`;

      let estado;
      if (qEntries.length === 0) {
        estado = '⏳ No ejecutado';
      } else if (qEntries.some(e => e.message.startsWith('✅'))) {
        estado = '✅ Éxito';
      } else if (qEntries.some(e => e.level === 'error')) {
        estado = '❌ Falló';
      } else {
        estado = '⚠ Con advertencias';
      }

      const eventLines = qEntries.length
        ? qEntries.map(e => `  [${e.ts.toLocaleTimeString('es-MX')}] ${e.message}`).join('\n')
        : '  (sin eventos registrados)';

      return `CUADRANTE ${qId} — ${title}\nEstado final: ${estado}\n${eventLines}`;
    }).join('\n\n');

    const hasErrors = this.entries.some(e => e.level === 'error');
    const footer = hasErrors
      ? '⚠ Esta ejecución presentó al menos un error — revisar detalle arriba.'
      : '✅ Sin errores registrados en esta ejecución.';

    return `${header}\n${sections}\n${line}\n${footer}\nGenerado por IA ORCHESTRATOR - JW Solutions`;
  },
};

// Dispara la descarga del reporte técnico como archivo .md
function downloadTechnicalReport() {
  if (!RunLog.meta) {
    UI.toast('⚠ Aún no hay ninguna ejecución para generar el reporte.');
    return;
  }
  const content = RunLog.build();
  const blob    = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url     = URL.createObjectURL(blob);
  const stamp   = RunLog.meta.startedAt.toISOString().replace(/[:.]/g, '-');

  const a = document.createElement('a');
  a.href = url;
  a.download = `reporte-tecnico_navia_${stamp}.md`;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);

  UI.toast('🩺 Reporte técnico descargado');
}

// Alterna la apariencia del botón de ejecución entre modo "ejecutar" y "cancelar"
function setPipelineBtn(running) {
  const btn = document.getElementById('btn-execute');
  if (!btn) return;
  if (running) {
    btn.textContent = '⛔ Cancelar';
    btn.classList.replace('from-blue-600', 'from-red-700');
    btn.classList.replace('to-purple-600', 'to-red-600');
    btn.classList.replace('hover:from-blue-500', 'hover:from-red-600');
    btn.classList.replace('hover:to-purple-500', 'hover:to-red-500');
  } else {
    btn.textContent = 'Ejecutar Orquestación';
    btn.classList.replace('from-red-700', 'from-blue-600');
    btn.classList.replace('to-red-600', 'to-purple-600');
    btn.classList.replace('hover:from-red-600', 'hover:from-blue-500');
    btn.classList.replace('hover:to-red-500', 'hover:to-purple-500');
  }
}

// ============================================================
// ORQUESTADOR — Pipeline secuencial de 2 fases con historial
// ============================================================
const Orchestrator = {
  async run(rawPrompt) {
    if (!AppState.isUnlocked || AppState.apiKeys.length < MIN_KEYS) {
      UI.toast('⚠ Configura tus llaves de OpenRouter primero (⚙️ Ajustes).');
      return;
    }

    const prompt = rawPrompt.trim();
    if (!prompt) return;

    Pipeline.active = true;
    setPipelineBtn(true);

    // ── Auto-detección semántica de tarea ─────────────────────
    const taskSelectEl = document.getElementById('task-select');
    if (taskSelectEl?.value === 'auto') {
      UI.toast('🤖 Detectando tarea automáticamente…');
      const detectedKey = await Orchestrator._autoDetect(prompt);
      if (!Pipeline.active) return; // cancelado durante auto-detect
      const resolvedKey = detectedKey ?? 'default';
      taskSelectEl.value = detectedKey ?? '';
      TaskRouter.apply(resolvedKey);
      if (detectedKey) {
        const label = taskSelectEl.querySelector(`option[value="${detectedKey}"]`)?.textContent ?? `Tarea ${detectedKey}`;
        UI.toast(`✅ Tarea detectada: ${label}`);
      } else {
        UI.toast('⚠ No se detectó tarea. Usando configuración general.');
      }
    }

    const downstream = [2, 3, 4].filter(qId =>
      document.getElementById(`active-${qId}`)?.checked ?? false
    );

    // Nueva bitácora técnica para esta ejecución (alimenta el reporte de diagnóstico)
    const _taskKey   = AppState.currentTask ?? 'default';
    const _taskLabel = taskSelectEl?.selectedOptions?.[0]?.textContent?.trim() ?? _taskKey;
    const _mode      = (TASK_MATRIX[_taskKey] ?? TASK_MATRIX['default']).pipelineMode ?? 'parallel';
    RunLog.reset(prompt, _taskKey, _taskLabel, _mode, downstream);

    [1, 2, 3, 4].forEach(qId => Output.clear(qId));
    Q4Preview.reset(); // limpiar preview de la ejecución anterior

    // ═══════════════════════════════════════════════════════════
    // FASE 1 — Cuadrante 1: Compresor de Prompt
    // Se añade el prompt crudo al historial de Q1 y se llama
    // con el array completo (incluye intercambios previos).
    // ═══════════════════════════════════════════════════════════
    downstream.forEach(qId => {
      Output.renderWaiting(qId);
      LED.set(qId, 'waiting');
      console.log(
        `%c[NavIA] Q${qId} ⏳ Esperando optimización de prompt... (Fase 1 en curso)`,
        'color:#eab308; font-weight:bold'
      );
    });

    // Prepend file context (si hay adjuntos) y vaciar staging area
    const _fileCtx       = FileAttachments.buildContext();
    const augmentedPrompt = _fileCtx ? `${_fileCtx}\n\n${prompt}` : prompt;
    FileAttachments.clear();

    Memory.push(1, 'user', augmentedPrompt);
    const optimizedText = await fetchStreamForQuadrant(1, Memory.get(1));

    // Guardar respuesta de Q1 y disparar compactación de fondo si aplica
    if (optimizedText !== null) {
      Memory.push(1, 'assistant', optimizedText);
      if (Memory.shouldCompact(1)) Memory.compact(1); // sin await → segundo plano
    }

    // ── Cancelación durante Fase 1 ────────────────────────────
    if (!Pipeline.active) {
      downstream.forEach(qId => {
        Output.clear(qId);
        LED.set(qId, document.getElementById(`active-${qId}`)?.checked ? 'done' : 'off');
      });
      RunLog.finish();
      setPipelineBtn(false);
      return;
    }

    // ── Q1 falló → abortar pipeline ───────────────────────────
    if (optimizedText === null) {
      // Revertir el push del user message fallido del historial de Q1
      QuadrantState[1].history.pop();
      downstream.forEach(qId => {
        Output.clear(qId);
        Output.renderMsg(qId, '⚠ El Optimizador (Q1) falló. Verifica las llaves y reintenta.', 'warn');
        LED.set(qId, 'off');
      });
      RunLog.finish();
      Pipeline.active = false;
      setPipelineBtn(false);
      return;
    }

    // ═══════════════════════════════════════════════════════════
    // FASE 2 — Q2, Q3, Q4 con el prompt optimizado.
    // Bifurca según pipelineMode de la tarea activa:
    //   'parallel' → los 3 reciben el mismo prompt y compiten (comportamiento original)
    //   'chain'    → Q2 → Q3 → Q4 en cadena, cada uno recibe el contexto acumulado
    // ═══════════════════════════════════════════════════════════
    const finalPrompt = optimizedText.trim() || prompt;
    const activeTask   = TASK_MATRIX[AppState.currentTask] ?? TASK_MATRIX['default'];
    const mode         = activeTask.pipelineMode ?? 'parallel';

    if (mode === 'chain') {
      await Orchestrator._runChain(downstream, finalPrompt, activeTask);
    } else {
      await Orchestrator._runParallel(downstream, finalPrompt, activeTask);
    }

    Pipeline.active = false;
    setPipelineBtn(false);
    RunLog.finish();

    // Mostrar panel de síntesis con comparativa de cuadrantes activos
    Synthesis.render(downstream, finalPrompt);
  },

  // ── Modo paralelo — comportamiento original sin cambios funcionales ──
  // Para cada cuadrante:
  //   1. Se añade el prompt optimizado al historial → conversación continua
  //   2. Se llama con el historial completo (incluye contexto previo)
  //   3. Se guarda la respuesta y, si aplica, se compacta en fondo
  async _runParallel(downstream, finalPrompt, activeTask) {
    // Ajustar system prompt de Q4 según la tarea activa.
    // Si la tarea tiene q4SystemPrompt (ej. visual/SVG), se aplica ahora;
    // si no, se restaura SYSTEM_ANTI_FLUFF para evitar que persista el de una tarea anterior.
    if (downstream.includes(4)) {
      const q4Sys = activeTask.q4SystemPrompt ?? SYSTEM_ANTI_FLUFF;
      if (QuadrantState[4].history[0]?.role === 'system') {
        QuadrantState[4].history[0].content = q4Sys;
      }
    }

    await Promise.allSettled(
      downstream.map(async qId => {
        // Añadir el prompt optimizado al historial de este cuadrante
        Memory.push(qId, 'user', finalPrompt);

        // El historial ya contiene el system prompt en [0] + toda la conversación anterior
        const response = await fetchStreamForQuadrant(qId, Memory.get(qId));

        if (response !== null) {
          // Guardar la respuesta del modelo en el historial
          Memory.push(qId, 'assistant', response);
          // Compactación semántica de fondo si el historial alcanzó el límite
          if (Memory.shouldCompact(qId)) Memory.compact(qId); // sin await → fondo
          // Q4: escanear respuesta para SVG/HTML y renderizar en la pestaña de preview
          if (qId === 4) Q4Preview.render(response);
        } else {
          // Si el stream falló, revertir el push del user message para mantener
          // el historial consistente (sin un 'user' huérfano sin 'assistant')
          QuadrantState[qId].history.pop();
        }
      })
    );
  },

  // ── Modo cadena — Q2 → Q3 → Q4 secuencial con contexto acumulado ──
  // Q2 recibe el prompt optimizado de Q1.
  // Q3 recibe: prompt original + output de Q2.
  // Q4 recibe: prompt original + output de Q2 + output de Q3.
  async _runChain(downstream, originalPrompt, taskConfig) {
    let accumulatedContext = originalPrompt;
    const outputs = {};

    for (const qId of downstream) {
      if (!Pipeline.active) break; // cancelado a mitad de la cadena

      // 1. Aplicar chainSystemPrompt si existe
      const qConf = taskConfig[`q${qId}`];
      if (qConf?.chainSystemPrompt && QuadrantState[qId].history[0]?.role === 'system') {
        QuadrantState[qId].history[0].content = qConf.chainSystemPrompt;
      }

      // 2. El prompt para este cuadrante es el contexto acumulado hasta ahora
      const promptForThisQuadrant = accumulatedContext;

      // 3. Mostrar estado de espera para los siguientes cuadrantes
      downstream
        .filter(id => id > qId)
        .forEach(id => {
          Output.renderWaiting(id);
          LED.set(id, 'waiting');
        });

      // 4. Ejecutar
      Memory.push(qId, 'user', promptForThisQuadrant);
      const response = await fetchStreamForQuadrant(qId, Memory.get(qId));

      if (response !== null) {
        Memory.push(qId, 'assistant', response);
        if (Memory.shouldCompact(qId)) Memory.compact(qId); // sin await → fondo
        if (qId === 4) Q4Preview.render(response);
        outputs[qId] = response;

        // Acumular contexto para el siguiente cuadrante:
        // [PROMPT ORIGINAL]\n\n[OUTPUT Q{n}]\n\n... por cada output producido hasta ahora
        accumulatedContext = originalPrompt + '\n\n' +
          Object.entries(outputs)
            .map(([id, out]) => `---\n[OUTPUT CUADRANTE ${id}]:\n${out}`)
            .join('\n\n');
      } else {
        // Fallo en un cuadrante de la cadena: degradación elegante.
        // El siguiente cuadrante recibe una nota explícita del fallo.
        QuadrantState[qId].history.pop();
        Output.renderMsg(
          qId,
          `⚠ Cuadrante ${qId} falló en la cadena. El siguiente paso recibirá el mejor contexto disponible.`,
          'warn'
        );
        RunLog.log(qId, 'warn', `⚠ Degradación de cadena: el siguiente cuadrante continuará con el mejor contexto disponible.`);
        accumulatedContext = accumulatedContext +
          `\n\n---\n[NOTA: El Cuadrante ${qId} falló. Ajusta tu respuesta con el contexto disponible.]`;
      }
    }
  },

  // Mini-fetch no-streaming para identificar la tarea más apropiada (1-48)
  async _autoDetect(userPrompt) {
    if (!AppState.apiKeys.length) return null;

    const TASK_LIST = `1. Scripts Python
2. Depuración de Código
3. Refactorización
4. Integración APIs
5. Frontend HTML/CSS/JS
6. Consultas SQL
7. Expresiones Regulares
8. Web Scraping
9. Entornos Docker/Git
10. Documentación Técnica
11. Modelado de Datos Relacionales
12. Fórmulas DAX (Power BI)
13. Power Query / M Language
14. Pandas Data Cleansing
15. Modelos Estocásticos
16. Auditoría Financiera
17. Informes y Dashboards
18. Grandes Volúmenes de Datos
19. Extracción PDFs
20. Predicción Monte Carlo
21. Google Sheets / Apps Script
22. Informes Administrativos
23. Análisis de Costos
24. Conciliación Bancaria
25. Auditoría Fondos de Salud
26. Cotizaciones y Seguros
27. Planificación de Proyectos / Gantt
28. Manuales ISO
29. Evaluación de Proveedores
30. Movilidad Eléctrica (ROI)
31. Guiones TikTok Gaming
32. Estrategia YouTube Gaming
33. SEO y Redes Sociales
34. UEFN / Fortnite Verse
35. Análisis Táctico FPS
36. Traducción Técnica
37. Resumen de Papers
38. Brainstorming de Marcas
39. Correos Corporativos
40. Prompt Engineering (LLMs)
41. Corrección de Estilo
42. Simulación de Entrevistas Técnicas
43. Prompt Engineering para Imágenes IA
44. Automatización de Video (FFmpeg/MoviePy)
45. Guiones y Storyboarding (Contenido Corto)
46. Redacción de Mensajes y Correos Cotidianos
47. Compresión de Textos y Extracción de Ideas
48. Planificación de Agenda y Bloques de Tiempo
49. Investigación Predictiva / Ensemble Multi-Modelo
50. Auditoría de Código Multi-Capa
51. Contenido Estratégico Multi-Canal
52. RAG Simulado / Análisis de Documento
53. Prompt Engineering Colaborativo
54. Diseño de Agentes Autónomos
55. LLMOps / Auditoría de Costos IA
56. Fine-Tuning Strategy`;

    const sysPrompt = `Eres un clasificador de tareas. Analiza el prompt del usuario y responde ÚNICAMENTE con el número (1-56) de la tarea más apropiada de esta lista:\n${TASK_LIST}\nResponde SOLO con el número, sin explicación, sin puntos, sin texto adicional.`;

    const models = ['google/gemini-2.5-flash:free', ...(MODEL_404_FALLBACKS[1] ?? [])];
    const key = AppState.apiKeys[QuadrantState[1].keyIndex % AppState.apiKeys.length];

    for (const model of models) {
      try {
        const resp = await fetch(OPENROUTER_URL, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${key}`,
            'Content-Type': 'application/json',
            'X-Title': 'IA ORCHESTRATOR - JW Solutions',
          },
          body: JSON.stringify({
            model,
            stream: false,
            messages: [
              { role: 'system', content: sysPrompt },
              { role: 'user',   content: userPrompt },
            ],
            max_tokens: 10,
          }),
        });

        if (!resp.ok) continue;

        const json = await resp.json();
        const raw  = json?.choices?.[0]?.message?.content?.trim() ?? '';
        const num  = parseInt(raw.replace(/\D/g, ''), 10);
        if (num >= 1 && num <= 56) return String(num);
      } catch (_) {
        // try next model
      }
    }
    return null;
  },
};

// ============================================================
// ============================================================
// BLOQUE 3: Matriz de Tareas y Enrutamiento Dinámico
// ============================================================
// ============================================================

// ============================================================
// TASK_MATRIX — Diccionario de configuración para las 48 tareas
//
// Estructura de cada entrada:
//   q1Title : texto del encabezado del cuadrante 1 (optimizador)
//   q2 / q3 / q4 : { title, models: [{id, label}] }
//     · title  → texto del h2 del cuadrante
//     · models → array ordenado de mejor a peor para esa tarea;
//                el primer item queda seleccionado automáticamente
//   star : 2 | 3 | 4 | null  → cuadrante con el mejor modelo absoluto
//          para esa tarea (recibe borde dorado + badge "⭐ Top Pick")
// ============================================================
const TASK_MATRIX = {

  // ── Estado por defecto — modo paralelo (sin tarea seleccionada) ──────
  'default': {
    pipelineMode: 'parallel',
    q1Title: '⚡ Filtro Optimizador',
    q2: {
      title: '🤖 Motor Avanzado',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
        { id: 'openai/gpt-4o',               label: 'GPT-4o' },
      ],
      role: 'Respuesta de calidad general',
    },
    q3: {
      title: '💡 Alternativa Gratis',
      models: [
        { id: 'deepseek/deepseek-chat',        label: 'DeepSeek Chat' },
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free',  label: 'Qwen 2.5 Coder Free' },
      ],
      role: 'Perspectiva alternativa',
    },
    q4: {
      title: '🚀 Contrapeso de Velocidad',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1 70B' },
        { id: 'google/gemini-2.5-flash:free',       label: 'Gemini 2.5 Flash Free' },
      ],
      role: 'Respuesta rápida de contraste',
    },
    star: 2,
  },

  // ════════════════════════════════════════════════════════════════════
  // GRUPO 1: DESARROLLO Y AUTOMATIZACIÓN
  // ════════════════════════════════════════════════════════════════════

  '1': { // Escritura de Scripts Python
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Sintaxis',
    q2: {
      title: '🤖 Arquitecto Python',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Diseña la lógica, estructura de funciones y manejo de errores',
      chainSystemPrompt: `Eres el Arquitecto de este pipeline de desarrollo Python.
Tu rol: diseñar la lógica del script — estructura de funciones, flujo de datos, manejo de errores, tipos de retorno.
Produce el esqueleto comentado del código con decisiones de diseño explicadas.
Tu output será implementado por un modelo especializado en código. Sé preciso en las interfaces entre funciones.
Sin saludos. Directo al diseño técnico.`,
    },
    q3: {
      title: '💡 Implementador Qwen',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder (Top)' },
        { id: 'deepseek/deepseek-chat',        label: 'DeepSeek Chat' },
      ],
      role: 'Implementa el diseño de Q2 en código Python completo',
      chainSystemPrompt: `Eres el Implementador de este pipeline. Recibirás el diseño arquitectural del cuadrante anterior.
Tu rol: implementar el código Python completo y funcional respetando cada decisión de diseño recibida.
Añade type hints, docstrings, logging básico y manejo de excepciones específicas.
Entrega el script listo para ejecutar. Sin texto adicional fuera del código y sus comentarios.`,
    },
    q4: {
      title: '🚀 QA y Tests',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash Free' },
      ],
      role: 'Detecta bugs en el código de Q3 y genera test cases',
      chainSystemPrompt: `Eres el QA de este pipeline. Recibirás el código Python implementado por el cuadrante anterior.
Tu rol: revisar el código, detectar bugs potenciales, edge cases no manejados y problemas de performance.
Produce: (1) lista de issues encontrados con línea aproximada, (2) versión corregida si hay bugs críticos,
(3) mínimo 3 test cases con pytest listos para correr. Sin saludos, directo a los hallazgos.`,
    },
    star: 3,
  },

  '2': { // Depuración de Código
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Analizador de Errores',
    q2: {
      title: '🤖 Diagnosticador',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
        { id: 'openai/gpt-4o',               label: 'GPT-4o' },
      ],
      role: 'Analiza el bug y traza la causa raíz',
      chainSystemPrompt: `Eres el Diagnosticador de este pipeline de debugging.
Tu rol: analizar el código o el error reportado, trazar la causa raíz exacta, explicar el porqué del fallo.
Produce: (1) causa raíz identificada, (2) mecanismo del fallo explicado técnicamente,
(3) descripción precisa de qué debe corregirse (sin escribir el fix aún).
Tu output será usado por un modelo especializado en código para escribir el fix exacto.`,
    },
    q3: {
      title: '💡 Cirujano de Código',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Produce el fix exacto basado en el diagnóstico de Q2',
      chainSystemPrompt: `Eres el Cirujano de este pipeline. Recibirás el diagnóstico del cuadrante anterior.
Tu rol: escribir el fix con el mínimo de cambios necesarios. No refactorices, no agregues features.
Entrega exclusivamente el código corregido con comentarios inline en cada línea modificada
explicando qué cambiaste y por qué. Mínimo de cambios, máximo de precisión.`,
    },
    q4: {
      title: '🚀 Validador del Fix',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Verifica que el fix no rompe otras partes del código',
      chainSystemPrompt: `Eres el Validador de este pipeline. Recibirás el diagnóstico y el fix propuesto.
Tu rol: verificar que el fix resuelve la causa raíz sin introducir regresiones.
Produce: (1) confirmación o refutación del fix, (2) riesgos de regresión identificados,
(3) un test de regresión mínimo para verificar que el bug no vuelve. Sin relleno.`,
    },
    star: 2,
  },

  '3': { // Refactorización
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Optimizador de Contexto',
    q2: {
      title: '🤖 Auditor de Deuda Técnica',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Identifica todos los problemas del código actual',
      chainSystemPrompt: `Eres el Auditor de deuda técnica de este pipeline.
Tu rol: analizar el código y producir un informe técnico completo de problemas.
Cubre: acoplamiento excesivo, código duplicado, naming confuso, complejidad ciclomática,
violaciones de SOLID/DRY/KISS, dead code, magic numbers, comentarios obsoletos.
Sé específico con líneas o funciones. Tu informe será la guía del refactorizador.`,
    },
    q3: {
      title: '💡 Refactorizador',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Produce el código refactorizado completo basado en la auditoría de Q2',
      chainSystemPrompt: `Eres el Refactorizador de este pipeline. Recibirás la auditoría de deuda técnica del cuadrante anterior.
Tu rol: producir el código refactorizado completo resolviendo cada issue identificado.
Entrega el código listo para usar, sin modificar la funcionalidad externa. 
Usa comentarios inline solo donde la decisión de diseño no sea obvia.`,
    },
    q4: {
      title: '🚀 Documentador',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Genera changelog y documentación del código refactorizado',
      chainSystemPrompt: `Eres el Documentador final de este pipeline. Recibirás el código original, la auditoría y el código refactorizado.
Tu rol: documentar qué cambió y por qué.
Produce: (1) changelog con cada cambio relevante y su justificación,
(2) sección README actualizada que describa la estructura del módulo refactorizado.
Formato limpio, técnico, sin relleno.`,
    },
    star: 3,
  },

  '4': { // Integración APIs
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Parser de Endpoints',
    q2: {
      title: '🤖 Diseñador de Contrato API',
      models: [
        { id: 'openai/gpt-4o',               label: 'GPT-4o' },
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define el contrato de la integración: endpoints, payloads, errores',
      chainSystemPrompt: `Eres el Diseñador de contrato de este pipeline de integración API.
Tu rol: definir el contrato técnico completo — endpoints, métodos HTTP, headers requeridos,
estructura de payloads de request/response, códigos de error esperados, estrategia de rate limiting.
Produce el contrato como especificación técnica que un desarrollador puede implementar directamente.
Sin código aún. Solo el diseño del contrato.`,
    },
    q3: {
      title: '💡 Implementador de Integración',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el código de integración completo basado en el contrato de Q2',
      chainSystemPrompt: `Eres el Implementador de este pipeline. Recibirás el contrato de integración API del cuadrante anterior.
Tu rol: escribir el código de integración completo siguiendo el contrato exactamente.
Incluye: retry logic con backoff exponencial, logging de requests/responses, manejo de todos los errores definidos,
tipado fuerte si el lenguaje lo permite. Código production-ready.`,
    },
    q4: {
      title: '🚀 Auditor de Seguridad',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Revisa la implementación de Q3 en busca de vulnerabilidades',
      chainSystemPrompt: `Eres el Auditor de seguridad de este pipeline. Recibirás la implementación de integración API del cuadrante anterior.
Tu rol: auditar la seguridad de la implementación.
Revisa: exposición de credenciales, validación de inputs, superficies de inyección,
manejo seguro de tokens, logging que no exponga datos sensibles, HTTPS forzado.
Produce: lista de vulnerabilidades encontradas + versión corregida de los fragmentos problemáticos.`,
    },
    star: 2,
  },

  '5': { // Frontend HTML/CSS/JS
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Estructurador DOM',
    q2: {
      title: '🤖 UX Architect',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define estructura semántica, componentes y jerarquía visual',
      chainSystemPrompt: `Eres el UX Architect de este pipeline frontend.
Tu rol: definir la arquitectura de la UI antes de escribir código.
Produce: (1) estructura HTML semántica por secciones con roles ARIA,
(2) lista de componentes necesarios y sus estados (hover, active, disabled, error),
(3) jerarquía visual: qué es lo primero que el usuario debe ver y por qué,
(4) decisiones de accesibilidad. Sin código CSS/JS aún. Solo el blueprint.`,
    },
    q3: {
      title: '💡 Builder Frontend',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa HTML+CSS+JS completo siguiendo el blueprint de Q2',
      chainSystemPrompt: `Eres el Builder de este pipeline frontend. Recibirás el blueprint de arquitectura UI del cuadrante anterior.
Tu rol: implementar el HTML+CSS+JS completo y funcional.
Requisitos: responsivo mobile-first, variables CSS para colores/tipografía, interacciones JS sin frameworks externos,
semántica HTML5 correcta. Entrega el archivo completo listo para abrir en browser.`,
    },
    q4: {
      title: '🚀 Polish y Performance',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Optimiza performance y añade micro-interacciones al código de Q3',
      chainSystemPrompt: `Eres el especialista de Polish de este pipeline. Recibirás el frontend implementado por el cuadrante anterior.
Tu rol: optimizar y pulir la implementación.
Produce la versión mejorada con: lazy loading donde aplique, transiciones CSS suaves,
micro-animaciones en interacciones clave, optimización de repaints, mejoras de accesibilidad detectadas.
Entrega el archivo completo con los cambios aplicados.`,
    },
    star: 2,
  },

  '6': { // Consultas SQL Complejas
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Validador de Esquemas',
    q2: {
      title: '🤖 Analista de Esquema SQL',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Analiza las relaciones del esquema y diseña la estrategia de query',
      chainSystemPrompt: `Eres el Analista de esquema de este pipeline SQL.
Tu rol: antes de escribir una línea de SQL, analizar el problema.
Produce: (1) mapa de relaciones relevantes entre tablas, (2) índices que deberían existir para esta query,
(3) estrategia de query — qué enfoque usar (CTE, subquery, window function, JOIN order) y por qué,
(4) volumetría estimada y su impacto en la estrategia.
Tu análisis será usado por el Query Builder para escribir el SQL óptimo.`,
    },
    q3: {
      title: '💡 Query Builder',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Escribe el SQL optimizado siguiendo la estrategia de Q2',
      chainSystemPrompt: `Eres el Query Builder de este pipeline. Recibirás el análisis del esquema y la estrategia del cuadrante anterior.
Tu rol: escribir el SQL completo y optimizado siguiendo exactamente la estrategia definida.
Incluye: CTEs bien nombradas, hints de índice si aplica, comentarios en bloques lógicos complejos,
versión EXPLAIN-ready. Dialect: especificado en el prompt original.`,
    },
    q4: {
      title: '🚀 Auditor SQL',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Detecta problemas de performance y seguridad en la query de Q3',
      chainSystemPrompt: `Eres el Auditor SQL de este pipeline. Recibirás la query producida por el cuadrante anterior.
Tu rol: auditar la query en dos dimensiones.
Performance: N+1 potencial, full table scans, cartesian products accidentales, índices no aprovechados.
Seguridad: superficies de SQL injection, exposición de datos sensibles en resultados.
Produce: hallazgos con severidad + versión optimizada de la query si hay problemas críticos.`,
    },
    star: 3,
  },

  '7': { // Expresiones Regulares
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Patrones',
    q2: {
      title: '🤖 Analizador de Casos',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Descompone el problema regex en casos y edge cases',
      chainSystemPrompt: `Eres el Analizador de patrones de este pipeline regex.
Tu rol: descomponer el problema antes de construir la expresión.
Produce: (1) formato exacto que debe matchear con 3-5 ejemplos válidos,
(2) formatos que NO deben matchear con 3-5 contraejemplos,
(3) edge cases específicos del dominio (caracteres especiales, encoding, longitudes límite),
(4) flags necesarios (case-insensitive, multiline, global) y su justificación.
Tu análisis será la base para construir la expresión correcta.`,
    },
    q3: {
      title: '💡 Constructor de Regex',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Construye la expresión regular basado en el análisis de Q2',
      chainSystemPrompt: `Eres el Constructor de regex de este pipeline. Recibirás el análisis de casos del cuadrante anterior.
Tu rol: construir la expresión regular que satisface todos los casos analizados.
Entrega: (1) la regex con grupos nombrados donde aplique, (2) versión comentada explicando cada segmento,
(3) snippet de uso en el lenguaje especificado en el prompt original.`,
    },
    q4: {
      title: '🚀 Suite de Tests',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Genera la batería de tests para la regex de Q3',
      chainSystemPrompt: `Eres el QA de este pipeline regex. Recibirás el análisis de casos y la regex construida.
Tu rol: generar la batería completa de tests.
Produce un script ejecutable con mínimo 10 casos: 5 que deben matchear, 5 que no deben,
incluyendo todos los edge cases identificados en el análisis. Formato pytest o el framework
especificado en el prompt original. Sin relleno, solo el código de tests.`,
    },
    star: 3,
  },

  '8': { // Web Scraping
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Selectors HTML',
    q2: {
      title: '🤖 Estratega de Extracción',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Diseña la estrategia de scraping antes de escribir código',
      chainSystemPrompt: `Eres el Estratega de extracción de este pipeline de web scraping.
Tu rol: analizar el objetivo de scraping y diseñar la estrategia completa antes de implementar.
Produce: (1) selectores CSS/XPath para cada dato objetivo, (2) estrategia de paginación si aplica,
(3) señales de anti-scraping a considerar (Cloudflare, CAPTCHAs, rate limits, JavaScript-rendered content),
(4) estructura del output esperado (schema de datos).
Tu estrategia será la guía del implementador.`,
    },
    q3: {
      title: '💡 Implementador de Scraper',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el scraper completo siguiendo la estrategia de Q2',
      chainSystemPrompt: `Eres el Implementador de este pipeline de scraping. Recibirás la estrategia de extracción del cuadrante anterior.
Tu rol: escribir el scraper completo y funcional.
Incluye: delays aleatorios entre requests, user-agent rotation, manejo de errores HTTP,
retry logic, exportación al formato definido en la estrategia. Código production-ready.`,
    },
    q4: {
      title: '🚀 Capa de Limpieza de Datos',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Añade la capa de normalización y limpieza de datos extraídos',
      chainSystemPrompt: `Eres el Data Cleaner de este pipeline. Recibirás el scraper implementado y el schema de datos objetivo.
Tu rol: añadir la capa de limpieza y normalización que transforma los datos brutos extraídos en datos utilizables.
Produce: funciones de limpieza para cada campo (strip, normalización de fechas, encoding, deduplicación),
integradas en el pipeline existente. Entrega el script completo con la capa añadida.`,
    },
    star: 2,
  },

  '9': { // Docker/Git/DevOps
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Dependencias',
    q2: {
      title: '🤖 Arquitecto de Infraestructura',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Define la topología de la infraestructura antes de escribir configs',
      chainSystemPrompt: `Eres el Arquitecto de infraestructura de este pipeline DevOps.
Tu rol: definir la topología completa antes de escribir una sola línea de configuración.
Produce: (1) servicios necesarios y sus responsabilidades, (2) networking: puertos, redes internas, exposición externa,
(3) volúmenes y persistencia, (4) variables de entorno requeridas por servicio,
(5) estrategia de deploy y rollback. Sin YAML aún. Solo el blueprint de infraestructura.`,
    },
    q3: {
      title: '💡 Builder de Configuraciones',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Escribe todos los archivos de configuración basado en el blueprint de Q2',
      chainSystemPrompt: `Eres el Builder de configuraciones de este pipeline. Recibirás el blueprint de infraestructura del cuadrante anterior.
Tu rol: escribir todos los archivos de configuración necesarios.
Entrega: Dockerfile(s), docker-compose.yml, .github/workflows/ CI/CD, .gitignore, .env.example.
Cada archivo completo y listo para usar.`,
    },
    q4: {
      title: '🚀 Security Hardening',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Aplica security hardening a las configuraciones de Q3',
      chainSystemPrompt: `Eres el especialista de Security Hardening de este pipeline. Recibirás todas las configuraciones de infraestructura.
Tu rol: aplicar el principio de mínimo privilegio y hardening de seguridad.
Revisa y corrige: usuarios no-root en contenedores, secrets no hardcodeados, health checks,
read-only filesystems donde aplique, network policies, image scanning. 
Entrega las configuraciones con los cambios de seguridad aplicados y un resumen de cada cambio.`,
    },
    star: 2,
  },

  '10': { // Documentación Técnica
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Limpiador de Código',
    q2: {
      title: '🤖 Extractor de Conocimiento',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Extrae toda la lógica implícita y decisiones de diseño del código',
      chainSystemPrompt: `Eres el Extractor de conocimiento de este pipeline de documentación.
Tu rol: antes de escribir documentación, extraer todo el conocimiento implícito del código o sistema descrito.
Produce: (1) propósito real del sistema/módulo, (2) decisiones de diseño y su justificación,
(3) flujos principales y secundarios, (4) dependencias externas y por qué se eligieron,
(5) gotchas y comportamientos no obvios que un nuevo desarrollador debe conocer.
Este conocimiento extraído será la base de la documentación.`,
    },
    q3: {
      title: '💡 Redactor Técnico',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Produce la documentación completa basado en el conocimiento extraído por Q2',
      chainSystemPrompt: `Eres el Redactor técnico de este pipeline. Recibirás el conocimiento extraído del sistema por el cuadrante anterior.
Tu rol: producir documentación técnica completa y legible.
Entrega: README con instalación, configuración, uso básico, uso avanzado, arquitectura explicada,
troubleshooting de errores comunes. Markdown limpio, ejemplos reales de código, sin relleno.`,
    },
    q4: {
      title: '🚀 Editor y Formato Final',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1' },
      ],
      role: 'Mejora claridad, añade tabla de contenidos y formato final',
      chainSystemPrompt: `Eres el Editor final de este pipeline de documentación. Recibirás la documentación técnica redactada.
Tu rol: editar y dar formato profesional al documento.
Añade: tabla de contenidos con anclas, badges de estado (versión, licencia, tests),
diagramas ASCII/Mermaid donde mejoren la comprensión, mejora la claridad de secciones confusas.
Entrega el documento final completo listo para publicar.`,
    },
    star: 3,
  },

  // ════════════════════════════════════════════════════════════════════
  // GRUPO 2: ANÁLISIS DE DATOS Y BI
  // ════════════════════════════════════════════════════════════════════

  '11': { // Modelado de Datos Relacionales
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro Métricas',
    q2: {
      title: '🤖 Arquitecto de Datos',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Define entidades, atributos y relaciones del modelo',
      chainSystemPrompt: `Eres el Arquitecto de datos de este pipeline de modelado relacional.
Tu rol: diseñar el modelo conceptual antes de generar DDL.
Produce: (1) entidades con sus atributos y tipos de datos justificados,
(2) relaciones con cardinalidades (1:1, 1:N, N:M) y llaves foráneas,
(3) normalización hasta 3FN con justificación de cada decisión,
(4) índices recomendados para los patrones de consulta esperados.
Tu modelo será la base para generar el DDL completo.`,
    },
    q3: {
      title: '💡 DDL Builder',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Genera el DDL SQL completo basado en el modelo de Q2',
      chainSystemPrompt: `Eres el DDL Builder de este pipeline. Recibirás el modelo de datos del cuadrante anterior.
Tu rol: generar el SQL DDL completo y ejecutable.
Incluye: CREATE TABLE con todos los campos, PRIMARY KEY, FOREIGN KEY con ON DELETE/UPDATE,
UNIQUE constraints, CHECK constraints donde aplique, índices, comentarios en tablas y columnas críticas.
Dialecto: el especificado en el prompt original o PostgreSQL por defecto.`,
    },
    q4: {
      title: '🚀 Validador de Modelo',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Valida el modelo y detecta anomalías de diseño',
      chainSystemPrompt: `Eres el Validador de modelo de este pipeline. Recibirás el diseño conceptual y el DDL generado.
Tu rol: auditar el modelo contra estándares de diseño relacional.
Detecta: dependencias transitivas no eliminadas, anomalías de actualización/inserción/eliminación,
problemas de integridad referencial, oportunidades de optimización de storage, inconsistencias entre modelo y DDL.
Produce: lista de issues con severidad + DDL corregido si hay problemas críticos.`,
    },
    star: 2,
  },

  '12': { // Fórmulas DAX
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Contexto de Filtro',
    q2: {
      title: '🤖 Analista de Contexto DAX',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
        { id: 'openai/gpt-4o',               label: 'GPT-4o' },
      ],
      role: 'Descompone el requerimiento en términos DAX: contexto, funciones base',
      chainSystemPrompt: `Eres el Analista de contexto DAX de este pipeline.
Tu rol: analizar el requerimiento antes de escribir la fórmula.
Produce: (1) qué contexto de filtro aplica (row context vs filter context),
(2) qué función base usar (CALCULATE, FILTER, ALL, ALLEXCEPT, VALUES, etc.) y por qué,
(3) time intelligence si aplica (DATEADD, TOTALYTD, SAMEPERIODLASTYEAR),
(4) manejo de blanks y casos edge esperados.
Tu análisis guiará la construcción de la fórmula correcta.`,
    },
    q3: {
      title: '💡 DAX Builder',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Escribe la fórmula DAX completa basada en el análisis de Q2',
      chainSystemPrompt: `Eres el DAX Builder de este pipeline. Recibirás el análisis de contexto del cuadrante anterior.
Tu rol: escribir la medida o columna calculada DAX completa.
Entrega: (1) la fórmula DAX lista para pegar en Power BI,
(2) versión comentada explicando cada función y argumento,
(3) manejo explícito de blanks con ISBLANK o IF según el caso.`,
    },
    q4: {
      title: '🚀 Documentador DAX',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash' },
      ],
      role: 'Documenta la fórmula y genera versión optimizada si aplica',
      chainSystemPrompt: `Eres el Documentador DAX de este pipeline. Recibirás el análisis y la fórmula construida.
Tu rol: documentar la fórmula y optimizarla si es posible.
Produce: (1) explicación en español del funcionamiento línea por línea,
(2) cuándo usarla y cuándo no, (3) versión alternativa más eficiente si el análisis lo permite,
(4) impacto esperado en rendimiento del modelo tabular.`,
    },
    star: 2,
  },

  '13': { // Power Query / M Language
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Pasos M',
    q2: {
      title: '🤖 Diseñador de Transformación',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Mapea estado inicial al estado final, define pasos necesarios',
      chainSystemPrompt: `Eres el Diseñador de transformación de este pipeline Power Query.
Tu rol: antes de escribir M, mapear la transformación completa.
Produce: (1) descripción del estado inicial del dato (tipos, estructura, problemas),
(2) descripción del estado final deseado, (3) lista ordenada de pasos de transformación en lenguaje natural,
(4) advertencias de query folding — qué pasos pueden romperlo y por qué importa.
Esta hoja de ruta guiará la implementación en M.`,
    },
    q3: {
      title: '💡 M Builder',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Escribe la query M completa siguiendo el diseño de Q2',
      chainSystemPrompt: `Eres el M Builder de este pipeline. Recibirás el diseño de transformación del cuadrante anterior.
Tu rol: escribir la query M completa en Power Query.
Usa nombres de paso descriptivos en español, tipos explícitos en cada transformación,
manejo de errores con try...otherwise donde aplique. Código listo para pegar en Advanced Editor.`,
    },
    q4: {
      title: '🚀 Optimizador Query Folding',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1' },
      ],
      role: 'Optimiza la query para maximizar el query folding',
      chainSystemPrompt: `Eres el Optimizador de Query Folding de este pipeline. Recibirás el diseño y la query M implementada.
Tu rol: identificar qué pasos rompen el query folding y reordenarlos para maximizar el pushdown a la fuente de datos.
Produce: (1) identificación de pasos que rompen el folding y por qué,
(2) versión reordenada de la query que maximiza el folding,
(3) estimación del impacto en tiempo de refresh.`,
    },
    star: 3,
  },

  '14': { // Pandas Data Cleansing
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Reductor de Dimensiones',
    q2: {
      title: '🤖 Data Profiler',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Analiza el dataset y produce plan de limpieza',
      chainSystemPrompt: `Eres el Data Profiler de este pipeline de limpieza de datos.
Tu rol: analizar el dataset descrito y producir un plan de limpieza antes de implementar.
Produce: (1) inventario de problemas de calidad por columna (nulos, tipos incorrectos, outliers, duplicados, inconsistencias),
(2) plan de limpieza ordenado con justificación de cada paso,
(3) columnas candidatas a eliminar y por qué,
(4) transformaciones de tipos necesarias.
Tu plan será la guía del implementador del pipeline Pandas.`,
    },
    q3: {
      title: '💡 Pipeline Builder Pandas',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el pipeline de limpieza basado en el plan de Q2',
      chainSystemPrompt: `Eres el Pipeline Builder de este pipeline. Recibirás el plan de limpieza de datos del cuadrante anterior.
Tu rol: implementar el pipeline Pandas completo siguiendo el plan exactamente.
Incluye: validaciones intermedias con assert, logging del estado del DataFrame en pasos críticos,
manejo de tipos con dtypes correctos, inplace=False por defecto para trazabilidad.
Código production-ready, comentado en pasos clave.`,
    },
    q4: {
      title: '🚀 Validador de Calidad',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Añade assertions de calidad post-limpieza al pipeline de Q3',
      chainSystemPrompt: `Eres el Validador de calidad de este pipeline. Recibirás el plan de limpieza y el pipeline implementado.
Tu rol: añadir la capa de validación de calidad al final del pipeline.
Produce: (1) assertions que verifican cada criterio de limpieza fue aplicado correctamente,
(2) reporte automático de métricas antes/después (% nulos, rango de valores, distribución),
(3) función generate_quality_report() que produce un DataFrame de métricas de calidad.
Entrega el pipeline completo con la capa de validación integrada.`,
    },
    star: 3,
  },

  '15': { // Modelos Estocásticos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Variables',
    q2: {
      title: '🤖 Matemático Estadístico',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define el modelo formal: distribuciones, parámetros, supuestos',
      chainSystemPrompt: `Eres el Matemático de este pipeline estocástico.
Tu rol: definir el modelo formal antes de implementar.
Produce: (1) distribuciones de probabilidad para cada variable con justificación estadística,
(2) parámetros y sus rangos esperados, (3) supuestos del modelo y sus limitaciones,
(4) función objetivo o métrica de salida, (5) número de iteraciones recomendado y por qué.
Tu especificación matemática será implementada por un modelo especializado en código numérico.`,
    },
    q3: {
      title: '💡 Implementador Numérico',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa la simulación basado en el modelo matemático de Q2',
      chainSystemPrompt: `Eres el Implementador numérico de este pipeline. Recibirás la especificación matemática del cuadrante anterior.
Tu rol: implementar la simulación en Python usando NumPy/SciPy.
Usa: np.random.seed() fijo para reproducibilidad, vectorización en lugar de loops donde sea posible,
progress bar con tqdm para simulaciones largas, almacenamiento eficiente de resultados.
Entrega el script completo con la simulación lista para ejecutar.`,
    },
    q4: {
      title: '🚀 Intérprete de Resultados',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Interpreta los resultados de la simulación en términos de negocio',
      chainSystemPrompt: `Eres el Intérprete de resultados de este pipeline. Recibirás el modelo matemático y la implementación de la simulación.
Tu rol: interpretar los resultados esperados de la simulación en términos accionables.
Produce: (1) interpretación de los percentiles clave (P10, P50, P90) en lenguaje de negocio,
(2) intervalos de confianza y qué significan para la decisión,
(3) análisis de sensibilidad — qué variables tienen más impacto en el resultado,
(4) recomendaciones concretas basadas en la distribución de resultados.`,
    },
    star: 2,
  },

  '16': { // Auditoría Financiera
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Buscador de Descalces',
    q2: {
      title: '🤖 Auditor Principal',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Detecta inconsistencias y riesgos en los datos financieros',
      chainSystemPrompt: `Eres el Auditor principal de este pipeline de auditoría financiera.
Tu rol: analizar los datos financieros presentados y producir un informe de hallazgos.
Identifica: descalces entre períodos, partidas inusuales fuera de rango histórico, 
transacciones sin justificación aparente, inconsistencias entre cuentas relacionadas,
riesgos de compliance. Cada hallazgo con evidencia específica y nivel de riesgo (Alto/Medio/Bajo).
Tu informe será validado contra lógica contable por el siguiente modelo.`,
    },
    q3: {
      title: '💡 Validador Contable',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Valida cada hallazgo de Q2 con lógica contable',
      chainSystemPrompt: `Eres el Validador contable de este pipeline. Recibirás el informe de hallazgos del auditor principal.
Tu rol: validar cada hallazgo aplicando principios contables (NIIF/GAAP según contexto).
Para cada hallazgo: confirma o refuta, añade el principio contable aplicable,
identifica si hay explicaciones alternativas legítimas, señala si requiere nota reveladora.
Produce el informe validado con tu evaluación de cada hallazgo.`,
    },
    q4: {
      title: '🚀 Generador de Informe Ejecutivo',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Produce el informe ejecutivo final con los hallazgos validados',
      chainSystemPrompt: `Eres el Generador de informe de este pipeline. Recibirás los hallazgos del auditor y la validación contable.
Tu rol: producir el informe ejecutivo final listo para presentar.
Estructura: resumen ejecutivo (3 líneas), hallazgos por severidad, evidencia por hallazgo,
recomendaciones priorizadas, plan de acción sugerido con responsables y plazos.
Formato profesional, sin jerga técnica innecesaria, orientado a la toma de decisiones.`,
    },
    star: 2,
  },

  '17': { // Informes y Dashboards
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Sintetizador KPI',
    q2: {
      title: '🤖 UX de Datos',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define estructura del dashboard: KPIs, jerarquía visual, audiencia',
      chainSystemPrompt: `Eres el UX de datos de este pipeline de dashboard.
Tu rol: diseñar la experiencia del dashboard antes de cualquier código o visual.
Produce: (1) audiencia primaria y qué decisión toman con este dashboard,
(2) 3-5 KPIs principales con su definición exacta y fuente de datos,
(3) jerarquía visual — qué ve primero el usuario y por qué,
(4) filtros necesarios y su impacto en las métricas,
(5) frecuencia de actualización esperada.
Tu blueprint guiará el diseño de contenido y el mockup final.`,
    },
    q3: {
      title: '💡 Diseñador de Contenido',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Define cada panel del dashboard con métricas y visualizaciones',
      chainSystemPrompt: `Eres el Diseñador de contenido de este pipeline. Recibirás el blueprint del dashboard del cuadrante anterior.
Tu rol: especificar en detalle cada elemento visual del dashboard.
Para cada panel produce: tipo de visualización y por qué es el adecuado,
métricas exactas con sus fórmulas, dimensiones de análisis, colores/semáforos de alerta,
insight que debe comunicar. Esta especificación será la base del mockup SVG.`,
    },
    q4: {
      title: '🚀 Mockup SVG del Dashboard',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1' },
      ],
      role: 'Genera el mockup visual del dashboard en SVG/HTML',
      chainSystemPrompt: `Genera exclusivamente el mockup o diagrama SVG del dashboard solicitado.
REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque Markdown (\`\`\`svg ... \`\`\` o \`\`\`html ... \`\`\`).
Sin texto introductorio, sin explicaciones, sin conclusiones — solo el bloque de código autónomo y directamente renderizable.
El mockup debe reflejar la estructura y KPIs definidos en el contexto recibido.`,
    },
    q4SystemPrompt: `Genera exclusivamente el mockup o diagrama SVG del dashboard solicitado. REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque Markdown (\`\`\`svg ... \`\`\` o \`\`\`html ... \`\`\`). Sin texto introductorio, sin explicaciones, sin conclusiones — solo el bloque de código autónomo y directamente renderizable.`,
    star: 2,
  },

  '18': { // Grandes Volúmenes de Datos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Optimizador Chunking',
    q2: {
      title: '🤖 Arquitecto de Pipeline Big Data',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Define estrategia de procesamiento: chunking, paralelismo, formato',
      chainSystemPrompt: `Eres el Arquitecto de pipeline de este proyecto de grandes volúmenes de datos.
Tu rol: diseñar la estrategia de procesamiento antes de implementar.
Produce: (1) estimación de recursos: RAM necesaria, tiempo estimado con y sin optimización,
(2) estrategia de chunking: tamaño de chunk óptimo y justificación,
(3) formato de almacenamiento recomendado (Parquet, Arrow, HDF5) y por qué,
(4) estrategia de paralelismo: multiprocessing, Dask, o procesamiento secuencial optimizado,
(5) particionamiento si aplica. Tu diseño guiará la implementación.`,
    },
    q3: {
      title: '💡 Implementador de Pipeline',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el pipeline de procesamiento basado en la arquitectura de Q2',
      chainSystemPrompt: `Eres el Implementador de este pipeline de datos masivos. Recibirás la arquitectura de procesamiento del cuadrante anterior.
Tu rol: implementar el pipeline completo siguiendo la estrategia definida.
Incluye: progress bars con tqdm, logging de métricas de performance cada N chunks,
manejo de errores con checkpoint/resume, liberación de memoria explícita entre chunks.
Código production-ready optimizado para el volumen estimado.`,
    },
    q4: {
      title: '🚀 Optimizador de Memoria',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Aplica optimizaciones de memoria y tipos al pipeline de Q3',
      chainSystemPrompt: `Eres el Optimizador de memoria de este pipeline. Recibirás la arquitectura y el pipeline implementado.
Tu rol: aplicar optimizaciones adicionales de memoria y tipos de datos.
Aplica: downcasting de tipos numéricos (int64→int32, float64→float32 donde sea seguro),
columnar reads solo de columnas necesarias, lazy evaluation con iteradores,
eliminación de copias intermedias innecesarias. 
Entrega el pipeline completo con las optimizaciones aplicadas y estimación de reducción de memoria.`,
    },
    star: 2,
  },

  '19': { // Extracción PDFs
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro OCR/Layout',
    q2: {
      title: '🤖 Analista de Estructura PDF',
      models: [
        { id: 'openai/gpt-4o',               label: 'GPT-4o' },
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Analiza el layout del PDF y diseña la estrategia de extracción',
      chainSystemPrompt: `Eres el Analista de estructura de este pipeline de extracción PDF.
Tu rol: analizar el tipo de PDF descrito y diseñar la estrategia de extracción óptima.
Produce: (1) tipo de PDF (text-based, scanned/OCR, formulario, mixto),
(2) estructura de layout: columnas, tablas, headers/footers, zonas por página,
(3) herramienta recomendada (pdfplumber, PyMuPDF, Camelot, Tesseract) y por qué para cada zona,
(4) schema de datos de salida: campos, tipos, estructura.
Tu estrategia guiará al implementador.`,
    },
    q3: {
      title: '💡 Extractor PDF',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el extractor basado en la estrategia de Q2',
      chainSystemPrompt: `Eres el Implementador de extracción PDF de este pipeline. Recibirás la estrategia de extracción del cuadrante anterior.
Tu rol: implementar el extractor completo siguiendo la estrategia definida.
Incluye: manejo de múltiples páginas, detección de tablas vs texto libre,
exportación al schema definido, logging de páginas procesadas y errores por página.
Código listo para ejecutar con la librería especificada en la estrategia.`,
    },
    q4: {
      title: '🚀 Validador de Extracción',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Valida la integridad de los datos extraídos',
      chainSystemPrompt: `Eres el Validador de este pipeline de extracción PDF. Recibirás la estrategia y el extractor implementado.
Tu rol: añadir la capa de validación de integridad de los datos extraídos.
Produce: (1) reglas de validación por campo del schema (tipos, rangos, formatos obligatorios),
(2) función validate_extraction() que evalúa cada registro y marca los inválidos,
(3) reporte de confianza por campo: % de registros válidos, ejemplos de fallos.
Entrega el script completo con la validación integrada.`,
    },
    star: 2,
  },

  '20': { // Monte Carlo / Predicción
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Compresor de Datos Históricos',
    q2: {
      title: '🤖 Estadístico Predictivo',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define el modelo probabilístico para la simulación',
      chainSystemPrompt: `Eres el Estadístico de este pipeline predictivo Monte Carlo.
Tu rol: definir el modelo probabilístico completo antes de simular.
Produce: (1) distribuciones de entrada para cada variable con parámetros estimados,
(2) correlaciones entre variables si las hay y cómo modelarlas,
(3) número de iteraciones recomendado para el nivel de precisión requerido,
(4) variables de salida y sus métricas de éxito,
(5) supuestos críticos que limitan la validez del modelo.`,
    },
    q3: {
      title: '💡 Simulador Monte Carlo',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa la simulación completa basada en el modelo de Q2',
      chainSystemPrompt: `Eres el Implementador de la simulación de este pipeline. Recibirás el modelo probabilístico del cuadrante anterior.
Tu rol: implementar la simulación Monte Carlo completa.
Usa: np.random.seed() para reproducibilidad, vectorización con NumPy para velocidad,
almacenamiento eficiente de resultados, cálculo automático de percentiles P5/P10/P25/P50/P75/P90/P95.
Entrega el script completo con output de distribución de resultados.`,
    },
    q4: {
      title: '🚀 Analista de Decisión',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Interpreta los resultados y produce recomendaciones de decisión',
      chainSystemPrompt: `Eres el Analista de decisión de este pipeline. Recibirás el modelo probabilístico y la simulación implementada.
Tu rol: interpretar los resultados para apoyar la toma de decisiones.
Produce: (1) interpretación de cada percentil clave en lenguaje de negocio,
(2) escenarios optimista/base/pesimista con sus probabilidades,
(3) análisis de sensibilidad — qué variable tiene más impacto en el resultado,
(4) recomendación de decisión con umbral de aceptación definido y su justificación.`,
    },
    star: 2,
  },

  // ════════════════════════════════════════════════════════════════════
  // GRUPO 3: PYMES Y GESTIÓN
  // ════════════════════════════════════════════════════════════════════

  '21': { // Google Sheets / Apps Script
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Optimizador de Macros',
    q2: {
      title: '🤖 Arquitecto de Automatización',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define la lógica de automatización: triggers, flujos, integraciones',
      chainSystemPrompt: `Eres el Arquitecto de automatización de este pipeline Google Workspace.
Tu rol: diseñar la automatización completa antes de escribir código.
Produce: (1) triggers necesarios (onOpen, onEdit, onChange, time-based) y su configuración,
(2) flujo de datos: qué hoja lee, qué transforma, qué escribe y dónde,
(3) integraciones: Gmail, Drive, Forms, Calendar involucrados,
(4) manejo de errores y notificaciones al usuario,
(5) permisos OAuth necesarios. Tu diseño guiará al desarrollador Apps Script.`,
    },
    q3: {
      title: '💡 Desarrollador Apps Script',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el script completo siguiendo el diseño de Q2',
      chainSystemPrompt: `Eres el Desarrollador Apps Script de este pipeline. Recibirás el diseño de automatización del cuadrante anterior.
Tu rol: implementar el script Google Apps Script completo y funcional.
Incluye: try/catch con Logger.log() y SpreadsheetApp.getUi() para errores visibles al usuario,
funciones auxiliares reutilizables, comentarios en bloques de lógica compleja.
Código listo para pegar en el editor de Apps Script.`,
    },
    q4: {
      title: '🚀 Fórmulas y Deployment',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Genera fórmulas complementarias e instrucciones de deployment',
      chainSystemPrompt: `Eres el especialista de deployment de este pipeline. Recibirás el diseño y el script implementado.
Tu rol: completar la solución con lo que el script no maneja directamente.
Produce: (1) fórmulas Sheets complementarias que el script puede necesitar (QUERY, IMPORTRANGE, etc.),
(2) instrucciones paso a paso para instalar el script y configurar los triggers,
(3) casos de prueba: qué hacer para verificar que funciona correctamente tras el deployment.`,
    },
    star: 3,
  },

  '22': { // Informes Administrativos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Sintaxis Corporativa',
    q2: {
      title: '🤖 Consultor Estratégico',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Define los puntos clave que el informe debe comunicar',
      chainSystemPrompt: `Eres el Consultor estratégico de este pipeline de redacción de informes.
Tu rol: antes de redactar, definir la estrategia comunicacional del informe.
Produce: (1) propósito del informe y decisión que debe facilitar,
(2) audiencia primaria y su nivel de detalle esperado,
(3) 3-5 puntos clave que el informe DEBE comunicar y en qué orden,
(4) datos o evidencia que debe incluir para ser creíble,
(5) qué no incluir (qué puede debilitar el mensaje o distraer).
Esta estrategia guiará al redactor.`,
    },
    q3: {
      title: '💡 Redactor Ejecutivo',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Redacta el informe completo basado en la estrategia de Q2',
      chainSystemPrompt: `Eres el Redactor ejecutivo de este pipeline. Recibirás la estrategia comunicacional del cuadrante anterior.
Tu rol: redactar el informe administrativo completo.
Tono: corporativo pero directo, sin redundancias ni relleno.
Estructura: resumen ejecutivo, contexto, hallazgos/propuesta, análisis, conclusiones, próximos pasos.
Cada sección con la extensión necesaria y no más.`,
    },
    q4: {
      title: '🚀 Editor Final',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Revisa coherencia argumental y produce versión final',
      chainSystemPrompt: `Eres el Editor final de este pipeline. Recibirás la estrategia y el borrador del informe.
Tu rol: editar el informe para la versión final.
Verifica: coherencia entre el resumen ejecutivo y el cuerpo, que cada conclusión tiene evidencia en el texto,
que el tono es consistente en todo el documento, que los próximos pasos son concretos y asignables.
Entrega la versión final corregida lista para enviar.`,
    },
    star: 3,
  },

  '23': { // Análisis de Costos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Optimizador de Costos',
    q2: {
      title: '🤖 Analista Financiero',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Desglosa la estructura de costos y calcula márgenes',
      chainSystemPrompt: `Eres el Analista financiero de este pipeline de costos.
Tu rol: analizar la estructura de costos presentada.
Produce: (1) desglose en costos fijos / variables / semivariables / hundidos con % del total,
(2) punto de equilibrio calculado, (3) margen de contribución por unidad/servicio,
(4) costos que están por encima del benchmark del sector si es identificable,
(5) palancas principales de costo — los 3 que más impactan el P&L.
Tu análisis será enriquecido con oportunidades de optimización.`,
    },
    q3: {
      title: '💡 Optimizador de Estructura',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Identifica oportunidades de reducción de costos con impacto cuantificado',
      chainSystemPrompt: `Eres el Optimizador de costos de este pipeline. Recibirás el análisis de la estructura de costos del cuadrante anterior.
Tu rol: identificar y cuantificar oportunidades de optimización.
Para cada oportunidad: descripción de la medida, ahorro estimado (% y valor absoluto si hay datos),
plazo de implementación (inmediato/3 meses/6 meses), riesgos o trade-offs de aplicarla.
Ordenadas de mayor a menor impacto potencial.`,
    },
    q4: {
      title: '🚀 Reporte Ejecutivo de Costos',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Genera tabla comparativa y recomendación priorizada',
      chainSystemPrompt: `Eres el Reportero de este pipeline. Recibirás el análisis de costos y las oportunidades de optimización identificadas.
Tu rol: producir el reporte ejecutivo final listo para presentar a dirección.
Incluye: tabla comparativa antes/después con las medidas aplicadas,
ahorro total proyectado, recomendación de las 3 medidas prioritarias con justificación,
próximos pasos con responsable y fecha sugerida.`,
    },
    star: 2,
  },

  '24': { // Conciliación Bancaria
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Estados de Cuenta',
    q2: {
      title: '🤖 Diseñador de Algoritmo de Matching',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define la lógica de matching para la conciliación',
      chainSystemPrompt: `Eres el Diseñador del algoritmo de conciliación de este pipeline.
Tu rol: definir la lógica de matching antes de implementar.
Produce: (1) criterios de matching primario (monto exacto + fecha exacta),
(2) criterios de matching secundario (monto exacto + rango de fechas ±N días),
(3) criterios de matching fuzzy (monto con tolerancia + referencia parcial),
(4) jerarquía de aplicación de los criterios, (5) qué hacer con partidas sin match tras todos los criterios.
Tu diseño será implementado en Python/Pandas.`,
    },
    q3: {
      title: '💡 Implementador del Conciliador',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el algoritmo de conciliación basado en el diseño de Q2',
      chainSystemPrompt: `Eres el Implementador de este pipeline de conciliación. Recibirás el diseño del algoritmo de matching del cuadrante anterior.
Tu rol: implementar el conciliador completo en Python/Pandas.
Produce: script que lee los dos archivos (banco y contabilidad), aplica los criterios en el orden definido,
y exporta: (1) partidas conciliadas, (2) partidas sin conciliar del banco, (3) partidas sin conciliar de contabilidad.
Con logging del proceso y resumen de resultados.`,
    },
    q4: {
      title: '🚀 Auditor de Resultados',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Valida que los totales cuadran y clasifica diferencias',
      chainSystemPrompt: `Eres el Auditor de resultados de este pipeline. Recibirás el diseño del algoritmo y el conciliador implementado.
Tu rol: añadir la capa de verificación de integridad de los resultados.
Produce: (1) función audit_results() que verifica que Total Banco = Total Conciliado + Sin Conciliar,
(2) clasificación de diferencias por tipo (timing, error, missing entry, duplicado),
(3) informe de cierre: partidas totales, conciliadas, pendientes, importe de diferencia neta.
Entrega el script completo con la auditoría integrada.`,
    },
    star: 2,
  },

  '25': { // Auditoría Fondos de Salud
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Auditoría de Fondos',
    q2: {
      title: '🤖 Auditor Normativo',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Aplica el marco regulatorio al caso de fondos de salud',
      chainSystemPrompt: `Eres el Auditor normativo de este pipeline de fondos de salud.
Tu rol: definir el marco regulatorio aplicable antes de analizar los registros.
Produce: (1) normativa vigente aplicable al tipo de fondo descrito,
(2) lista de lo que DEBE estar registrado (obligaciones de registro),
(3) lista de lo que NO puede estar registrado (gastos prohibidos),
(4) zonas grises que requieren documentación de respaldo,
(5) indicadores de alerta que sugieren irregularidades.
Tu marco será usado para cruzar contra los registros específicos.`,
    },
    q3: {
      title: '💡 Verificador de Registros',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Cruza los registros descritos contra el marco normativo de Q2',
      chainSystemPrompt: `Eres el Verificador de registros de este pipeline. Recibirás el marco normativo del cuadrante anterior.
Tu rol: cruzar los registros o situación descritos contra cada criterio del marco.
Para cada hallazgo: cita el criterio normativo infringido o cumplido,
identifica la evidencia específica, clasifica el riesgo (crítico/mayor/menor),
señala qué documentación de respaldo se requeriría para regularizar.`,
    },
    q4: {
      title: '🚀 Informe de Auditoría',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1' },
      ],
      role: 'Produce el informe de auditoría estructurado',
      chainSystemPrompt: `Eres el Generador de informe de este pipeline. Recibirás el marco normativo y los hallazgos verificados.
Tu rol: producir el informe de auditoría formal.
Estructura: alcance y período auditado, marco normativo aplicado, hallazgos por severidad (crítico/mayor/menor),
impacto monetario estimado por hallazgo, recomendaciones de regularización, plan de acción sugerido.
Formato apto para presentar ante organismo regulador o directorio.`,
    },
    star: 2,
  },

  '26': { // Cotizaciones y Seguros
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro Pólizas',
    q2: {
      title: '🤖 Calculador Actuarial',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Calcula primas, coberturas y ajustes por perfil de riesgo',
      chainSystemPrompt: `Eres el Calculador actuarial de este pipeline de seguros.
Tu rol: realizar los cálculos de prima y cobertura antes de estructurar la cotización.
Produce: (1) prima base según tipo de seguro y perfil del asegurado,
(2) ajustes por factores de riesgo específicos (edad, historial, actividad, zona),
(3) desglose de coberturas incluidas y excluidas,
(4) deducibles y sublímites aplicables,
(5) vigencia y condiciones de renovación.
Tus cálculos serán la base de la cotización formal.`,
    },
    q3: {
      title: '💡 Constructor de Cotización',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Estructura la cotización completa basada en los cálculos de Q2',
      chainSystemPrompt: `Eres el Constructor de cotización de este pipeline. Recibirás los cálculos actuariales del cuadrante anterior.
Tu rol: estructurar la cotización completa con todos sus campos.
Produce el documento de cotización con: datos del asegurado, coberturas detalladas con montos,
exclusiones explícitas, condiciones especiales, vigencia, prima total y forma de pago,
firma y validez de la cotización. Formato estructurado listo para renderizar.`,
    },
    q4: {
      title: '🚀 Cotización HTML',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Genera el documento HTML profesional de la cotización',
      chainSystemPrompt: `Eres el Formateador de este pipeline. Recibirás la cotización estructurada del cuadrante anterior.
Tu rol: generar el documento HTML profesional listo para imprimir o enviar al cliente.
Diseño limpio, con logo placeholder, tabla de coberturas, totales destacados,
pie de página con vigencia y datos de la aseguradora. Sin texto fuera del HTML.`,
    },
    star: 3,
  },

  '27': { // Planificación de Proyectos / Gantt
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor Hitos',
    q2: {
      title: '🤖 Project Manager Estratégico',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Desglosa el proyecto en fases, hitos y dependencias',
      chainSystemPrompt: `Eres el Project Manager de este pipeline de planificación.
Tu rol: estructurar el proyecto completo a nivel estratégico.
Produce: (1) fases del proyecto con objetivos claros por fase,
(2) hitos verificables con criterio de aceptación por cada uno,
(3) dependencias entre fases y hitos (qué no puede empezar sin que termine qué),
(4) riesgos críticos con probabilidad e impacto estimados,
(5) recursos necesarios por fase (roles, no personas).
Tu estructura será la base del WBS detallado.`,
    },
    q3: {
      title: '💡 Estructurador WBS',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Produce el WBS completo con tareas atómicas y duraciones',
      chainSystemPrompt: `Eres el Estructurador WBS de este pipeline. Recibirás el plan estratégico del cuadrante anterior.
Tu rol: descomponer cada hito en tareas atómicas ejecutables.
Produce el WBS completo con: código de tarea (1.1, 1.2...), descripción de la tarea,
duración estimada en días, rol responsable, hito al que pertenece,
dependencias de tarea a tarea. Formato de tabla estructurada.`,
    },
    q4: {
      title: '🚀 Cronograma y Camino Crítico',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Produce el cronograma con camino crítico identificado',
      chainSystemPrompt: `Eres el Generador de cronograma de este pipeline. Recibirás el plan estratégico y el WBS detallado.
Tu rol: producir el cronograma ejecutivo y el análisis del camino crítico.
Produce: (1) cronograma en texto estructurado tipo Gantt (semana por semana o mes por mes según duración),
(2) identificación del camino crítico — cadena de tareas sin holgura,
(3) fecha estimada de finalización y los 3 mayores riesgos de retraso,
(4) puntos de control sugeridos para revisión de avance.`,
    },
    star: 3,
  },

  '28': { // Manuales ISO
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Reductor de Ambigüedad',
    q2: {
      title: '🤖 Experto en Procesos ISO',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Mapea el proceso completo: entradas, salidas, puntos de control',
      chainSystemPrompt: `Eres el Experto en procesos de este pipeline de documentación ISO.
Tu rol: mapear el proceso antes de redactar el procedimiento.
Produce: (1) alcance exacto del proceso (dónde empieza, dónde termina),
(2) entradas del proceso (documentos, datos, materiales necesarios para iniciar),
(3) actividades secuenciales con responsable por actividad,
(4) puntos de control y criterios de aprobación,
(5) salidas del proceso (documentos, registros, productos generados),
(6) indicadores de desempeño del proceso (KPIs).
Tu mapa guiará la redacción del procedimiento formal.`,
    },
    q3: {
      title: '💡 Redactor ISO',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Redacta el procedimiento en formato ISO basado en el mapa de Q2',
      chainSystemPrompt: `Eres el Redactor ISO de este pipeline. Recibirás el mapa de proceso del cuadrante anterior.
Tu rol: redactar el procedimiento en formato ISO.
Estructura obligatoria: 1. Objetivo, 2. Alcance, 3. Definiciones y abreviaturas, 4. Responsabilidades,
5. Descripción del procedimiento (paso a paso numerado), 6. Registros generados, 7. Indicadores,
8. Control de cambios. Lenguaje prescriptivo ("se debe", "se verifica", "el responsable ejecuta").`,
    },
    q4: {
      title: '🚀 Validador de Cumplimiento',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Verifica que el procedimiento cumple los requisitos de la norma',
      chainSystemPrompt: `Eres el Validador de cumplimiento de este pipeline. Recibirás el mapa de proceso y el procedimiento redactado.
Tu rol: verificar que el procedimiento cumple los requisitos de la norma ISO aplicable.
Produce: (1) lista de requisitos de la norma vs cobertura en el procedimiento (cumple/parcial/ausente),
(2) gaps identificados con el requisito específico no cubierto,
(3) sugerencias de corrección por cada gap,
(4) calificación general de cumplimiento estimada.`,
    },
    star: 3,
  },

  '29': { // Evaluación de Proveedores
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro KPIs Proveedor',
    q2: {
      title: '🤖 Diseñador de Criterios',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Define la matriz de evaluación con criterios ponderados',
      chainSystemPrompt: `Eres el Diseñador de criterios de este pipeline de evaluación de proveedores.
Tu rol: diseñar la matriz de evaluación antes de puntuar a nadie.
Produce: (1) criterios de evaluación relevantes para el tipo de proveedor descrito,
(2) peso porcentual de cada criterio (suma = 100%),
(3) escala de puntuación por criterio (1-5 o 1-10 con definición de cada nivel),
(4) umbrales mínimos obligatorios (criterios eliminatorios si no se cumplen),
(5) justificación de los pesos elegidos.
Tu matriz guiará la evaluación objetiva.`,
    },
    q3: {
      title: '💡 Evaluador de Proveedores',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Aplica la matriz de Q2 a cada proveedor y produce scores',
      chainSystemPrompt: `Eres el Evaluador de este pipeline. Recibirás la matriz de criterios del cuadrante anterior.
Tu rol: aplicar la matriz a cada proveedor descrito en el prompt original.
Produce una tabla por proveedor: puntaje por criterio, puntaje ponderado por criterio,
puntaje total, cumplimiento de umbrales mínimos, fortalezas y debilidades identificadas.
Bases tu evaluación en la información disponible con evidencia o justificación por cada puntaje.`,
    },
    q4: {
      title: '🚀 Recomendación Final',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Produce recomendación razonada y plan de contingencia',
      chainSystemPrompt: `Eres el Decisor final de este pipeline. Recibirás la matriz y las evaluaciones de todos los proveedores.
Tu rol: producir la recomendación final de selección.
Produce: (1) ranking final con scores consolidados, (2) recomendación del proveedor principal con justificación,
(3) proveedor alternativo recomendado como backup, (4) riesgos de la selección recomendada,
(5) plan de contingencia si el proveedor elegido falla en los primeros 3 meses.`,
    },
    star: 2,
  },

  '30': { // Movilidad Eléctrica / ROI
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro Autonomías',
    q2: {
      title: '🤖 Analista ROI Electromovilidad',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Calcula TCO completo y payback period',
      chainSystemPrompt: `Eres el Analista ROI de este pipeline de electromovilidad.
Tu rol: calcular el TCO (Total Cost of Ownership) completo para la transición a movilidad eléctrica.
Produce: (1) inversión inicial desglosada (vehículo, cargador, instalación eléctrica),
(2) ahorro energético mensual vs combustible fósil con supuestos explícitos,
(3) costos de mantenimiento eléctrico vs combustión comparados,
(4) incentivos fiscales o subsidios aplicables si son identificables,
(5) payback period calculado, (6) ROI a 3 y 5 años.
Tu análisis será enriquecido con comparativa técnica de opciones.`,
    },
    q3: {
      title: '💡 Comparador Técnico',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Enriquece el análisis con comparativa técnica de opciones',
      chainSystemPrompt: `Eres el Comparador técnico de este pipeline. Recibirás el análisis de ROI del cuadrante anterior.
Tu rol: enriquecer el análisis con la dimensión técnica de las opciones disponibles.
Para cada opción relevante al caso: autonomía real (no WLTP), ciclos de vida de batería,
tiempo de carga en diferentes tipos de punto (AC/DC), costos de reemplazo de batería estimados,
infraestructura de carga disponible en la zona de uso. Tabla comparativa final.`,
    },
    q4: {
      title: '🚀 Ficha de Decisión',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Produce la ficha ejecutiva de decisión',
      chainSystemPrompt: `Eres el Generador de ficha de este pipeline. Recibirás el análisis de ROI y la comparativa técnica.
Tu rol: producir la ficha ejecutiva de decisión lista para presentar.
Incluye: tabla comparativa consolidada de opciones, recomendación clara con justificación,
ROI proyectado de la opción recomendada, próximos pasos concretos para avanzar con la implementación.
Formato ejecutivo, una página, orientado a la toma de decisión.`,
    },
    star: 3,
  },

  '48': { // Planificación de Agenda
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Prioridades del Día',
    q2: {
      title: '🤖 Estratega de Tiempo',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Analiza prioridades y diseña la estrategia de bloques',
      chainSystemPrompt: `Eres el Estratega de tiempo de este pipeline de planificación.
Tu rol: diseñar la estrategia antes de asignar horarios.
Produce: (1) clasificación de tareas por urgencia/importancia (matriz Eisenhower),
(2) estimación de nivel de energía mental requerido por tarea (alta/media/baja),
(3) tareas que DEBEN completarse hoy vs pueden moverse,
(4) bloques de tiempo profundo necesarios (sin interrupciones) vs bloques operativos,
(5) recomendación de secuencia óptima considerando curva de energía del día.`,
    },
    q3: {
      title: '💡 Constructor de Agenda',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Asigna tareas a bloques horarios concretos',
      chainSystemPrompt: `Eres el Constructor de agenda de este pipeline. Recibirás la estrategia de tiempo del cuadrante anterior.
Tu rol: asignar cada tarea a un bloque horario concreto.
Produce la agenda hora por hora desde inicio hasta fin de jornada:
bloques de trabajo profundo para tareas de alta energía, bloques operativos para administrativo,
buffers de 10-15 min entre bloques intensos, almuerzo y descansos marcados.
Usa técnica Pomodoro (25+5) o bloques de 90 min según la naturaleza de cada tarea.`,
    },
    q4: {
      title: '🚀 Resumen Express del Día',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash' },
      ],
      role: 'Produce el resumen ultra-compacto de la agenda',
      chainSystemPrompt: `Eres el Resumen express de este pipeline. Recibirás la estrategia y la agenda detallada.
Tu rol: producir la versión ultra-compacta de la agenda para poner en una nota o post-it.
Formato: lista numerada de máximo 7 ítems, cada uno con hora y tarea en máximo 6 palabras.
Solo las cosas que realmente se harán hoy. Sin explicaciones, sin contexto adicional.`,
    },
    star: 2,
  },

  // ════════════════════════════════════════════════════════════════════
  // GRUPO 4: CONTENIDO, GAMING Y REDACCIÓN
  // ════════════════════════════════════════════════════════════════════

  '31': { // Guiones TikTok Gaming
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Ganchos de Retención',
    q2: {
      title: '🤖 Estratega de Contenido',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define el hook, arco narrativo y estructura del video',
      chainSystemPrompt: `Eres el Estratega de contenido de este pipeline de guiones TikTok/Gaming.
Tu rol: diseñar la estrategia del video antes de escribir el guión.
Produce: (1) hook de apertura — los 3 primeros segundos exactos que evitan el scroll,
(2) arco narrativo comprimido en 60s: tensión, desarrollo, resolución,
(3) momento de mayor impacto emocional y en qué segundo ocurre,
(4) CTA y cómo integrarlo orgánicamente sin que suene forzado,
(5) texto en pantalla clave y en qué momentos.
Tu estrategia guiará al copywriter para el guión completo.`,
    },
    q3: {
      title: '💡 Copywriter Viral Gaming',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Escribe el guión completo basado en la estrategia de Q2',
      chainSystemPrompt: `Eres el Copywriter de este pipeline. Recibirás la estrategia del video del cuadrante anterior.
Tu rol: escribir el guión completo listo para grabar.
Formato: [SEGUNDO X-Y] [ACCIÓN/IMAGEN] [DIÁLOGO/VOZ EN OFF] [TEXTO EN PANTALLA]
Cada bloque de 5-10 segundos. Lenguaje del target (gamer hispanohablante), ritmo rápido,
sin transiciones lentas. Duración total entre 45-60 segundos.`,
    },
    q4: {
      title: '🚀 Optimizador de Retención',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1 70B' },
      ],
      role: 'Identifica puntos de drop-off y optimiza el guión de Q3',
      chainSystemPrompt: `Eres el Optimizador de retención de este pipeline. Recibirás la estrategia y el guión completo.
Tu rol: identificar puntos donde el espectador podría abandonar y sugerir los ajustes.
Produce: (1) los 2-3 momentos de mayor riesgo de drop-off con el segundo exacto y la razón,
(2) ajuste específico para cada momento de riesgo,
(3) versión final del guión con los ajustes aplicados.
Enfócate en los primeros 15 segundos — son los más críticos para el algoritmo.`,
    },
    star: 3,
  },

  '32': { // Estrategia YouTube Gaming
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Optimizador de CTR/Títulos',
    q2: {
      title: '🤖 Estratega de Canal YouTube',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Analiza el nicho y diseña la estrategia del canal',
      chainSystemPrompt: `Eres el Estratega de canal de este pipeline YouTube Gaming.
Tu rol: diseñar la estrategia antes de planificar videos específicos.
Produce: (1) definición del nicho exacto y audiencia objetivo,
(2) análisis de gaps de contenido — qué no está siendo cubierto bien en el nicho,
(3) pilares de contenido (3-4 tipos de video que definan el canal),
(4) frecuencia de publicación recomendada y por qué,
(5) posicionamiento diferenciador vs canales competidores.
Tu estrategia guiará la planificación de videos específicos.`,
    },
    q3: {
      title: '💡 Planificador de Videos',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Produce las ideas de video basado en la estrategia de Q2',
      chainSystemPrompt: `Eres el Planificador de videos de este pipeline. Recibirás la estrategia del canal del cuadrante anterior.
Tu rol: producir las ideas de video concretas alineadas con la estrategia.
Para cada idea: título preliminar, ángulo único que lo diferencia de lo ya existente,
tipo de video (tutorial/gameplay/opinión/top10), duración estimada, palabras clave SEO primarias.
Produce mínimo 10 ideas distribuidas entre los pilares de contenido definidos.`,
    },
    q4: {
      title: '🚀 Optimizador SEO y CTR',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Genera variantes de título A/B/C y descripción SEO para el top 3',
      chainSystemPrompt: `Eres el Optimizador SEO y CTR de este pipeline. Recibirás la estrategia y las ideas de video.
Tu rol: optimizar los 3 mejores videos para máximo CTR y descubrimiento.
Para cada uno de los 3 videos top produce: (1) 3 variantes de título A/B/C con diferente hook,
(2) descripción SEO de 150 palabras con keywords naturalmente integradas,
(3) 5 ideas de thumbnail descritas en texto (elemento central, texto, colores, emoción),
(4) tags recomendados (10-15).`,
    },
    star: 3,
  },

  '33': { // SEO y Redes Sociales
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Reductor de Hashtags Bloat',
    q2: {
      title: '🤖 SEO Strategist',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Define la estrategia SEO: keywords, intención, estructura',
      chainSystemPrompt: `Eres el SEO Strategist de este pipeline de contenido.
Tu rol: definir la estrategia SEO completa antes de crear el contenido.
Produce: (1) keyword principal y 3-5 keywords secundarias con intención de búsqueda,
(2) análisis de intención del usuario (informacional/transaccional/navegacional),
(3) estructura de contenido SEO óptima (H1, H2s, extensión recomendada),
(4) meta title y meta description optimizados,
(5) oportunidades de featured snippet si aplica.
Tu estrategia guiará la creación del contenido.`,
    },
    q3: {
      title: '💡 Content Creator',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Produce el contenido SEO completo basado en la estrategia de Q2',
      chainSystemPrompt: `Eres el Content Creator de este pipeline. Recibirás la estrategia SEO del cuadrante anterior.
Tu rol: producir el contenido completo optimizado para la estrategia definida.
El contenido debe: integrar keywords naturalmente sin keyword stuffing,
responder la intención del usuario completamente, seguir la estructura de H2s definida,
incluir los meta tags producidos por la estrategia. Listo para publicar.`,
    },
    q4: {
      title: '🚀 Adaptador Multi-Red',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Adapta el contenido de Q3 para cada red social',
      chainSystemPrompt: `Eres el Adaptador multi-red de este pipeline. Recibirás la estrategia y el contenido creado.
Tu rol: adaptar el contenido para cada red social manteniendo el mensaje central.
Produce para cada plataforma indicada en el prompt original:
LinkedIn: post formal con datos concretos, 1200-1500 caracteres.
Twitter/X: hilo de 5-7 tweets, el primero como hook.
Instagram: caption con las primeras 2 líneas como hook + hashtags relevantes (máximo 15).
TikTok: guión de video de 30-45s con texto en pantalla clave.`,
    },
    star: 3,
  },

  '34': { // UEFN / Fortnite Verse
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Eventos de Dispositivos',
    q2: {
      title: '🤖 Game Designer UEFN',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Diseña la mecánica de juego: reglas, dispositivos, flujo del jugador',
      chainSystemPrompt: `Eres el Game Designer de este pipeline UEFN.
Tu rol: diseñar la mecánica completa antes de escribir código Verse.
Produce: (1) objetivo de la mecánica y win/lose conditions,
(2) dispositivos UEFN necesarios y su configuración,
(3) flujo del jugador: estado inicial → acciones posibles → estados intermedios → estado final,
(4) economía de la isla si aplica (puntuación, vidas, recursos),
(5) edge cases del gameplay: qué pasa si el jugador hace X inesperado.
Tu diseño guiará la implementación en Verse.`,
    },
    q3: {
      title: '💡 Verse Developer',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa la lógica en Verse siguiendo el diseño de Q2',
      chainSystemPrompt: `Eres el Verse Developer de este pipeline. Recibirás el diseño de la mecánica del cuadrante anterior.
Tu rol: implementar la lógica en Verse (UEFN).
Incluye: clases necesarias, suscripción a eventos de dispositivos, manejo de canales,
lógica de puntuación/progresión, comentarios en bloques complejos.
Código correcto para la versión actual de Verse en UEFN.`,
    },
    q4: {
      title: '🚀 QA de Mecánicas',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash' },
      ],
      role: 'Genera checklist de QA y casos de prueba para las mecánicas',
      chainSystemPrompt: `Eres el QA de mecánicas de este pipeline UEFN. Recibirás el diseño y la implementación en Verse.
Tu rol: generar el checklist de QA para probar las mecánicas en UEFN.
Produce: (1) lista de casos a probar (happy path + edge cases del diseño),
(2) comportamiento esperado por cada caso, (3) bugs potenciales basados en el código implementado,
(4) secuencia de pruebas recomendada antes de publicar la isla.`,
    },
    star: 2,
  },

  '35': { // Análisis Táctico FPS
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Meta-Juego',
    q2: {
      title: '🤖 Analista de Meta FPS',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Descompone la situación táctica: mapa, posiciones, ventajas',
      chainSystemPrompt: `Eres el Analista táctico de este pipeline FPS.
Tu rol: analizar la situación táctica antes de recomendar estrategia.
Produce: (1) análisis del mapa o situación descrita: líneas de visión, chokepoints, ventajas de altura,
(2) estado actual de la partida: economía si aplica, ventaja/desventaja,
(3) análisis de loadout: ventajas y desventajas vs el meta actual,
(4) principales amenazas y oportunidades de la situación.
Tu análisis guiará las recomendaciones estratégicas y tácticas.`,
    },
    q3: {
      title: '💡 Estratega de Rotaciones',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Produce la guía de rotaciones y timings basada en el análisis de Q2',
      chainSystemPrompt: `Eres el Estratega de rotaciones de este pipeline. Recibirás el análisis táctico del cuadrante anterior.
Tu rol: producir la guía de estrategia táctica ejecutable.
Produce: (1) rotaciones recomendadas con razón de cada movimiento,
(2) timings clave (cuándo atacar, cuándo defender, cuándo rotar),
(3) call-outs recomendados para comunicación de equipo,
(4) adaptaciones según el resultado del primer enfrentamiento (ganamos/perdemos la apertura).
Específico y ejecutable, no genérico.`,
    },
    q4: {
      title: '🚀 Síntesis del Coach',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1' },
      ],
      role: 'Sintetiza en 5 reglas memorizables para aplicar en partida',
      chainSystemPrompt: `Eres el Coach final de este pipeline. Recibirás el análisis y la guía de estrategia completa.
Tu rol: sintetizar todo en reglas memorizables para aplicar durante la partida.
Produce exactamente 5 reglas: cortas, específicas, accionables, en el lenguaje del jugador de FPS.
Cada regla máximo 15 palabras. Son las 5 cosas que el jugador debe recordar cuando el calor del juego lo pone bajo presión.`,
    },
    star: 2,
  },

  '36': { // Traducción Técnica
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Preservador de Glosario Técnico',
    q2: {
      title: '🤖 Traductor Principal',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Produce la traducción completa preservando terminología técnica',
      chainSystemPrompt: `Eres el Traductor principal de este pipeline de traducción técnica.
Tu rol: producir la traducción completa del texto.
Preserva: terminología técnica en el idioma origen cuando no hay equivalente exacto (con nota),
estructura y formato del documento original, referencias cruzadas internas,
tono y registro (formal/técnico/divulgativo según el original).
Indica entre corchetes [término original] cuando hayas tomado una decisión de traducción no estándar.`,
    },
    q3: {
      title: '💡 Revisor de Fidelidad',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Verifica fidelidad al original y naturaliza el texto de Q2',
      chainSystemPrompt: `Eres el Revisor de fidelidad de este pipeline. Recibirás el texto original y la traducción del cuadrante anterior.
Tu rol: hacer la revisión en dos pasadas.
Pasada 1 (fidelidad): verifica que ningún concepto técnico fue alterado, omitido o mal interpretado.
Pasada 2 (naturalización): elimina calcos sintácticos, construcciones literales que suenan raras en el idioma destino.
Entrega el texto revisado con los cambios marcados en [CAMBIO: razón].`,
    },
    q4: {
      title: '🚀 Versión Final Publicable',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Produce la versión final limpia lista para publicar',
      chainSystemPrompt: `Eres el Editor final de este pipeline de traducción. Recibirás la traducción revisada.
Tu rol: producir la versión final limpia.
Elimina todas las marcas de revisión [CAMBIO:] y [término original], aplica los cambios,
verifica coherencia terminológica en todo el documento (mismo término = misma traducción siempre),
ajusta formato final si el original tenía estructura específica.
Entrega el texto final listo para publicar, sin marcas ni anotaciones.`,
    },
    star: 2,
  },

  '37': { // Resumen de Papers
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Entidades Clave',
    q2: {
      title: '🤖 Extractor de Conocimiento Científico',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Identifica los componentes estructurales del paper',
      chainSystemPrompt: `Eres el Extractor de conocimiento de este pipeline de análisis de papers.
Tu rol: descomponer el paper en sus componentes estructurales antes de sintetizar.
Produce: (1) pregunta de investigación exacta, (2) hipótesis planteada,
(3) metodología usada y tamaño de muestra/dataset, (4) hallazgos principales con datos específicos,
(5) limitaciones reconocidas por los autores, (6) implicaciones prácticas señaladas.
Tu extracción será la base para la síntesis y la crítica.`,
    },
    q3: {
      title: '💡 Sintetizador Accesible',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Produce el resumen accesible para no especialistas',
      chainSystemPrompt: `Eres el Sintetizador de este pipeline. Recibirás los componentes estructurales del paper del cuadrante anterior.
Tu rol: producir un resumen denso y accesible para alguien inteligente pero no especialista en el tema.
Máximo 300 palabras. Sin jerga innecesaria. Incluye: qué problema resuelve, cómo lo hicieron,
qué descubrieron, por qué importa. Los datos concretos van, las palabras vacías no.`,
    },
    q4: {
      title: '🚀 Crítico Metodológico',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Evalúa la solidez metodológica y las limitaciones del paper',
      chainSystemPrompt: `Eres el Crítico metodológico de este pipeline. Recibirás la extracción y el resumen del paper.
Tu rol: evaluar la solidez del paper de forma objetiva.
Produce: (1) fortalezas metodológicas concretas,
(2) debilidades o limitaciones que los autores no mencionaron,
(3) qué conclusiones están bien respaldadas vs cuáles son especulativas,
(4) calificación de confianza general (alta/media/baja) con justificación.
Sin sesgo de confirmación. Si el paper tiene problemas, dilo.`,
    },
    star: 2,
  },

  '38': { // Brainstorming de Marcas
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Clichés de Marca',
    q2: {
      title: '🤖 Brand Strategist',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define posicionamiento, arquetipo y territorio semántico de la marca',
      chainSystemPrompt: `Eres el Brand Strategist de este pipeline de branding.
Tu rol: definir el territorio de la marca antes de generar nombres.
Produce: (1) propuesta de valor única — en una oración, qué hace esta marca diferente,
(2) arquetipo de marca (Jung) y cómo se expresa en el tono de comunicación,
(3) territorio semántico: 5 palabras que la marca DEBE evocar y 5 que debe evitar,
(4) target primario: descripción específica del cliente ideal,
(5) restricciones de naming: idioma, extensión, sonoridad, qué no puede parecer.
Tu estrategia guiará la generación de nombres.`,
    },
    q3: {
      title: '💡 Generador de Nombres',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Genera nombres de marca basado en la estrategia de Q2',
      chainSystemPrompt: `Eres el Generador de nombres de este pipeline. Recibirás la estrategia de marca del cuadrante anterior.
Tu rol: generar nombres de marca que cumplan la estrategia definida.
Produce 15 nombres con: (1) el nombre, (2) concepto o etimología detrás del nombre,
(3) cómo se alinea con el territorio semántico definido, (4) posible dominio .com/.io/.co.
Variedad de enfoques: descriptivo, abstracto, compuesto, neologismo, acrónimo.`,
    },
    q4: {
      title: '🚀 Filtro de Mercado',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Evalúa los nombres y selecciona el top 3 con justificación',
      chainSystemPrompt: `Eres el Filtro de mercado de este pipeline. Recibirás la estrategia de marca y los 15 nombres generados.
Tu rol: evaluar cada nombre y recomendar el top 3.
Para los 15 nombres evalúa: memorabilidad (1-5), riesgo de confusión con marcas existentes (bajo/medio/alto),
pronunciabilidad en español e inglés, disponibilidad estimada de dominio.
Produce: tabla de evaluación + recomendación de top 3 con justificación de por qué estos y no los otros.`,
    },
    star: 3,
  },

  '39': { // Correos Corporativos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Tono de Negociación',
    q2: {
      title: '🤖 Estratega de Comunicación',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Define objetivo, tono y estrategia del correo antes de redactar',
      chainSystemPrompt: `Eres el Estratega de comunicación de este pipeline de correos corporativos.
Tu rol: diseñar la estrategia antes de redactar una sola línea.
Produce: (1) objetivo real del correo — qué acción concreta debe tomar el receptor,
(2) posición negociadora: cuánta flexibilidad tenemos y cuánta mostramos,
(3) tono exacto recomendado y por qué (asertivo/consultivo/formal/colaborativo),
(4) qué información incluir para maximizar la probabilidad de respuesta positiva,
(5) qué omitir estratégicamente aunque sea verdad.
Tu estrategia guiará al redactor.`,
    },
    q3: {
      title: '💡 Redactor Corporativo',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Redacta el correo completo siguiendo la estrategia de Q2',
      chainSystemPrompt: `Eres el Redactor de este pipeline. Recibirás la estrategia comunicacional del cuadrante anterior.
Tu rol: redactar el correo completo.
Incluye: asunto que maximiza la tasa de apertura, párrafo de apertura sin relleno,
cuerpo directo y estructurado, CTA claro y específico, cierre profesional.
Sin saludos genéricos de relleno, sin frases de "espero que este correo te encuentre bien".
Listo para enviar.`,
    },
    q4: {
      title: '🚀 Revisor de Comunicación',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Verifica tono, detecta ambigüedades y produce versión final',
      chainSystemPrompt: `Eres el Revisor final de este pipeline. Recibirás la estrategia y el correo redactado.
Tu rol: revisar el correo antes de enviarlo.
Verifica: (1) que el asunto refleja el contenido y es atractivo sin ser clickbait,
(2) que el CTA es claro y el receptor sabe exactamente qué hacer,
(3) que no hay ambigüedades que puedan malinterpretarse,
(4) que el tono es consistente con la estrategia definida.
Entrega la versión final corregida lista para enviar.`,
    },
    star: 3,
  },

  '40': { // Prompt Engineering
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Optimizador de System Prompts',
    q2: {
      title: '🤖 Arquitecto de Prompts',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Diseña la estructura del prompt: sistema, few-shots, formato',
      chainSystemPrompt: `Eres el Arquitecto de prompts de este pipeline de prompt engineering.
Tu rol: diseñar la arquitectura del prompt antes de redactarlo.
Produce: (1) estrategia de system prompt — qué debe incluir y en qué orden,
(2) necesidad de few-shot examples — cuántos y de qué tipo,
(3) cadena de razonamiento — si aplica chain-of-thought y cómo estructurarlo,
(4) formato de output — qué estructura debe tener la respuesta del modelo,
(5) variables o placeholders que el prompt debe parametrizar.
Tu diseño guiará la redacción del prompt completo.`,
    },
    q3: {
      title: '💡 Generador de Variantes',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Produce el prompt base y 2 variantes alternativas',
      chainSystemPrompt: `Eres el Generador de variantes de este pipeline. Recibirás el diseño arquitectural del prompt del cuadrante anterior.
Tu rol: producir el prompt completo en 3 variantes estratégicamente diferentes.
Variante A: enfoque directo e instruccional (dile exactamente qué hacer).
Variante B: enfoque role-play (asígnale una identidad experta al modelo).
Variante C: chain-of-thought (pídele que piense paso a paso antes de responder).
Para cada variante: el prompt completo + en qué situación funciona mejor.`,
    },
    q4: {
      title: '🚀 Meta-Evaluador',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Evalúa las variantes y produce la versión fusionada optimizada',
      chainSystemPrompt: `Eres el Meta-evaluador de este pipeline. Recibirás el diseño arquitectural y las 3 variantes del prompt.
Tu rol: evaluar cuál variante producirá mejores resultados para el caso de uso específico y por qué.
Produce: (1) evaluación de cada variante con su fortaleza y debilidad principal,
(2) recomendación de cuál usar en producción con justificación técnica,
(3) versión fusionada que toma lo mejor de las 3 variantes,
(4) sugerencias de red flags a monitorear en las respuestas del modelo al usar este prompt.`,
    },
    star: 2,
  },

  '41': { // Corrección de Estilo
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Corrector de Ortografía',
    q2: {
      title: '🤖 Editor de Contenido',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Corrige ortografía, gramática y coherencia argumental',
      chainSystemPrompt: `Eres el Editor de contenido de este pipeline de corrección.
Tu rol: primera pasada de corrección estructural.
Corrige: ortografía, puntuación, concordancia gramatical, tiempos verbales inconsistentes,
referencias pronominales ambiguas, estructura de párrafos (idea central + desarrollo).
Entrega el texto corregido. Si hay problemas de coherencia argumental (el texto no tiene sentido lógico),
señálalos entre [COHERENCIA: descripción del problema].`,
    },
    q3: {
      title: '💡 Estilista de Texto',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Mejora el estilo del texto corregido por Q2',
      chainSystemPrompt: `Eres el Estilista de este pipeline. Recibirás el texto ya corregido gramaticalmente.
Tu rol: mejorar el estilo sin cambiar el contenido ni el registro original.
Mejora: variedad sintáctica (mezcla oraciones cortas y largas), vocabulario más preciso donde sea vago,
elimina muletillas y redundancias, mejora las transiciones entre ideas,
evita repetición de palabras en párrafos cercanos. Entrega el texto estilizado.`,
    },
    q4: {
      title: '🚀 Verificador de Tono Final',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Verifica coherencia de tono y entrega versión final',
      chainSystemPrompt: `Eres el Verificador de tono final de este pipeline. Recibirás el texto original y las versiones corregidas.
Tu rol: verificar que la versión final mantiene el tono y voz del autor original.
Detecta: cambios de tono que no corresponden al texto original (se volvió más formal/informal de lo que era),
pérdida de la voz del autor en la corrección de estilo. Produce la versión final con los ajustes necesarios.`,
    },
    star: 3,
  },

  '42': { // Simulación de Entrevistas Técnicas
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Sesgos Técnicos',
    q2: {
      title: '🤖 Entrevistador Senior',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Formula preguntas técnicas progresivas y evalúa respuestas',
      chainSystemPrompt: `Eres el Entrevistador senior de este pipeline de preparación de entrevistas.
Tu rol: simular la parte técnica de la entrevista.
Produce: (1) 5-7 preguntas técnicas progresivas para el rol y nivel indicado en el prompt original
(conceptual → aplicado → diseño de sistemas → situacional),
(2) si el prompt incluye respuestas del candidato, evalúa cada una con: qué acertó, qué faltó, qué fue incorrecto.
Sé exigente pero justo. El objetivo es preparar al candidato para la entrevista real.`,
    },
    q3: {
      title: '💡 Evaluador de Gaps',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Identifica gaps de conocimiento específicos basado en la evaluación de Q2',
      chainSystemPrompt: `Eres el Evaluador de gaps de este pipeline. Recibirás las preguntas de la entrevista y la evaluación del candidato.
Tu rol: identificar los gaps de conocimiento específicos y su impacto.
Produce: (1) mapa de competencias evaluadas y nivel demostrado por el candidato,
(2) gaps críticos que podrían costar el trabajo (con prioridad alta),
(3) gaps importantes pero no bloqueantes (con prioridad media),
(4) fortalezas detectadas que vale la pena seguir desarrollando.`,
    },
    q4: {
      title: '🚀 Coach de Preparación',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Produce el plan de estudio personalizado basado en los gaps de Q3',
      chainSystemPrompt: `Eres el Coach de preparación de este pipeline. Recibirás la evaluación de la entrevista y el mapa de gaps.
Tu rol: producir el plan de estudio personalizado para cerrar los gaps antes de la próxima entrevista.
Produce: (1) recursos concretos por gap (documentación, cursos específicos, proyectos prácticos),
(2) orden de estudio recomendado: qué estudiar primero y por qué,
(3) 3 preguntas de práctica para los 3 gaps más críticos,
(4) estimación realista de tiempo para estar listo.`,
    },
    star: 2,
  },

  '43': { // Prompt Engineering para Imágenes IA
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Optimizador de Descripción Visual',
    q2: {
      title: '🤖 Visual Strategist',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define estilo, composición, paleta y mood de la imagen',
      chainSystemPrompt: `Eres el Visual Strategist de este pipeline de prompt engineering para imágenes IA.
Tu rol: definir la dirección visual completa antes de construir el prompt.
Produce: (1) estilo artístico específico con referencias (fotorrealismo, ilustración, pintura al óleo, anime, etc.),
(2) composición: plano, ángulo de cámara, regla de tercios aplicada,
(3) paleta de colores: 3-5 colores dominantes con descripción,
(4) lighting: tipo de luz, dirección, temperatura,
(5) elementos a incluir y elementos a excluir explícitamente,
(6) mood/atmósfera que debe transmitir la imagen.
Tu dirección visual guiará la construcción del prompt técnico.`,
    },
    q3: {
      title: '💡 Prompt Constructor IA Visual',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Construye el prompt técnico para Midjourney/SDXL basado en la dirección de Q2',
      chainSystemPrompt: `Eres el Prompt Constructor de este pipeline. Recibirás la dirección visual del cuadrante anterior.
Tu rol: construir el prompt técnico optimizado para generadores de imagen IA.
Produce: (1) prompt positivo completo para Midjourney con pesos si aplica,
(2) negative prompt completo con los elementos a evitar,
(3) parámetros recomendados (--ar, --style, --v, steps, CFG scale para SDXL),
(4) variante del prompt para Stable Diffusion si el estilo es diferente.`,
    },
    q4: {
      title: '🚀 Preview SVG del Concepto',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash' },
      ],
      role: 'Genera infografía SVG de referencia de composición',
      chainSystemPrompt: `Genera exclusivamente el elemento SVG o infografía visual solicitada como referencia de composición.
REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque Markdown (\`\`\`svg ... \`\`\` o \`\`\`html ... \`\`\`).
Sin texto introductorio, sin explicaciones, sin conclusiones — solo el bloque de código autónomo y directamente renderizable.
El SVG debe representar la composición, paleta y elementos definidos en el contexto recibido.`,
    },
    q4SystemPrompt: `Genera exclusivamente el elemento SVG o infografía visual solicitada. REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque Markdown (\`\`\`svg ... \`\`\` o \`\`\`html ... \`\`\`). Sin texto introductorio, sin explicaciones, sin conclusiones — solo el bloque de código autónomo y directamente renderizable.`,
    star: 2,
  },

  '44': { // Automatización de Video (FFmpeg/MoviePy)
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Comandos Multimedia',
    q2: {
      title: '🤖 Diseñador de Pipeline de Video',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define el flujo de procesamiento de video: inputs, transformaciones, outputs',
      chainSystemPrompt: `Eres el Diseñador de pipeline de video de este proyecto.
Tu rol: diseñar el pipeline completo antes de escribir código o comandos.
Produce: (1) inputs esperados: formato, resolución, codec, estructura de archivos,
(2) transformaciones necesarias en orden: corte, escala, filtros, overlay, audio, etc.,
(3) output esperado: formato de contenedor, codec de video, codec de audio, resolución, bitrate,
(4) herramienta recomendada (FFmpeg puro, MoviePy, OpenCV) y justificación para esta tarea.
Tu diseño guiará al implementador.`,
    },
    q3: {
      title: '💡 Implementador Multimedia',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Implementa el script completo basado en el diseño de Q2',
      chainSystemPrompt: `Eres el Implementador multimedia de este pipeline. Recibirás el diseño del pipeline de video del cuadrante anterior.
Tu rol: implementar el script completo siguiendo el diseño.
Incluye: manejo de errores con mensajes útiles, progress logging, validación de archivos de entrada,
creación de directorio de output si no existe. Script listo para ejecutar.`,
    },
    q4: {
      title: '🚀 Optimizador de Comandos',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1' },
      ],
      role: 'Optimiza los comandos FFmpeg para velocidad/calidad y genera one-liners CLI',
      chainSystemPrompt: `Eres el Optimizador de comandos de este pipeline. Recibirás el diseño y el script implementado.
Tu rol: optimizar los comandos FFmpeg para máxima eficiencia.
Produce: (1) versión optimizada de cada comando FFmpeg con flags de hardware acceleration si aplica (NVENC/VAAPI),
(2) balance óptimo velocidad/calidad para el caso de uso descrito,
(3) versión one-liner CLI para los casos de uso más comunes del pipeline,
(4) estimación de tiempo de procesamiento para 1 minuto de video de entrada.`,
    },
    star: 2,
  },

  '45': { // Guiones y Storyboarding
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Gancho Narrativo',
    q2: {
      title: '🤖 Director Creativo',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Define narrativa, arco emocional y estructura de escenas',
      chainSystemPrompt: `Eres el Director creativo de este pipeline de guiones y storyboarding.
Tu rol: definir la dirección creativa antes de escribir el guión.
Produce: (1) premisa en una oración — de qué trata y por qué alguien debería verlo,
(2) arco emocional: qué siente el espectador al inicio, en el punto de inflexión y al final,
(3) estructura de escenas: número de escenas, función de cada una y duración estimada,
(4) tono visual: referencias estéticas, paleta de color, ritmo de edición,
(5) mensaje central que el espectador debe llevarse.`,
    },
    q3: {
      title: '💡 Guionista',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Escribe el guión completo escena por escena basado en la dirección de Q2',
      chainSystemPrompt: `Eres el Guionista de este pipeline. Recibirás la dirección creativa del cuadrante anterior.
Tu rol: escribir el guión completo.
Formato por escena: [ESCENA N — DURACIÓN ESTIMADA]
Locación/contexto visual | Acción | Diálogo o voz en off | Música/sonido sugerido.
Cada escena con tiempo estimado. Total dentro de la duración objetivo del prompt original.`,
    },
    q4: {
      title: '🚀 Storyboard en Texto',
      models: [
        { id: 'meta-llama/llama-3.1-70b-instruct', label: 'Llama 3.1' },
      ],
      role: 'Produce el storyboard textual detallado del guión',
      chainSystemPrompt: `Eres el Storyboarder de este pipeline. Recibirás la dirección creativa y el guión completo.
Tu rol: producir el storyboard textual listo para trasladar a bocetos o referenciar en producción.
Por cada plano produce: número de plano, tipo de plano (plano general/medio/primer plano/detalle),
ángulo de cámara, descripción de lo que se ve, movimiento de cámara si aplica,
duración del plano, audio/diálogo correspondiente.`,
    },
    star: 2,
  },

  '46': { // Mensajes y Correos Cotidianos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Filtro de Tono y Claridad',
    q2: {
      title: '🤖 Redactor de Mensajes',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Produce el mensaje completo con el tono correcto',
      chainSystemPrompt: `Eres el Redactor de este pipeline de comunicación cotidiana.
Tu rol: producir el mensaje o correo completo con el tono adecuado al contexto.
Lee el contexto y el objetivo del prompt original.
Produce el mensaje completo: directo, sin relleno, con la intención comunicacional lograda.
Si es correo: incluye asunto, cuerpo y cierre. Si es mensaje de chat: texto listo para pegar.`,
    },
    q3: {
      title: '💡 Simplificador',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Elimina todo lo que no suma y produce versión más directa',
      chainSystemPrompt: `Eres el Simplificador de este pipeline. Recibirás el mensaje redactado por el cuadrante anterior.
Tu rol: eliminar todo lo que no suma al objetivo comunicacional.
Corta: frases de cortesía vacías, repeticiones, contexto que el receptor ya sabe,
cualquier oración que se pueda quitar sin perder el mensaje.
Entrega la versión mínima viable del mensaje que aún logra el objetivo.`,
    },
    q4: {
      title: '🚀 Versión Express',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash' },
      ],
      role: 'Produce la versión ultra-corta para WhatsApp/SMS',
      chainSystemPrompt: `Eres el especialista de versión express de este pipeline. Recibirás el mensaje simplificado del cuadrante anterior.
Tu rol: producir la versión ultra-corta para WhatsApp o SMS.
Máximo 3 líneas. Sin saludos. Sin despedidas. Solo el mensaje esencial.
El receptor debe entender exactamente qué se le pide o comunica sin ambigüedad.
Si hay CTA, que sea la última línea.`,
    },
    star: 2,
  },

  '47': { // Compresión de Textos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Pre-filtro de Densidad',
    q2: {
      title: '🤖 Extractor de Ideas Fuerza',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Identifica las ideas principales y su peso relativo',
      chainSystemPrompt: `Eres el Extractor de ideas de este pipeline de compresión de texto.
Tu rol: identificar las ideas fuerza antes de sintetizar.
Produce: (1) lista de todas las ideas relevantes del texto (no detalles, no ejemplos, solo ideas),
(2) jerarquización: ideas principales vs ideas de soporte vs ejemplos prescindibles,
(3) relaciones entre ideas: cuáles se derivan de cuáles, cuáles son independientes,
(4) la idea central única de la que todo lo demás depende.
Tu extracción guiará la síntesis semántica.`,
    },
    q3: {
      title: '💡 Sintetizador Semántico',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Produce el párrafo ultra-denso con todas las ideas fuerza',
      chainSystemPrompt: `Eres el Sintetizador semántico de este pipeline. Recibirás el mapa de ideas del cuadrante anterior.
Tu rol: producir el párrafo de síntesis que contiene todas las ideas fuerza sin redundancia.
Máximo 150 palabras. Cada oración debe agregar información nueva.
Sin frases de transición vacías. Sin repetir con otras palabras lo que ya se dijo.
Denso, preciso, completo.`,
    },
    q4: {
      title: '🚀 TL;DR Final',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5' },
      ],
      role: 'Produce el resumen de 1-3 líneas para compartir',
      chainSystemPrompt: `Eres el TL;DR de este pipeline. Recibirás el mapa de ideas y la síntesis del texto.
Tu rol: producir el resumen de máximo 3 líneas listo para compartir en cualquier contexto.
Captura la esencia completa del texto original. Si alguien solo lee estas 3 líneas,
debe entender de qué trata y cuál es su conclusión principal.
Sin "Este texto habla de..." ni frases similares. Directo al contenido.`,
    },
    star: 2,
  },

  // ════════════════════════════════════════════════════════════════════
  // TAREAS NUEVAS 49-56: FLUJOS AVANZADOS DE ESPECIALIZACIÓN
  // ════════════════════════════════════════════════════════════════════

  '49': { // Investigación Predictiva / Ensemble de Modelos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Compresor de Variables Predictivas',
    q2: {
      title: '🤖 Analista Táctico GPT',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Síntesis táctica e integración de contexto heterogéneo',
      chainSystemPrompt: `Eres el Analista táctico de este pipeline de investigación predictiva.
Tu rol: integrar toda la información disponible y producir el análisis de contexto.
Produce: (1) síntesis de las variables clave y sus relaciones,
(2) hipótesis principal con evidencia de soporte,
(3) factores de riesgo que podrían invalidar la hipótesis,
(4) datos adicionales que fortalecerían o debilitarían el análisis.
Estructura tu output en secciones claras: [CONTEXTO], [HIPÓTESIS], [EVIDENCIA], [FACTORES DE RIESGO].
Tu análisis será auditado por un modelo especializado en validación lógica.`,
    },
    q3: {
      title: '💡 Auditor Lógico Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Audita el razonamiento de Q2 y valida consistencia lógica',
      chainSystemPrompt: `Eres el Auditor lógico de este pipeline. Recibirás el análisis del cuadrante anterior.
Tu rol: auditar la solidez del razonamiento recibido.
Produce: (1) validaciones — qué partes del análisis están bien fundamentadas,
(2) inconsistencias o saltos lógicos identificados,
(3) supuestos no declarados que el análisis asume implícitamente,
(4) confianza estimada en la hipótesis principal (0-100%) con justificación,
(5) correcciones o matices que deben incorporarse.
Tu auditoría alimentará la síntesis ensemble final.`,
    },
    q4: {
      title: '🚀 Sintetizador Ensemble Gemini',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash Free' },
      ],
      role: 'Produce la predicción final ensemble resolviendo discrepancias',
      chainSystemPrompt: `Eres el Sintetizador ensemble de este pipeline. Recibirás el análisis táctico y la auditoría lógica.
Tu rol: producir la conclusión predictiva final reconciliando ambas perspectivas.
Produce: (1) resolución de cada discrepancia encontrada entre el análisis y la auditoría,
(2) predicción final con nivel de confianza ponderado,
(3) escenarios alternativos si la confianza es menor al 70%,
(4) señales específicas a monitorear que confirmarían o refutarían la predicción.`,
    },
    star: 4,
  },

  '50': { // Auditoría de Código Multi-Capa
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Problema Técnico',
    q2: {
      title: '🤖 Auditor Arquitectural Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Auditoría de arquitectura y refactorización de alto nivel',
      chainSystemPrompt: `Eres el Auditor arquitectural de este pipeline de auditoría multi-capa.
Tu rol: auditar el código a nivel de arquitectura y diseño.
Produce: (1) evaluación de la estructura general: cohesión, acoplamiento, separación de responsabilidades,
(2) patrones de diseño presentes y si son los adecuados para el caso,
(3) deuda técnica arquitectural identificada con impacto en mantenibilidad,
(4) propuesta de refactorización de alto nivel (sin reescribir el código aún).
Tu auditoría arquitectural guiará la validación a nivel de código.`,
    },
    q3: {
      title: '💡 Validador de Código Qwen',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Valida sintaxis, edge cases y produce el código refactorizado',
      chainSystemPrompt: `Eres el Validador de código de este pipeline. Recibirás la auditoría arquitectural del cuadrante anterior.
Tu rol: implementar las correcciones a nivel de código siguiendo las recomendaciones arquitecturales.
Produce: (1) código refactorizado completo aplicando los cambios recomendados,
(2) manejo de edge cases no cubiertos en el código original,
(3) mejoras de performance a nivel de implementación (no de arquitectura).
Código completo y ejecutable.`,
    },
    q4: {
      title: '🚀 Documentador de Auditoría',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash Free' },
      ],
      role: 'Documenta los cambios realizados y genera el reporte de auditoría',
      chainSystemPrompt: `Eres el Documentador de este pipeline. Recibirás la auditoría arquitectural y el código refactorizado.
Tu rol: producir la documentación completa de la auditoría.
Produce: (1) resumen ejecutivo de la auditoría (para un manager técnico),
(2) changelog técnico detallado: qué cambió, por qué, impacto esperado,
(3) guía de migración si hay cambios que afectan la API pública del módulo,
(4) checklist de validación post-refactorización.`,
    },
    star: 2,
  },

  '51': { // Contenido Estratégico Multi-Canal
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Audiencia y Objetivo',
    q2: {
      title: '🤖 Redactor Narrativo Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Produce el borrador con estructura narrativa sólida',
      chainSystemPrompt: `Eres el Redactor narrativo de este pipeline de contenido estratégico.
Tu rol: producir el borrador con la narrativa correcta para el objetivo del contenido.
Considera: audiencia, canal primario y objetivo comunicacional del prompt original.
Produce el contenido completo con: hook de apertura, desarrollo con evidencia/ejemplos,
punto de inflexión o insight sorprendente, cierre con mensaje memorable o CTA.
Tu borrador será refinado en estilo y adaptado por los cuadrantes siguientes.`,
    },
    q3: {
      title: '💡 Refinador de Estilo DeepSeek',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Refina el estilo del borrador de Q2, elimina fluff y densifica',
      chainSystemPrompt: `Eres el Refinador de estilo de este pipeline. Recibirás el borrador del cuadrante anterior.
Tu rol: refinar el estilo sin cambiar el contenido ni la narrativa.
Aplica: eliminar frases decorativas sin información, oraciones más cortas en momentos de impacto,
vocabulario más preciso y específico, eliminar redundancias, mejorar ritmo de lectura.
Entrega el texto refinado, más denso y directo que el borrador.`,
    },
    q4: {
      title: '🚀 Adaptador de Canal GPT',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Adapta el contenido refinado al canal de publicación objetivo',
      chainSystemPrompt: `Eres el Adaptador de canal de este pipeline. Recibirás el contenido refinado y el canal objetivo del prompt original.
Tu rol: adaptar el contenido al formato y convenciones del canal específico.
Para el canal indicado en el prompt: ajusta extensión, formato, tono, estructura de párrafos,
uso de hashtags o keywords si aplica, longitud de oraciones para el contexto de lectura del canal.
Entrega la versión final lista para publicar en ese canal específico.`,
    },
    star: 4,
  },

  '52': { // RAG Simulado / Análisis de Documento
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Preguntas del Documento',
    q2: {
      title: '🤖 Respondedor Profundo GPT',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Responde en profundidad basándose exclusivamente en el documento',
      chainSystemPrompt: `Eres el Respondedor profundo de este pipeline RAG simulado.
Tu rol: responder basándote ÚNICAMENTE en el documento adjunto en el prompt original.
Produce: respuestas a cada pregunta extraída del documento, citando la sección específica de origen.
Si una pregunta no puede responderse con el documento, dilo explícitamente.
No añadas conocimiento externo. Solo lo que está en el documento.
Estructura: [PREGUNTA] → [RESPUESTA] → [SECCIÓN DE ORIGEN].`,
    },
    q3: {
      title: '💡 Verificador de Coherencia Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Verifica que las respuestas de Q2 son coherentes con el documento',
      chainSystemPrompt: `Eres el Verificador de coherencia de este pipeline. Recibirás las respuestas del cuadrante anterior y el documento original.
Tu rol: verificar que cada respuesta es fiel al documento.
Para cada respuesta: confirma si la cita de origen es correcta, detecta si hubo alucinación
(información que no está en el documento), identifica respuestas parciales que omiten información relevante.
Produce el reporte de verificación con: qué es correcto, qué es incorrecto, qué está incompleto.`,
    },
    q4: {
      title: '🚀 Resumen Ejecutivo Gemini',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash Free' },
      ],
      role: 'Genera resumen ejecutivo y lista de gaps del documento',
      chainSystemPrompt: `Eres el Sintetizador final de este pipeline. Recibirás las respuestas verificadas del documento.
Tu rol: producir el entregable final del análisis.
Produce: (1) resumen ejecutivo del documento en máximo 200 palabras,
(2) respuestas validadas a las preguntas planteadas (incorporando correcciones de la verificación),
(3) gaps de información — preguntas que el documento no responde y que requieren fuentes adicionales,
(4) próximos pasos recomendados basados en el contenido del documento.`,
    },
    star: 4,
  },

  '53': { // Prompt Engineering Colaborativo
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor del Objetivo del Prompt',
    q2: {
      title: '🤖 Arquitecto de Prompt Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Diseña y redacta el master prompt con estructura técnica',
      chainSystemPrompt: `Eres el Arquitecto de prompt de este pipeline colaborativo de prompt engineering.
Tu rol: diseñar y redactar el master prompt técnico para el objetivo indicado.
Incluye: system prompt completo, instrucciones de comportamiento, formato de output esperado,
few-shot examples si aplica, variables parametrizables en {{doble_llave}}.
El prompt debe ser production-ready para el modelo target indicado en el prompt original.`,
    },
    q3: {
      title: '💡 Generador de Variantes DeepSeek',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Genera variante alternativa del prompt y casos edge',
      chainSystemPrompt: `Eres el Generador de variantes de este pipeline. Recibirás el master prompt del cuadrante anterior.
Tu rol: generar una variante alternativa con enfoque diferente y los casos edge del prompt original.
Produce: (1) variante del prompt con una estrategia diferente (si Q2 usó chain-of-thought, usa role-play, etc.),
(2) lista de casos edge que el prompt original no maneja bien,
(3) sugerencias de cómo el master prompt podría fallar y cómo prevenirlo.`,
    },
    q4: {
      title: '🚀 Meta-Evaluador GPT',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Evalúa ambas variantes y produce la versión fusionada final',
      chainSystemPrompt: `Eres el Meta-evaluador de este pipeline. Recibirás el master prompt, la variante alternativa y los casos edge.
Tu rol: evaluar ambos prompts y producir la versión fusionada óptima.
Produce: (1) evaluación de cada prompt en dimensiones: claridad, completitud, robustez, eficiencia de tokens,
(2) qué elementos de cada versión son superiores y por qué,
(3) versión fusionada final que incorpora lo mejor de ambas y cubre los casos edge identificados,
(4) instrucciones de uso: cuándo usar esta versión, parámetros recomendados del modelo.`,
    },
    star: 4,
  },

  '54': { // Diseño de Agentes Autónomos
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Objetivo del Agente',
    q2: {
      title: '🤖 Arquitecto de Agente Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Diseña la arquitectura del agente: herramientas, memoria, condiciones de parada',
      chainSystemPrompt: `Eres el Arquitecto de agentes de este pipeline.
Tu rol: diseñar la arquitectura completa del agente autónomo.
Produce: (1) objetivo del agente y definición clara de éxito,
(2) herramientas necesarias (web_search, code_execution, file_read, API calls, etc.) y su propósito,
(3) estrategia de memoria: qué guardar en memoria de corto plazo vs largo plazo,
(4) condiciones de parada: cuándo el agente debe detenerse (éxito, fallo, límite de iteraciones),
(5) puntos de decisión donde el agente debe pedir confirmación humana.
Tu arquitectura guiará la implementación.`,
    },
    q3: {
      title: '💡 Implementador de Flujo Qwen',
      models: [
        { id: 'qwen/qwen-2.5-coder-32b-instruct:free', label: 'Qwen 2.5 Coder' },
      ],
      role: 'Implementa el flujo del agente en pseudocódigo o LangGraph',
      chainSystemPrompt: `Eres el Implementador de flujo de este pipeline. Recibirás la arquitectura del agente del cuadrante anterior.
Tu rol: implementar el flujo del agente en código ejecutable.
Usa: LangGraph si el prompt especifica Python, pseudocódigo estructurado si no se especifica lenguaje.
Incluye: nodos del grafo con sus funciones, edges condicionales, manejo de errores en cada herramienta,
logging de cada acción del agente para trazabilidad. Código o pseudocódigo completo.`,
    },
    q4: {
      title: '🚀 Evaluador de Robustez GPT',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Evalúa robustez, identifica fallos potenciales y diseña monitoreo',
      chainSystemPrompt: `Eres el Evaluador de robustez de este pipeline. Recibirás la arquitectura y la implementación del agente.
Tu rol: evaluar qué puede salir mal y cómo prepararse.
Produce: (1) escenarios de fallo más probables: herramienta no disponible, respuesta inesperada, loop infinito,
(2) estrategias de mitigación para cada escenario,
(3) métricas de monitoreo recomendadas (tasa de éxito, iteraciones promedio, costo de tokens por tarea),
(4) criterios para saber cuándo el agente necesita ser ajustado o retirado.`,
    },
    star: 2,
  },

  '55': { // LLMOps / Auditoría de Costos IA
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor de Métricas de Uso',
    q2: {
      title: '🤖 Analista de Uso GPT',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Analiza el uso actual: tokens, latencia, costos por endpoint',
      chainSystemPrompt: `Eres el Analista de uso LLM de este pipeline LLMOps.
Tu rol: analizar el estado actual del uso de modelos de lenguaje.
Produce: (1) desglose de costo por modelo y endpoint,
(2) análisis de latencia: P50/P95/P99 si hay datos, o estimación según el modelo usado,
(3) eficiencia de tokens: ratio tokens de input vs output, costo por token útil en el output,
(4) identificación de los 3 endpoints o casos de uso con mayor costo,
(5) comparación con alternativas más baratas si las hay para los mismos casos de uso.`,
    },
    q3: {
      title: '💡 Optimizador de Prompts Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Optimiza los prompts para reducir tokens sin perder calidad',
      chainSystemPrompt: `Eres el Optimizador de prompts de este pipeline. Recibirás el análisis de uso del cuadrante anterior.
Tu rol: identificar oportunidades concretas de optimización de tokens.
Produce: (1) técnicas de compresión de prompts aplicables al caso (few-shot reduction, instruction pruning),
(2) candidatos a cambio de modelo (dónde un modelo más barato puede hacer el trabajo igualmente bien),
(3) casos donde cacheo de prompts reduciría costos significativamente,
(4) estimación de ahorro mensual por cada optimización propuesta.`,
    },
    q4: {
      title: '🚀 Reporte Ejecutivo de Ahorro Gemini',
      models: [
        { id: 'google/gemini-2.5-flash:free', label: 'Gemini 2.5 Flash Free' },
      ],
      role: 'Genera reporte ejecutivo con proyección de ahorro',
      chainSystemPrompt: `Eres el Generador de reporte ejecutivo de este pipeline. Recibirás el análisis de uso y las optimizaciones propuestas.
Tu rol: producir el reporte ejecutivo de LLMOps listo para presentar a management.
Incluye: costo actual mensual estimado, ahorro potencial total con las optimizaciones,
ROI de implementar las optimizaciones (esfuerzo vs ahorro), roadmap de implementación priorizado por ROI,
métricas de monitoreo continuo recomendadas para evitar que los costos escalen sin control.`,
    },
    star: 4,
  },

  '56': { // Fine-Tuning Strategy
    pipelineMode: 'chain',
    chainContext: 'full',
    q1Title: '⚡ Extractor del Caso de Fine-Tuning',
    q2: {
      title: '🤖 Diseñador de Dataset Claude',
      models: [
        { id: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet' },
      ],
      role: 'Diseña la estructura y criterios de calidad del dataset',
      chainSystemPrompt: `Eres el Diseñador de dataset de este pipeline de fine-tuning.
Tu rol: diseñar el dataset antes de generar ejemplos.
Produce: (1) justificación de por qué fine-tuning es la solución correcta vs prompting,
(2) estructura del dataset: formato input/output, campos necesarios,
(3) cantidad de ejemplos recomendada y por qué,
(4) criterios de calidad por ejemplo: qué hace un buen ejemplo, qué lo hace malo,
(5) distribución del dataset: categorías de casos y su peso porcentual.
Tu diseño guiará la generación de ejemplos.`,
    },
    q3: {
      title: '💡 Generador de Ejemplos DeepSeek',
      models: [
        { id: 'deepseek/deepseek-chat', label: 'DeepSeek Chat' },
      ],
      role: 'Genera ejemplos del dataset para el dominio específico',
      chainSystemPrompt: `Eres el Generador de ejemplos de este pipeline. Recibirás el diseño del dataset del cuadrante anterior.
Tu rol: generar ejemplos reales del dataset siguiendo el diseño exactamente.
Genera mínimo 10 ejemplos distribuidos entre las categorías definidas.
Cada ejemplo en el formato especificado, cumpliendo los criterios de calidad definidos.
Incluye casos positivos (buenos ejemplos) y negativos (cómo NO responder) si el diseño los requiere.`,
    },
    q4: {
      title: '🚀 Plan de Entrenamiento GPT',
      models: [
        { id: 'openai/gpt-4o', label: 'GPT-4o' },
      ],
      role: 'Produce el plan técnico de entrenamiento con métricas de éxito',
      chainSystemPrompt: `Eres el Planificador de entrenamiento de este pipeline. Recibirás el diseño del dataset y los ejemplos generados.
Tu rol: producir el plan técnico completo de fine-tuning.
Produce: (1) modelo base recomendado y justificación (GPT-3.5, Llama 3, Mistral, etc.),
(2) hiperparámetros de entrenamiento sugeridos: epochs, learning rate, batch size,
(3) división train/validation/test con ratios y razón,
(4) métricas de evaluación específicas para este caso de uso,
(5) criterio de éxito — cómo saber que el fine-tuning funcionó,
(6) plan de evaluación humana: qué evaluar, quién lo hace, cuántos ejemplos de prueba.`,
    },
    star: 2,
  },

};

// ============================================================
// MÓDULO TASK ROUTER
// ============================================================
const TaskRouter = {
  current: 'default',

  /**
   * Aplica la configuración de TASK_MATRIX[taskKey] al DOM:
   *   1. Actualiza los títulos h2 de los 4 cuadrantes.
   *   2. Reconstruye los <select> de modelos en el orden óptimo.
   *   3. Aplica/retira el destaque dorado "Top Pick" al cuadrante estrella.
   */
  apply(taskKey) {
    const config = TASK_MATRIX[taskKey] ?? TASK_MATRIX.default;
    this.current        = taskKey;
    AppState.currentTask = taskKey; // disponible para bloques futuros

    // Título de Q1
    const t1 = document.getElementById('title-1');
    if (t1) t1.textContent = config.q1Title;

    // Q2, Q3, Q4: título + select reordenado
    [2, 3, 4].forEach(qId => {
      const qConf = config[`q${qId}`];

      // Actualizar encabezado del cuadrante
      const titleEl = document.getElementById(`title-${qId}`);
      if (titleEl) titleEl.textContent = qConf.title;

      // Reconstruir el <select> de modelos.
      // El primer <option> queda seleccionado por defecto → apunta al modelo óptimo.
      // getModelId(qId) en el Orquestador leerá select.value, que es el primer item.
      const sel = document.getElementById(`model-${qId}`);
      if (sel) {
        sel.innerHTML = qConf.models
          .map(m => `<option value="${m.id}">${m.label}</option>`)
          .join('');
      }
    });

    // Destaque visual al cuadrante estrella
    this._applyStarHighlight(config.star);

    // Badge de modo de pipeline (chain vs parallel) — solo indicativo,
    // el modo real lo fuerza la tarea seleccionada, no un toggle manual.
    AppState.pipelineMode = config.pipelineMode ?? 'parallel';
    const badge = document.getElementById('pipeline-mode-badge');
    if (badge) {
      badge.classList.remove(
        'hidden',
        'bg-blue-900/30', 'text-blue-300', 'border-blue-700/40',
        'bg-purple-900/30', 'text-purple-300', 'border-purple-700/40'
      );
      if (AppState.pipelineMode === 'chain') {
        badge.textContent = '🔗 Cadena';
        badge.classList.add('bg-blue-900/30', 'text-blue-300', 'border-blue-700/40');
      } else {
        badge.textContent = '⚡ Paralelo';
        badge.classList.add('bg-purple-900/30', 'text-purple-300', 'border-purple-700/40');
      }
    }
  },

  // Limpia el destaque anterior y aplica el nuevo al cuadrante ganador
  _applyStarHighlight(starQId) {
    [2, 3, 4].forEach(qId => {
      document.getElementById(`quad-${qId}`)?.classList.remove('quad-star');
      document.getElementById(`star-badge-${qId}`)?.remove();
    });

    if (!starQId) return;

    // Borde dorado al contenedor
    document.getElementById(`quad-${starQId}`)?.classList.add('quad-star');

    // Badge "⭐ Top Pick" insertado como hermano inmediato del h2,
    // dentro del mismo flexbox que el LED → aparece a la derecha del título.
    const titleEl = document.getElementById(`title-${starQId}`);
    if (titleEl && !document.getElementById(`star-badge-${starQId}`)) {
      const badge = document.createElement('span');
      badge.id        = `star-badge-${starQId}`;
      badge.className = [
        'text-[9px] font-bold px-1.5 py-0.5 rounded-full ml-2 align-middle',
        'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40',
        'whitespace-nowrap select-none',
      ].join(' ');
      badge.textContent = '⭐ Top Pick';
      titleEl.insertAdjacentElement('afterend', badge);
    }
  },
};

// ============================================================
// MÓDULO COLORES DE CUADRANTES — Personalización + Persistencia
// Guarda preferencias en localStorage (no sensibles).
// apply() usa inline style: si .quad-star tiene border !important,
// el borde dorado de "top pick" gana, pero el fondo personalizado persiste.
// ============================================================
const QuadrantColors = {
  defaults: { 1: '#0080ff', 2: '#00cc00', 3: '#9933ff', 4: '#ff8000' },

  apply(qId, hex) {
    const el = document.getElementById(`quad-${qId}`);
    if (!el) return;
    // Border sin !important: .quad-star { border-color !important } sigue ganando el borde dorado
    el.style.borderColor = hex;
    // Background con !important para ganar sobre los overrides del tema claro
    // hex + '26' → formato #RRGGBBAA; 0x26 = 38/255 ≈ 15% opacidad (tinte sutil visible)
    el.style.setProperty('background-color', hex + '26', 'important');
  },

  load() {
    [1, 2, 3, 4].forEach(qId => {
      const saved = localStorage.getItem(`navia_q${qId}_color`);
      if (saved) this.apply(qId, saved);
    });
  },
};

// ============================================================
// MÓDULO TEMA — Claro / Oscuro con persistencia en localStorage
// ============================================================
const Theme = {
  _key: 'navia_theme',

  init() {
    this._set(localStorage.getItem(this._key) === 'light' ? 'light' : 'dark');
  },

  toggle() {
    this._set(document.body.classList.contains('light-theme') ? 'dark' : 'light');
  },

  _set(mode) {
    const isLight = mode === 'light';
    document.body.classList.toggle('light-theme', isLight);
    const btn = document.getElementById('btn-theme');
    if (btn) btn.textContent = isLight ? '☀️' : '🌙';
    localStorage.setItem(this._key, mode);
  },
};

// ============================================================
// DEV TOOLS — Simulación de errores de red y auditoría de pipeline
//
// ACTIVO solo cuando IS_DEV === true (IS_PRODUCTION = false).
// En producción (IS_PRODUCTION = true):
//   · _DevSim.consume() siempre devuelve null → fetch real, sin intercepción.
//   · window.simulateNetworkError NO se expone en el objeto global window.
//
// Uso en desarrollo (consola del navegador):
//   window.simulateNetworkError(2, 429)
//   window.simulateNetworkError(3, 402)
// ============================================================
const _DevSim = {
  _pending: {},

  queueError(qId, code) {
    if (!IS_DEV) return; // No-op total en producción
    if (![429, 402].includes(code)) {
      console.warn(`[DevSim] Código inválido: ${code}. Usa 429 o 402.`);
      return;
    }
    this._pending[qId] = code;
    console.log(
      `%c[DevSim] Q${qId}: próxima petición devolverá HTTP ${code} (sin coste de saldo)`,
      'color:#f59e0b; font-weight:bold; background:#1c1917; padding:2px 6px; border-radius:3px'
    );
  },

  consume(qId) {
    if (!IS_DEV) return null; // Producción → siempre fetch real, sin intercepción
    const code = this._pending[qId] ?? null;
    if (code !== null) delete this._pending[qId];
    return code;
  },
};

// Solo registrar la función de test en window cuando estamos en modo desarrollo.
// En producción, window.simulateNetworkError no existe → no es invocable desde DevTools.
if (IS_DEV) {
  window.simulateNetworkError = (quadrantId, errorCode) =>
    _DevSim.queueError(quadrantId, errorCode);
}

// ============================================================
// MÓDULO SYNTHESIS — Panel post-ejecución con resumen estructurado
// ============================================================
const Synthesis = {
  _collapsed: false,
  _report:    '',

  render(downstream, optimizedPrompt) {
    const panel = document.getElementById('synthesis-panel');
    const body  = document.getElementById('synthesis-body');
    if (!panel || !body) return;

    // Recopilar texto de cada cuadrante activo que produjo respuesta
    const results = downstream.map(qId => {
      const titleEl = document.getElementById(`title-${qId}`);
      const bubble  = document.querySelector(`#output-${qId} .stream-bubble`);
      return {
        qId,
        title: titleEl?.textContent?.trim() ?? `Cuadrante ${qId}`,
        text:  bubble?.textContent?.trim()  ?? '',
      };
    }).filter(r => r.text.length > 0);

    if (results.length === 0) return;

    // Construir reporte completo para clipboard (texto plano, sin HTML)
    this._report = this._buildReport(results, optimizedPrompt);

    // Renderizar viñetas en el panel (solo textContent, sin innerHTML para LLM output)
    body.innerHTML = '';

    const label = document.createElement('p');
    label.className = 'text-[10px] text-gray-600 uppercase tracking-widest pb-1';
    label.textContent = 'Comparativa de respuestas por cuadrante:';
    body.appendChild(label);

    results.forEach(r => {
      const snippet = r.text.length > 260 ? r.text.slice(0, 260) + '…' : r.text;

      const row = document.createElement('div');
      row.className = 'border-l-2 border-gray-700 pl-3 py-0.5 space-y-0.5';

      const titleSpan = document.createElement('span');
      titleSpan.className = 'block text-[11px] font-bold text-gray-200';
      titleSpan.textContent = r.title;

      const textSpan = document.createElement('span');
      textSpan.className = 'block text-gray-500 leading-snug';
      textSpan.textContent = snippet;

      row.appendChild(titleSpan);
      row.appendChild(textSpan);
      body.appendChild(row);
    });

    // Mostrar panel expandido
    this._collapsed = false;
    panel.style.display = 'flex';
    panel.style.flexDirection = 'column';
    const tog = document.getElementById('synthesis-toggle');
    if (tog) tog.textContent = '▲';
    const bodyEl = document.getElementById('synthesis-body');
    if (bodyEl) bodyEl.style.display = '';
  },

  toggle() {
    this._collapsed = !this._collapsed;
    const bodyEl = document.getElementById('synthesis-body');
    const togBtn = document.getElementById('synthesis-toggle');
    if (bodyEl) bodyEl.style.display = this._collapsed ? 'none' : '';
    if (togBtn) togBtn.textContent   = this._collapsed ? '▼' : '▲';
  },

  hide() {
    const panel = document.getElementById('synthesis-panel');
    if (panel) panel.style.display = 'none';
    this._collapsed = false;
    this._report    = '';
  },

  _buildReport(results, prompt) {
    const line = '─'.repeat(52);
    const header = [
      '=== REPORTE CONSOLIDADO — IA ORCHESTRATOR - JW Solutions ===',
      `Prompt optimizado: ${prompt}`,
      line,
    ].join('\n');
    const sections = results.map(r =>
      `\n▸ ${r.title}\n${r.text}`
    ).join(`\n\n${line}`);
    return `${header}${sections}\n${line}\nGenerado por IA ORCHESTRATOR - JW Solutions`;
  },
};

// ============================================================
// MÓDULO Q4 PREVIEW — Renderizador SVG/HTML en vivo (Cuadrante 4)
// ============================================================
const Q4Preview = {
  _CSS_ACTIVE:   'text-xs px-2.5 py-0.5 rounded font-medium transition bg-orange-900/40 text-orange-300 border border-orange-700/40',
  _CSS_INACTIVE: 'text-xs px-2.5 py-0.5 rounded font-medium transition text-gray-500 hover:text-gray-400 hover:bg-gray-800/40',
  _svgCode: null, // SVG string almacenado para la descarga

  // ── Extracción de contenido renderable ─────────────────────
  // Prioridad: bloque de código SVG/HTML fenceado > SVG raw > documento HTML
  _extract(text) {
    // 1. Bloque ```svg o ```html
    const fenced = text.match(/```(?:svg|html)\s*([\s\S]*?)```/i);
    if (fenced) {
      const code = fenced[1].trim();
      return { code, type: /^\s*<svg/i.test(code) ? 'svg' : 'html' };
    }
    // 2. Elemento SVG en bruto
    const svgM = text.match(/<svg[\s\S]*?<\/svg>/i);
    if (svgM) return { code: svgM[0].trim(), type: 'svg' };
    // 3. Documento HTML completo
    const htmlM = text.match(/<!DOCTYPE\s+html[\s\S]*/i) ?? text.match(/<html[\s\S]*<\/html>/i);
    if (htmlM) return { code: htmlM[0].trim(), type: 'html' };
    return null;
  },

  // Envuelve SVG suelto en un documento HTML centrado y limpio
  _wrap(extracted) {
    if (extracted.type === 'html') {
      // Ya es un documento completo
      if (/<!DOCTYPE|<html/i.test(extracted.code)) return extracted.code;
      // HTML parcial — envolver
      return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{margin:0;padding:8px;font-family:sans-serif;background:#fff;}</style></head><body>${extracted.code}</body></html>`;
    }
    // SVG — centrar en lienzo blanco
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>*{box-sizing:border-box}body{margin:0;padding:12px;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#fff;}svg{max-width:100%;height:auto;}</style></head><body>${extracted.code}</body></html>`;
  },

  // Llama tras recibir la respuesta completa de Q4 — detecta y renderiza
  render(text) {
    const extracted = this._extract(text);
    if (!extracted) return;

    const frame = document.getElementById('q4-preview-frame');
    if (!frame) return;

    // Almacenar el SVG puro para la descarga (desde el contenido extraído)
    this._svgCode = extracted.type === 'svg'
      ? extracted.code
      : (extracted.code.match(/<svg[\s\S]*?<\/svg>/i)?.[0] ?? null);

    frame.srcdoc = this._wrap(extracted);
    this.switchTab('preview');

    // Mostrar panel de descarga si hay SVG
    if (this._svgCode) {
      document.getElementById('q4-download-tools')?.classList.remove('hidden');
    }
  },

  // Alterna entre pestaña "Código" y "Vista Previa"
  switchTab(tab) {
    const output  = document.getElementById('output-4');
    const preview = document.getElementById('q4-preview-container');
    const tabCode = document.getElementById('q4-tab-code');
    const tabPrev = document.getElementById('q4-tab-preview');
    if (!output || !preview || !tabCode || !tabPrev) return;

    if (tab === 'preview') {
      output.classList.add('hidden');
      preview.classList.remove('hidden');
      tabCode.className = this._CSS_INACTIVE;
      tabPrev.className = this._CSS_ACTIVE;
    } else {
      output.classList.remove('hidden');
      preview.classList.add('hidden');
      tabCode.className = this._CSS_ACTIVE;
      tabPrev.className = this._CSS_INACTIVE;
    }
  },

  // Reset completo — llamado al iniciar un nuevo run o nueva conversación
  reset() {
    this._svgCode = null;
    const frame = document.getElementById('q4-preview-frame');
    if (frame) frame.srcdoc = '';
    document.getElementById('q4-download-tools')?.classList.add('hidden');
    this.switchTab('code');
  },
};

// ============================================================
// EXPORTACIÓN SVG → PNG / JPG (High-DPI x2)
// ============================================================
async function downloadQ4Render(format) {
  const svgCode = Q4Preview._svgCode;
  if (!svgCode) {
    UI.toast('⚠ No hay SVG listo para descargar. Genera primero un gráfico en el Cuadrante 4.');
    return;
  }

  // Asegurar namespace SVG obligatorio
  let svgStr = svgCode;
  if (!svgStr.includes('xmlns=')) {
    svgStr = svgStr.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"');
  }

  // Crear Blob y Object URL
  const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
  const url  = URL.createObjectURL(blob);

  const img = new Image();

  img.onload = () => {
    // Resolver dimensiones: naturalWidth → viewBox → fallback 800×600
    let w = img.naturalWidth;
    let h = img.naturalHeight;
    if (!w || !h) {
      const vb = svgStr.match(/viewBox=["']([^"']+)["']/i);
      if (vb) {
        const p = vb[1].trim().split(/[\s,]+/);
        w = parseFloat(p[2]) || 800;
        h = parseFloat(p[3]) || 600;
      } else {
        w = 800; h = 600;
      }
    }

    const SCALE  = 2; // Upscaling High-DPI/Retina
    const canvas = document.createElement('canvas');
    canvas.width  = w * SCALE;
    canvas.height = h * SCALE;
    const ctx = canvas.getContext('2d');

    // Fondo blanco para JPG — evita canal alpha → negro
    if (format === 'jpg') {
      ctx.fillStyle = '#FFFFFF';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
    }

    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

    const mime    = format === 'jpg' ? 'image/jpeg' : 'image/png';
    const quality = format === 'jpg' ? 0.95 : undefined;
    const dataUrl = canvas.toDataURL(mime, quality);
    const ext     = format === 'jpg' ? 'jpg' : 'png';
    const fname   = `mockup_dashboard_${Date.now()}.${ext}`;

    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = fname;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();

    URL.revokeObjectURL(url);
    UI.toast(`✅ Descargando ${fname} (${Math.round(canvas.width)}×${Math.round(canvas.height)} px)`);
  };

  img.onerror = () => {
    URL.revokeObjectURL(url);
    UI.toast('⚠ Error al procesar el SVG. Verifica que sea código SVG válido.');
  };

  img.src = url;
}

// ============================================================
// MÓDULO FILE ATTACHMENTS — Lectura local + inyección de contexto
// ============================================================
const FileAttachments = {

  // Procesa un FileList (desde input[file] o drop). Lee en UTF-8 con FileReader.
  process(files) {
    Array.from(files).forEach(file => {
      const dot = file.name.lastIndexOf('.');
      const ext = dot >= 0 ? file.name.slice(dot).toLowerCase() : '';

      if (!VALID_ATTACH_EXT.has(ext)) {
        UI.toast(`⚠ "${file.name}" — tipo no soportado. Usa: txt, csv, md, py, dax, sql, json, js, html, css.`);
        return;
      }
      if (file.size > MAX_ATTACH_BYTES) {
        UI.toast(`⚠ "${file.name}" supera 2 MB y fue descartado para no saturar el contexto.`);
        return;
      }
      if (stagedFiles.some(f => f.name === file.name && f.size === file.size)) {
        UI.toast(`⚠ "${file.name}" ya está en la cola de adjuntos.`);
        return;
      }

      const reader = new FileReader();
      reader.onload  = e => {
        stagedFiles.push({ name: file.name, ext: ext.slice(1), size: file.size, content: e.target.result });
        this._renderPreview();
      };
      reader.onerror = () => UI.toast(`⚠ Error al leer "${file.name}". Intenta de nuevo.`);
      reader.readAsText(file, 'UTF-8');
    });
  },

  // Reconstruye los badges en #attachments-preview
  _renderPreview() {
    const container = document.getElementById('attachments-preview');
    if (!container) return;

    container.innerHTML = '';

    if (stagedFiles.length === 0) {
      container.style.display = 'none';
      return;
    }

    container.style.display = 'flex';

    stagedFiles.forEach((f, idx) => {
      const badge = document.createElement('span');
      badge.className = 'attachment-badge flex items-center gap-1 bg-gray-700 text-gray-200 text-xs px-2.5 py-1 rounded-full border border-gray-600 select-none';

      const nameSpan = document.createElement('span');
      nameSpan.className = 'max-w-[180px] truncate';
      nameSpan.textContent = f.name;
      nameSpan.title = f.name;

      const removeBtn = document.createElement('button');
      removeBtn.className = 'text-gray-400 hover:text-red-400 transition font-bold leading-none ml-0.5 flex-shrink-0';
      removeBtn.textContent = '×';
      removeBtn.title = `Quitar "${f.name}"`;
      removeBtn.addEventListener('click', () => {
        stagedFiles.splice(idx, 1);
        this._renderPreview();
      });

      badge.appendChild(nameSpan);
      badge.appendChild(removeBtn);
      container.appendChild(badge);
    });
  },

  // Vacía el array y limpia la UI — llamado tras cada pipeline y en Nueva Conversación
  clear() {
    stagedFiles = [];
    this._renderPreview();
  },

  // Genera el bloque Markdown estructurado para inyectar al inicio del prompt
  buildContext() {
    if (stagedFiles.length === 0) return '';
    return stagedFiles.map(f =>
      `---\n[ARCHIVO ADJUNTO: ${f.name}]\n\`\`\`${f.ext}\n${f.content}\n\`\`\`\n---`
    ).join('\n\n');
  },
};

// ============================================================
// NUEVA CONVERSACIÓN — Reset completo sin tocar keys ni preferencias
// ============================================================
function newConversation() {
  // 1. Abortar streams activos y desactivar pipeline
  [1, 2, 3, 4].forEach(qId => QuadrantState[qId].controller?.abort());
  Pipeline.active = false;
  setPipelineBtn(false);

  // 2. Reiniciar historiales (re-inyecta system prompts de cada cuadrante)
  Memory.init();

  // 3. Limpiar outputs y restaurar LEDs al estado de reposo
  Output.clear(1); LED.set(1, 'idle');
  Output.clear(2); LED.set(2, 'done');
  Output.clear(3); LED.set(3, 'idle');
  const isQ4Active = document.getElementById('active-4')?.checked ?? false;
  Output.clear(4);
  LED.set(4, isQ4Active ? 'done' : 'off');
  if (!isQ4Active) {
    const out4 = document.getElementById('output-4');
    if (out4 && !document.getElementById('q4-idle-msg')) {
      const msg = document.createElement('div');
      msg.id = 'q4-idle-msg';
      msg.className = 'h-full text-gray-500 flex items-center justify-center italic text-xs';
      msg.textContent = 'Desmarcado – Esta IA no recibirá la consulta para ahorrar tokens.';
      out4.appendChild(msg);
    }
  }

  // 4. Limpiar textarea
  const ta = document.getElementById('prompt-input');
  if (ta) ta.value = '';

  // 5. Limpiar archivos adjuntos pendientes y reset preview Q4
  FileAttachments.clear();
  Q4Preview.reset();

  // 6. Ocultar panel de síntesis y limpiar bitácora técnica
  Synthesis.hide();
  RunLog.clear();

  UI.toast('🔄 Nueva conversación iniciada. Historial limpiado.');
}

// ============================================================
// ARRANQUE
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  // ── BLOQUE 1: Seguridad ────────────────────────────────────
  document.getElementById('btn-settings')
    ?.addEventListener('click', () => SettingsModal.open());

  document.getElementById('btn-new-chat')
    ?.addEventListener('click', () => newConversation());

  UI.updateSettingsBtn();

  // Tema y colores: restaurar preferencias guardadas en localStorage
  Theme.init();
  document.getElementById('btn-theme')
    ?.addEventListener('click', () => Theme.toggle());
  QuadrantColors.load();

  // Panel de síntesis: colapsar / expandir + copiar reporte
  document.getElementById('synthesis-header')
    ?.addEventListener('click', () => Synthesis.toggle());
  document.getElementById('btn-copy-report')
    ?.addEventListener('click', e => {
      e.stopPropagation(); // evitar que el click cierre/abra el panel
      if (!Synthesis._report) return;
      navigator.clipboard.writeText(Synthesis._report).catch(() => {});
      UI.toast('📋 Reporte copiado al portapapeles');
    });
  document.getElementById('btn-generate-report')
    ?.addEventListener('click', e => {
      e.stopPropagation(); // evitar que el click cierre/abra el panel
      downloadTechnicalReport();
    });

  // ── BLOQUE 2: Orquestador ─────────────────────────────────

  // ── Adjuntos: clip + drag & drop ────────────────────────────
  const fileInput = document.getElementById('file-attachments');
  document.getElementById('btn-attach')
    ?.addEventListener('click', () => fileInput?.click());
  fileInput?.addEventListener('change', e => {
    FileAttachments.process(e.target.files);
    e.target.value = ''; // reset para permitir re-adjuntar el mismo archivo
  });

  // Drag & Drop sobre el textarea
  const textarea = document.getElementById('prompt-input');
  textarea?.addEventListener('dragover', e => {
    e.preventDefault();
    textarea.classList.add('drag-over');
  });
  textarea?.addEventListener('dragleave', () => {
    textarea.classList.remove('drag-over');
  });
  textarea?.addEventListener('drop', e => {
    e.preventDefault();
    textarea.classList.remove('drag-over');
    const droppedFiles = e.dataTransfer?.files;
    if (droppedFiles?.length) FileAttachments.process(droppedFiles);
  });

  // Prompt footer: Enter envía (Shift+Enter = salto de línea)
  textarea?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (Pipeline.active) { Pipeline.abort(); return; }
      Orchestrator.run(textarea.value);
    }
  });

  document.getElementById('btn-execute')
    ?.addEventListener('click', () => {
      if (Pipeline.active) { Pipeline.abort(); return; }
      Orchestrator.run(textarea?.value ?? '');
    });

  // Bind de clic en LEDs para rotación manual por cuadrante
  [1, 2, 3, 4].forEach(qId => LED.bindClick(qId));

  // Inicializar LEDs al estado visual correcto
  LED.set(1, 'idle');   // Q1: siempre activo, pulsando
  LED.set(2, 'done');   // Q2: activo y en espera
  LED.set(3, 'idle');   // Q3: activo, pulsando (estado amarillo → idle-green)
  LED.set(4, 'off');    // Q4: inactivo por defecto

  // Q4 checkbox: actualiza LED e mensaje de inactividad
  const cb4 = document.getElementById('active-4');
  cb4?.addEventListener('change', e => {
    const idleMsg = document.getElementById('q4-idle-msg');
    if (e.target.checked) {
      idleMsg?.remove();
      LED.set(4, 'done');
    } else {
      const output4 = document.getElementById('output-4');
      if (output4 && !document.getElementById('q4-idle-msg')) {
        output4.innerHTML = '';
        const msg = document.createElement('div');
        msg.id = 'q4-idle-msg';
        msg.className = 'h-full text-gray-500 flex items-center justify-center italic text-xs';
        msg.textContent = 'Desmarcado – Esta IA no recibirá la consulta para ahorrar tokens.';
        output4.appendChild(msg);
      }
      LED.set(4, 'off');
    }
  });

  // ── BLOQUE: Pestañas + Descarga del Cuadrante 4 ────────────────
  document.getElementById('q4-tab-code')
    ?.addEventListener('click', () => Q4Preview.switchTab('code'));
  document.getElementById('q4-tab-preview')
    ?.addEventListener('click', () => Q4Preview.switchTab('preview'));
  document.getElementById('q4-btn-png')
    ?.addEventListener('click', () => downloadQ4Render('png'));
  document.getElementById('q4-btn-jpg')
    ?.addEventListener('click', () => downloadQ4Render('jpg'));

  // ── BLOQUE 3: Task Router ─────────────────────────────────────
  // Escucha el selector global de tareas y reconfigura los cuadrantes
  document.getElementById('task-select')
    ?.addEventListener('change', e => {
      // value="" (opción inicial) → restablecer estado por defecto
      // value="auto" → el Orchestrator intercepta antes del pipeline
      if (e.target.value !== 'auto') {
        TaskRouter.apply(e.target.value || 'default');
      }
    });

  // Aplicar estado por defecto al cargar (títulos + selects iniciales)
  TaskRouter.apply('default');

  // ── Buscador predictivo de tareas ────────────────────────────
  const taskSearch = document.getElementById('task-search');
  const taskSelect = document.getElementById('task-select');
  if (taskSearch && taskSelect) {
    taskSearch.addEventListener('input', () => {
      const q = taskSearch.value.trim().toLowerCase();
      const options = taskSelect.querySelectorAll('option');
      const groups  = taskSelect.querySelectorAll('optgroup');

      if (!q) {
        // Sin filtro: mostrar todo
        options.forEach(o => { o.hidden = false; });
        groups.forEach(g  => { g.hidden = false; });
        return;
      }

      // Filtrar opciones (mantener siempre visibles "auto" y la opción vacía)
      options.forEach(o => {
        if (!o.value || o.value === 'auto') { o.hidden = false; return; }
        o.hidden = !o.textContent.toLowerCase().includes(q);
      });

      // Ocultar optgroup si todos sus options están ocultos
      groups.forEach(g => {
        const visible = Array.from(g.querySelectorAll('option')).some(o => !o.hidden);
        g.hidden = !visible;
      });
    });
  }

  // ── BLOQUE 5: Memoria ─────────────────────────────────────────
  // Inyecta el system prompt base en el historial de cada cuadrante.
  // Debe llamarse DESPUÉS de que QuadrantState ya esté definido y al
  // final del arranque para no ser sobreescrito por otros init.
  Memory.init();
});
