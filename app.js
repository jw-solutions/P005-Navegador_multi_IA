// app.js — IA ORCHESTRATOR - JW Solutions
// BLOQUE 1: Sistema de Seguridad y Gestión de API Keys
// BLOQUE 2: Orquestador OpenRouter y Streamers en Paralelo

// ============================================================
// ESTADO GLOBAL (nunca serializado a disco en texto plano)
// ============================================================
const AppState = {
  apiKeys: [],      // Keys descifradas, solo en memoria de sesión
  isUnlocked: false,
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
        await delay(400);
        LED.set(qId, 'loading');
        continue; // no decrementa attemptsLeft — el problema es el modelo, no la llave
      }
      LED.set(qId, 'error');
      Output.renderMsg(qId, `❌ Modelo no encontrado (404) y sin más alternativas para Q${qId}.`, 'error');
      return null;
    }

    // ── Otro error HTTP no recuperable ─────────────────────────
    if (!response.ok) {
      LED.set(qId, 'error');
      Output.renderMsg(qId, `❌ HTTP ${response.status}: ${response.statusText}`, 'error');
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
      }
      return null;
    } finally {
      // reader.cancel() libera el lock Y envía la señal de cierre al ReadableStream,
      // cerrando la conexión TCP/HTTP subyacente sin esperar al garbage collector.
      // Es equivalente a releaseLock() + body.cancel() en una sola llamada async.
      reader.cancel().catch(() => {});
    }

    LED.set(qId, 'done');
    return fullText; // ✅ Éxito — devuelve el texto completo al orquestador
  }

  // Pool agotado: ninguna llave funcionó
  LED.set(qId, 'error');
  Output.renderMsg(
    qId,
    `❌ Pool agotado: las ${total} llaves fallaron con 429/402. Añade llaves nuevas en ⚙️ Ajustes.`,
    'error'
  );
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
      Pipeline.active = false;
      setPipelineBtn(false);
      return;
    }

    // ═══════════════════════════════════════════════════════════
    // FASE 2 — Q2, Q3, Q4 en paralelo con el prompt optimizado
    //
    // Para cada cuadrante:
    //   1. Se añade el prompt optimizado al historial → conversación continua
    //   2. Se llama con el historial completo (incluye contexto previo)
    //   3. Se guarda la respuesta y, si aplica, se compacta en fondo
    // ═══════════════════════════════════════════════════════════
    const finalPrompt = optimizedText.trim() || prompt;

    // Ajustar system prompt de Q4 según la tarea activa.
    // Si la tarea tiene q4SystemPrompt (ej. visual/SVG), se aplica ahora;
    // si no, se restaura SYSTEM_ANTI_FLUFF para evitar que persista el de una tarea anterior.
    if (downstream.includes(4)) {
      const q4Sys = TASK_MATRIX[AppState.currentTask]?.q4SystemPrompt ?? SYSTEM_ANTI_FLUFF;
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

    Pipeline.active = false;
    setPipelineBtn(false);

    // Mostrar panel de síntesis con comparativa de cuadrantes activos
    Synthesis.render(downstream, finalPrompt);
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
48. Planificación de Agenda y Bloques de Tiempo`;

    const sysPrompt = `Eres un clasificador de tareas. Analiza el prompt del usuario y responde ÚNICAMENTE con el número (1-48) de la tarea más apropiada de esta lista:\n${TASK_LIST}\nResponde SOLO con el número, sin explicación, sin puntos, sin texto adicional.`;

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
        if (num >= 1 && num <= 48) return String(num);
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

  // ── Estado por defecto (sin tarea seleccionada) ──────────────
  'default': {
    q1Title: '⚡ Filtro Optimizador',
    q2: { title: '🤖 Motor Avanzado', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Alternativa Gratis', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder Free' },
    ]},
    q4: { title: '🚀 Contrapeso de Velocidad', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1 70B' },
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash Free' },
    ]},
    star: 2,
  },

  // ─────────────────────────────────────────────────────────────
  // GRUPO 1: DESARROLLO Y AUTOMATIZACIÓN (PYTHON, APIs, SQL, GIT)
  // ─────────────────────────────────────────────────────────────
  '1': { // Escritura de Scripts Python
    q1Title: '⚡ Filtro de Sintaxis',
    q2: { title: '🤖 Lógica Compleja Python', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Scripting Eficiente', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder (Top)' },
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Prototipado Rápido', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash Free' },
    ]},
    star: 3,
  },
  '2': { // Depuración de Código (Debugging)
    q1Title: '⚡ Analizador de Errores',
    q2: { title: '🤖 Debugger Avanzado', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Revisión de Sintaxis', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Traza Prontísima', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1 70B' },
    ]},
    star: 2,
  },
  '3': { // Refactorización
    q1Title: '⚡ Optimizador de Contexto',
    q2: { title: '🤖 Arquitectura Limpia', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Refactorizador Gratis', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Formateador Express', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '4': { // Integración APIs (WhatsApp/Sheets)
    q1Title: '⚡ Parser de Endpoints',
    q2: { title: '🤖 Integrador de Webhooks', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Lógica de Conexión JSON', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Mapeo de Variables', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '5': { // Frontend HTML/CSS/JS
    q1Title: '⚡ Estructurador DOM',
    q2: { title: '🤖 UI/UX Engine', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 CSS/JS Estético', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Render HTML Base', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '6': { // Consultas SQL Complejas
    q1Title: '⚡ Validador de Esquemas',
    q2: { title: '🤖 Optimizador de Querys SQL', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Generador de Joins/DML', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Consulta Simple', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 3,
  },
  '7': { // Expresiones Regulares
    q1Title: '⚡ Filtro de Patrones',
    q2: { title: '🤖 Regex Engine Pro', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Validador de Strings', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Match Veloz', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '8': { // Web Scraping
    q1Title: '⚡ Filtro de Selectors HTML',
    q2: { title: '🤖 Scraper Avanzado/BeautifulSoup', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Extractor de Nodos', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Fetch Simples', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '9': { // Configuración Entornos (Docker/Git)
    q1Title: '⚡ Filtro de Dependencias',
    q2: { title: '🤖 DevOps & SysAdmin', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Configuración .yaml/.json', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Comandos Terminal', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '10': { // Documentación
    q1Title: '⚡ Limpiador de Código',
    q2: { title: '🤖 Redactor Técnico Readme', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Documentador Markdown', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Comentarios Inline', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 3,
  },

  // ──────────────────────────────────────────────────────────────
  // GRUPO 2: ANÁLISIS DE DATOS Y BI (POWER BI, DAX, STOCHASTIC)
  // ──────────────────────────────────────────────────────────────
  '11': { // Modelado de Datos Relacionales
    q1Title: '⚡ Filtro Métricas',
    q2: { title: '🤖 Arquitectura Relacional BI', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Diseño Estrella/Copo Nieve', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Mapeo de Llaves', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '12': { // Fórmulas Avanzadas DAX (Power BI)
    q1Title: '⚡ Filtro de Contexto de Filtro',
    q2: { title: '🤖 DAX Architect Pro', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Motor de Cálculo Time Intelligence', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Expresiones Simples', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash' },
    ]},
    star: 2,
  },
  '13': { // Power Query
    q1Title: '⚡ Filtro de Pasos M',
    q2: { title: '🤖 Power Query Optimizer', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Transformación M Language', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Extractor de Tipos', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 3,
  },
  '14': { // Pandas Data Cleansing
    q1Title: '⚡ Reductor de Dimensiones',
    q2: { title: '🤖 Data Wrangler Pandas', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Limpieza de Dataframes', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Slices Simples', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '15': { // Modelos Estocásticos
    q1Title: '⚡ Extractor de Variables',
    q2: { title: '🤖 Stochastic & Math Engine', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Modelado Estadístico', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Operaciones Matrices', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '16': { // Auditoría Financiera
    q1Title: '⚡ Buscador de Descalces',
    q2: { title: '🤖 Auditor de Datos Financieros', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Conciliador de Registros', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Cruce Indexado', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '17': { // Generación Informes/Dashboards
    q1Title: '⚡ Sintetizador KPI',
    q2: { title: '🤖 Consultor de Dashboards UX', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Diseño de Reportes Visuales', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Mockup Estructural SVG', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    q4SystemPrompt: `Genera exclusivamente el mockup o diagrama SVG solicitado. REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque Markdown (\`\`\`svg ... \`\`\` o \`\`\`html ... \`\`\`). Sin texto introductorio, sin explicaciones, sin conclusiones — solo el bloque de código autónomo y directamente renderizable.`,
    star: 2,
  },
  '18': { // Procesamiento Grandes Volúmenes
    q1Title: '⚡ Optimizador Chunking',
    q2: { title: '🤖 Big Data Parquet/CSV Engine', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Pipeline Batch Local', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Stream de Carga', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '19': { // Extracción PDFs Inestructurados
    q1Title: '⚡ Filtro OCR/Layout',
    q2: { title: '🤖 Estructurador PDF Vision', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Regular Expressions Extractor', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Texto Plano Dump', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '20': { // Modelos de Predicción Deportiva / Simulación Monte Carlo
    q1Title: '⚡ Compresor de Datos Históricos & Pesos Anthropocéntricos',
    q2: { title: '🤖 Engine de Probabilidad Predictiva', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Simulador Estocástico Poisson/MonteCarlo', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Generador de Muestras Iterativas', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },

  // ─────────────────────────────────────────────────────────────────
  // GRUPO 3: AUTOMATIZACIÓN DE PYMES Y GESTIÓN DE RECURSOS (ADMIN)
  // ─────────────────────────────────────────────────────────────────
  '21': { // Google Sheets/Forms
    q1Title: '⚡ Optimizador de Macros',
    q2: { title: '🤖 Apps Script Architect', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Automatizador Hojas de Cálculo', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Fórmulas Avanzadas Sheets', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '22': { // Redacción Informes Administrativos
    q1Title: '⚡ Filtro de Sintaxis Corporativa',
    q2: { title: '🤖 Consultor Financiero/Administración', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Redactor Ejecutivo Comercial', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Resumen Ejecutivo', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 3,
  },
  '23': { // Análisis Costos/Recursos Materiales
    q1Title: '⚡ Optimizador de Costos',
    q2: { title: '🤖 Analista Financiero de Insumos', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Matriz de Asignación de Recursos', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Cálculos Básicos Margen', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '24': { // Conciliación Bancaria
    q1Title: '⚡ Extractor de Estados de Cuenta',
    q2: { title: '🤖 Algoritmo de Conciliación Bancaria', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Matcher de Asientos Contables', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Verificador de Totales', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '25': { // Auditoría Fondos de Salud
    q1Title: '⚡ Filtro de Auditoría de Fondos',
    q2: { title: '🤖 Inspector de Saldos de Salud', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Reconciliador de Cuentas Médicas', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Reporte de Desviaciones', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '26': { // Cotizaciones/Pólizas
    q1Title: '⚡ Filtro Pólizas',
    q2: { title: '🤖 Liquidador/Cotizador Automatizado Seguros', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Calculador de Primas Life/Funeral', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Plantilla HTML de Cotización', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '27': { // Planificación Proyectos
    q1Title: '⚡ Extractor Hitos',
    q2: { title: '🤖 Project Manager Estratégico', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Estructurador WBS / Hitos Gantt', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Listado de Tareas Checklist', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 3,
  },
  '28': { // Manuales de Procedimientos
    q1Title: '⚡ Reductor de Ambigüedad',
    q2: { title: '🤖 Ingeniero de Procesos / ISO9001', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Redactor de Manuales de Operación', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Flujograma de Pasos (Texto)', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '29': { // Evaluación Proveedores
    q1Title: '⚡ Filtro KPIs Proveedor',
    q2: { title: '🤖 Evaluador de Logística y Suministro', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Scorecard de Suministros Pyme', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Tabla de Precios Comparativa', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '30': { // Movilidad Eléctrica
    q1Title: '⚡ Filtro Autonomías',
    q2: { title: '🤖 Analista ROI de Electromovilidad', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Comparador Técnico de Motos/Bicis Eléctricas', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Ficha Comparativa', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },

  // ─────────────────────────────────────────────────────────────────────
  // GRUPO 4: CONTENIDO, GAMING Y REDACCIÓN ESTRATÉGICA (THE MANKS CHANNEL)
  // ─────────────────────────────────────────────────────────────────────
  '31': { // Guiones para Contenido Corto (TikTok/Reels)
    q1Title: '⚡ Filtro de Ganchos de Retención (Hooks)',
    q2: { title: '🤖 Editor Creativo Audiovisual', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Copywriter de Impacto Viral (Gaming)', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat (Top)' },
    ]},
    q4: { title: '🚀 Estructura de Guión Rápido', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1 70B' },
    ]},
    star: 3,
  },
  '32': { // Estrategia YouTube Gaming
    q1Title: '⚡ Optimizador de CTR/Títulos',
    q2: { title: '🤖 YouTube Growth Strategist', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Planificador de Contenido Gaming', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Ideas de Miniaturas/Títulos', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '33': { // SEO & Redes Sociales
    q1Title: '⚡ Reductor de Hashtags Bloat',
    q2: { title: '🤖 SEO Expert / Social Media Specialist', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Generador de Copys de Enganche', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Tags Relacionados', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 3,
  },
  '34': { // UEFN / Fortnite Creative
    q1Title: '⚡ Filtro de Eventos de Dispositivos',
    q2: { title: '🤖 Arquitecto de Mecánicas UEFN (Verse/Logic)', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Programador de Dispositivos e Hilos Creativos', models: [
      { id: 'qwen/qwen-2.5-coder-72b:free',       label: 'Qwen 2.5 Coder' },
    ]},
    q4: { title: '🚀 Mapeo de Canales Básicos', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash' },
    ]},
    star: 2,
  },
  '35': { // Análisis Táctico Shooters
    q1Title: '⚡ Filtro de Meta-Juego',
    q2: { title: '🤖 Analista Táctico FPS (Delta Force/CoD)', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Estratega de Loadouts y Rotaciones', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Guía Rápida de Spawn', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '36': { // Traducción Técnica
    q1Title: '⚡ Preservador de Glosario Técnico',
    q2: { title: '🤖 Traductor de Contexto Avanzado', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Localizador de Idioma Fiel', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Traducción Literal Rápida', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '37': { // Resumen Ultra-Denso
    q1Title: '⚡ Extractor de Entidades Clave',
    q2: { title: '🤖 Sintetizador Conceptual de Ensayos/Papers', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Compresor Semántico Informativo', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Bulletpoints Ejecutivos', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 2,
  },
  '38': { // Brainstorming de Marcas
    q1Title: '⚡ Filtro de Clichés de Marca',
    q2: { title: '🤖 Consultor de Branding & Identidad Digital', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Generador de Nombres / Conceptos de Marca', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Lluvia de Palabras Clave', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 3,
  },
  '39': { // Correos Corporativos
    q1Title: '⚡ Filtro de Tono de Negociación',
    q2: { title: '🤖 Redactor de Correos de Alianzas Corporativas', models: [
      { id: 'openai/gpt-4o',                      label: 'GPT-4o' },
    ]},
    q3: { title: '💡 Copys para Patrocinios y Marcas', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Respuesta Rápida de Cortesía', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '40': { // Prompt Engineering
    q1Title: '⚡ Optimizador de System Prompts',
    q2: { title: '🤖 Meta-Prompt Engineer Avanzado', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Estructurador de Variables de Prompt', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Prompt de una sola línea', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '41': { // Corrección de Estilo
    q1Title: '⚡ Corrector de Ortografía',
    q2: { title: '🤖 Editor de Estilo y Narrativa', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Revisor de Coherencia Gramatical', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Filtro de Tipeos Rápidos', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5' },
    ]},
    star: 3,
  },
  '42': { // Simulación de Entrevistas
    q1Title: '⚡ Filtro de Sesgos Técnicos',
    q2: { title: '🤖 Entrevistador Técnico Senior / Evaluador', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Simulador Conceptual de Arquitectura', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Q&A Rápido de Conceptos', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },

  // ─────────────────────────────────────────────────────────────
  // TAREAS NUEVAS — MULTIMEDIA, COTIDIANAS Y CREATIVIDAD
  // ─────────────────────────────────────────────────────────────
  '43': { // Prompt Engineering para Generadores de Imagen / Visuales SVG
    q1Title: '⚡ Optimizador de Descripción Visual',
    q2: { title: '🤖 Prompt Artist Midjourney / SDXL Avanzado', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Generador ComfyUI / Stable Diffusion', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Infografía SVG Rápida', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash' },
    ]},
    q4SystemPrompt: `Genera exclusivamente el elemento SVG o infografía visual solicitada. REGLA OBLIGATORIA: encapsula TODO el código dentro de un único bloque Markdown (\`\`\`svg ... \`\`\` o \`\`\`html ... \`\`\`). Sin texto introductorio, sin explicaciones, sin conclusiones — solo el bloque de código autónomo y directamente renderizable.`,
    star: 2,
  },
  '44': { // Automatización de Video por Código
    q1Title: '⚡ Filtro de Comandos Multimedia',
    q2: { title: '🤖 Experto FFmpeg / Video Processing', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Scripting MoviePy / OpenCV', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Comandos CLI Rápidos de Video', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '45': { // Guiones y Storyboarding — Contenido Corto
    q1Title: '⚡ Filtro de Gancho Narrativo',
    q2: { title: '🤖 Guionista de Contenido Viral (TikTok/Reels)', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Storyboard Visual por Escenas', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Hook y CTA Ultra-Rápido', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash' },
    ]},
    star: 2,
  },
  '46': { // Redactor de Mensajes y Correos Cotidianos
    q1Title: '⚡ Filtro de Tono y Claridad',
    q2: { title: '🤖 Redactor Profesional de Mensajes', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Pulidor de Estilo Cotidiano', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Versión Corta y Directa', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash' },
    ]},
    star: 2,
  },
  '47': { // Compresor de Textos y Extractor de Ideas
    q1Title: '⚡ Pre-filtro de Densidad',
    q2: { title: '🤖 Compresión Semántica Profunda', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Extractor de Ideas Fuerza', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 TL;DR Ultra-Compacto', models: [
      { id: 'meta-llama/llama-3.1-70b-instruct',  label: 'Llama 3.1' },
    ]},
    star: 2,
  },
  '48': { // Planificador de Agenda y Bloques de Tiempo
    q1Title: '⚡ Filtro de Prioridades del Día',
    q2: { title: '🤖 Planificador de Bloques Pomodoro', models: [
      { id: 'anthropic/claude-3.5-sonnet',        label: 'Claude 3.5 Sonnet' },
    ]},
    q3: { title: '💡 Gestor de Energía y Tiempos', models: [
      { id: 'deepseek/deepseek-chat',              label: 'DeepSeek Chat' },
    ]},
    q4: { title: '🚀 Agenda Rápida del Día', models: [
      { id: 'google/gemini-2.5-flash:free',        label: 'Gemini 2.5 Flash' },
    ]},
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

  // 6. Ocultar panel de síntesis
  Synthesis.hide();

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
