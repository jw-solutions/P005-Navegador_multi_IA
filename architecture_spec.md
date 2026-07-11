# Architectural Specification: Navegador IA - JW Solutions (SPA Multi-LLM)

## 1. Project Overview
Navegador IA - JW Solutions is a lightweight, client-side-only Single Page Application (SPA) designed to optimize multi-LLM workflows inside Microsoft Edge. It renders a 2x2 grid layout running isolated AI models concurrently via OpenRouter API. It emphasizes aggressive token mitigation, fallback key rotation, and contextual coherence across models.

## 2. Technical Stack
- **Frontend:** HTML5, Tailwind CSS (via CDN), Vanilla JavaScript (ES6+ async/await).
- **External API:** OpenRouter API (OpenAI-compatible completion endpoint).
- **Storage & Security:** Client-side LocalStorage and SessionStorage with local AES/WebCrypto API encryption.

## 3. Component Architecture & UI (Rainbow Grid)
The viewport is a locked 2x2 grid (`grid-cols-2 grid-rows-2 h-[calc(100vh-140px)] overflow-hidden`).
- **Quadrant 1 (Fixed - Blue Border/Tint):** Prompt Optimizer & Router. Intercepts raw user input, queries a free model (e.g., `gemini-2.5-flash:free`), and compresses instructions.
- **Quadrant 2 (Green Border/Tint):** Advanced/Paid Model (e.g., `claude-3.5-sonnet`).
- **Quadrant 3 (Purple Border/Tint):** High-Performance Free Model (e.g., `qwen-2.5-coder-72b:free`).
- **Quadrant 4 (Orange Border/Tint):** Fast/Alternative Model (e.g., `llama-3.1-70b`).

*Visuals:* Radii set to `rounded-2xl`. Backgrounds use highly desaturated tint factors (3% opacity light mode, 15% dark mode using `hsla`) to prevent visual fatigue. Each quadrant features an independent status LED indicator (Green/Yellow/Red) and an active checkbox selector.

## 4. Core Core Systems (The Intelligence Backend)

### A. Token Mitigation Engine (Anti-Fluff System)
- **Input Compactor:** Quadrant 1 processes raw prompts using a hardcoded system prompt instructing it to trim conversational bloat and output *only* raw technical objectives.
- **Output Optimizer:** Quadrants 2, 3, and 4 append a stealth system suffix to every outbound payload: *"Be direct. Omit greetings, introductions, and conclusions. Code blocks must only contain essential inline comments."*

### B. Fallback Key Rotation Pool
- **Input Validation:** UI enforces a mandatory minimum of 3 (Optimal: 5) OpenRouter API keys pasted in line-separated plain text.
- **Interception Logic:** Network fetches capture HTTP status codes `429` (Rate Limited) or `402` (Insufficient Funds). On trigger, the index increments, transparently retrying the exact payload with the next key in line.
- **Manual Override:** A manual "Panic Button" (`🔄 Switch Account`) forces an instant key rotation per quadrant.

### C. Sliding Window Semantic Memory Compactor
- **Trigger Condition:** Tracks absolute turn count. Every 10 iterations, it triggers background compression.
- **Compaction Routine:** Segregates the array of `messages`. Slices indices 0 to 7 (oldest), sends them to the free model via Quadrant 1 with a summary extraction prompt.
- **Injection:** Replaces indices 0-7 with a single system message object: `{"role": "system", "content": "[Semantic Context Compacted]: <Summary_Data>"}`. Indices 8 and 9 are preserved raw for micro-context.

### D. Task-to-Model Routing Matrix
Maps a master list of 42 specific tasks to prioritized configurations. When a user selects a task from the global dropdown navbar, JavaScript dynamically reorganizes the dropdown choices inside Quadrants 2, 3, and 4, bubbling the most optimal models for that specific category to the top of the list and disabling non-optimal options.