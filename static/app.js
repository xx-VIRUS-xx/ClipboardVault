const state = {
  items: [],
  activeKind: "",
  revealItem: null,
  revealTimer: null,
};

const $ = (id) => document.getElementById(id);

const els = {
  passphrase: $("passphrase"),
  content: $("content"),
  title: $("title"),
  tags: $("tags"),
  favorite: $("favorite"),
  pipeline: $("pipeline"),
  notice: $("notice"),
  items: $("items"),
  search: $("search"),
  filters: $("filters"),
  vaultState: $("vaultState"),
  revealDialog: $("revealDialog"),
  revealTitle: $("revealTitle"),
  revealKind: $("revealKind"),
  revealedContent: $("revealedContent"),
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function setNotice(message, error = false) {
  els.notice.textContent = message;
  els.notice.className = error ? "notice error" : "notice";
}

function tagsFromInput() {
  return els.tags.value
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);
}

function formatDate(epoch) {
  if (!epoch) return "never used";
  return new Date(epoch * 1000).toLocaleString();
}

function renderPipeline(info) {
  if (!info) {
    els.pipeline.innerHTML = "<span>Waiting for content</span>";
    return;
  }
  const sensitivityClass = info.sensitivity === "high" ? "danger" : "warn";
  const chips = [
    `<span>Classified: ${info.kind}</span>`,
    `<span class="${sensitivityClass}">Sensitivity: ${info.sensitivity}</span>`,
    `<span>Preview: ${escapeHtml(info.masked_preview || "empty")}</span>`,
    ...info.tags.map((tag) => `<span>${escapeHtml(tag)}</span>`),
  ];
  els.pipeline.innerHTML = chips.join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function classifyCurrent() {
  const content = els.content.value.trim();
  if (!content) {
    renderPipeline(null);
    return;
  }
  try {
    const info = await api("/api/classify", {
      method: "POST",
      body: JSON.stringify({ content }),
    });
    renderPipeline(info);
    if (!els.title.value.trim()) els.title.value = info.summary || info.kind;
    if (!els.tags.value.trim() && info.tags.length) els.tags.value = info.tags.join(", ");
  } catch (error) {
    setNotice(error.message, true);
  }
}

async function loadStatus() {
  const status = await api("/api/status");
  els.vaultState.textContent = status.vault_exists ? `${status.count} saved` : "New vault";
}

async function loadItems() {
  const params = new URLSearchParams();
  if (els.search.value.trim()) params.set("q", els.search.value.trim());
  if (state.activeKind) params.set("kind", state.activeKind);
  state.items = await api(`/api/items?${params.toString()}`);
  renderFilters();
  renderItems();
  await loadStatus();
}

function renderFilters() {
  const kinds = Array.from(new Set(state.items.map((item) => item.kind))).sort();
  const all = [`<button type="button" data-kind="" class="${state.activeKind === "" ? "active" : ""}">All</button>`];
  els.filters.innerHTML = all
    .concat(kinds.map((kind) => `<button type="button" data-kind="${escapeHtml(kind)}">${escapeHtml(kind)}</button>`))
    .join("");
  els.filters.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeKind = button.dataset.kind;
      loadItems();
    });
  });
}

function renderItems() {
  if (!state.items.length) {
    els.items.innerHTML = '<p class="notice">No saved items match this view.</p>';
    return;
  }

  els.items.innerHTML = state.items
    .map((item) => {
      const tags = item.tags.map((tag) => `<span class="chip">${escapeHtml(tag)}</span>`).join("");
      const danger = item.sensitivity === "high" ? " danger" : "";
      return `
        <article class="item">
          <div class="item-top">
            <div class="item-title">${item.favorite ? "* " : ""}${escapeHtml(item.title)}</div>
            <span class="chip${danger}">${escapeHtml(item.kind)}</span>
          </div>
          <p class="preview">${escapeHtml(item.masked_preview || item.summary)}</p>
          <div class="meta">
            <span>Updated ${formatDate(item.updated_at)}</span>
            <span>Last used ${formatDate(item.last_used_at)}</span>
          </div>
          <div class="meta">${tags}</div>
          <div class="item-actions">
            <button type="button" data-action="reveal" data-id="${item.id}">Reveal</button>
            <button type="button" data-action="favorite" data-id="${item.id}">${item.favorite ? "Unfavorite" : "Favorite"}</button>
            <button type="button" data-action="delete" data-id="${item.id}">Delete</button>
          </div>
        </article>
      `;
    })
    .join("");

  els.items.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => handleItemAction(button.dataset.action, Number(button.dataset.id)));
  });
}

async function handleItemAction(action, id) {
  const item = state.items.find((entry) => entry.id === id);
  if (!item) return;
  try {
    if (action === "reveal") {
      await revealItem(item);
    } else if (action === "favorite") {
      await api(`/api/items/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ favorite: !item.favorite }),
      });
      await loadItems();
    } else if (action === "delete") {
      await api(`/api/items/${id}`, { method: "DELETE" });
      await loadItems();
    }
  } catch (error) {
    setNotice(error.message, true);
  }
}

async function revealItem(item) {
  if (!els.passphrase.value) {
    setNotice("Enter your vault passphrase first.", true);
    return;
  }
  const revealed = await api(`/api/items/${item.id}/reveal`, {
    method: "POST",
    body: JSON.stringify({ passphrase: els.passphrase.value }),
  });
  state.revealItem = revealed;
  els.revealTitle.textContent = revealed.title;
  els.revealKind.textContent = `${revealed.kind} / ${revealed.sensitivity}`;
  els.revealedContent.textContent = revealed.content;
  els.revealDialog.showModal();
  clearTimeout(state.revealTimer);
  state.revealTimer = setTimeout(closeReveal, 30000);
}

function closeReveal() {
  els.revealedContent.textContent = "";
  state.revealItem = null;
  if (els.revealDialog.open) els.revealDialog.close();
}

async function saveItem() {
  const content = els.content.value.trim();
  if (!content) {
    setNotice("Paste or read clipboard content first.", true);
    return;
  }
  if (!els.passphrase.value) {
    setNotice("Enter a vault passphrase. First save creates the vault.", true);
    return;
  }
  try {
    await api("/api/items", {
      method: "POST",
      body: JSON.stringify({
        content,
        passphrase: els.passphrase.value,
        title: els.title.value,
        tags: tagsFromInput(),
        favorite: els.favorite.checked,
      }),
    });
    els.content.value = "";
    els.title.value = "";
    els.tags.value = "";
    els.favorite.checked = false;
    renderPipeline(null);
    setNotice("Saved encrypted item.");
    await loadItems();
  } catch (error) {
    setNotice(error.message, true);
  }
}

async function readClipboard() {
  try {
    els.content.value = await navigator.clipboard.readText();
    setNotice("Clipboard loaded. Review it before saving.");
    await classifyCurrent();
  } catch (error) {
    setNotice("Browser blocked clipboard read. Paste into the text area instead.", true);
  }
}

$("readClipboard").addEventListener("click", readClipboard);
$("pasteSample").addEventListener("click", classifyCurrent);
$("saveItem").addEventListener("click", saveItem);
$("closeDialog").addEventListener("click", closeReveal);
$("copyRevealed").addEventListener("click", async () => {
  if (!state.revealItem) return;
  await navigator.clipboard.writeText(state.revealItem.content);
  closeReveal();
  setNotice("Copied revealed content. Dialog cleared.");
});

els.content.addEventListener("input", () => {
  clearTimeout(state.inputTimer);
  state.inputTimer = setTimeout(classifyCurrent, 250);
});
els.search.addEventListener("input", () => {
  clearTimeout(state.searchTimer);
  state.searchTimer = setTimeout(loadItems, 180);
});

loadStatus().then(loadItems).catch((error) => setNotice(error.message, true));
