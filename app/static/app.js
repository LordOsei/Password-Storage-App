const AUTO_HIDE_MS = 30000;
const CLIPBOARD_CLEAR_MS = 30000;
const GENERATED_LENGTH = 20;
const GENERATOR_CHARS =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?";

const hideTimers = new WeakMap();

async function fetchPassword(id) {
  const res = await fetch(`/secrets/${id}/reveal`, { cache: "no-store" });
  if (!res.ok) throw new Error(`reveal failed: ${res.status}`);
  return (await res.json()).password;
}

function hidePassword(row) {
  const value = row.querySelector(".pw-value");
  value.hidden = true;
  value.textContent = "";
  row.querySelector(".pw-mask").hidden = false;
  row.querySelector(".reveal-btn").textContent = "Reveal";
  clearTimeout(hideTimers.get(row));
}

async function onReveal(btn) {
  const row = btn.closest("tr");
  const value = row.querySelector(".pw-value");
  if (!value.hidden) {
    hidePassword(row);
    return;
  }
  try {
    value.textContent = await fetchPassword(btn.dataset.id);
  } catch {
    alert("Could not reveal password.");
    return;
  }
  value.hidden = false;
  row.querySelector(".pw-mask").hidden = true;
  btn.textContent = "Hide";
  hideTimers.set(row, setTimeout(() => hidePassword(row), AUTO_HIDE_MS));
}

async function onCopy(btn) {
  const row = btn.closest("tr");
  const value = row.querySelector(".pw-value");
  let password;
  try {
    password = !value.hidden && value.textContent ? value.textContent : await fetchPassword(btn.dataset.id);
    await navigator.clipboard.writeText(password);
  } catch {
    alert("Could not copy password.");
    return;
  }
  btn.textContent = "Copied!";
  setTimeout(() => (btn.textContent = "Copy"), 1500);
  setTimeout(async () => {
    // Only clear if the clipboard still holds this password; if we can't read it, clear to be safe.
    try {
      if ((await navigator.clipboard.readText()) !== password) return;
    } catch {}
    try {
      await navigator.clipboard.writeText("");
    } catch {}
  }, CLIPBOARD_CLEAR_MS);
}

function generatePassword() {
  // Rejection sampling avoids modulo bias.
  const limit = 256 - (256 % GENERATOR_CHARS.length);
  const out = [];
  while (out.length < GENERATED_LENGTH) {
    for (const byte of crypto.getRandomValues(new Uint8Array(GENERATED_LENGTH * 2))) {
      if (byte < limit && out.length < GENERATED_LENGTH) out.push(GENERATOR_CHARS[byte % GENERATOR_CHARS.length]);
    }
  }
  return out.join("");
}

function setPasswordVisible(field, visible) {
  field.querySelector("input").type = visible ? "text" : "password";
  field.querySelector(".toggle-pw-btn").textContent = visible ? "Hide" : "Show";
}

document.addEventListener("click", (e) => {
  const t = e.target;
  if (t.matches(".reveal-btn")) onReveal(t);
  if (t.matches(".copy-btn")) onCopy(t);

  if (t.matches(".toggle-pw-btn")) {
    const field = t.closest(".pw-field");
    setPasswordVisible(field, field.querySelector("input").type === "password");
  }

  if (t.matches(".generate-btn")) {
    const field = t.closest(".pw-field");
    field.querySelector("input").value = generatePassword();
    setPasswordVisible(field, true);
  }
});

document.addEventListener("submit", (e) => {
  const message = e.target.dataset.confirm;
  if (message && !confirm(message)) e.preventDefault();
});

const search = document.getElementById("search");
if (search) {
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    let visible = 0;
    for (const row of document.querySelectorAll("tbody tr")) {
      const text = [0, 1, 3].map((i) => row.cells[i].textContent).join(" ").toLowerCase(); // site, username, notes
      row.hidden = q !== "" && !text.includes(q);
      if (!row.hidden) visible++;
    }
    document.getElementById("no-matches").hidden = visible > 0;
  });
}
