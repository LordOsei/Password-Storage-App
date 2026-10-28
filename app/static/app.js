document.addEventListener("click", async (e) => {
  if (e.target.matches(".reveal-btn")) {
    const id = e.target.dataset.id;
    const row = e.target.closest("tr");
    const mask = row.querySelector(".pw-mask");
    const value = row.querySelector(".pw-value");
    const copyBtn = row.querySelector(".copy-btn");

    if (!value.hidden) {
      value.hidden = true;
      mask.hidden = false;
      copyBtn.hidden = true;
      e.target.textContent = "Reveal";
      return;
    }

    const res = await fetch(`/secrets/${id}/reveal`);
    if (!res.ok) {
      alert("Could not reveal password.");
      return;
    }
    const data = await res.json();
    value.textContent = data.password;
    value.hidden = false;
    mask.hidden = true;
    copyBtn.hidden = false;
    e.target.textContent = "Hide";
  }

  if (e.target.matches(".copy-btn")) {
    const row = e.target.closest("tr");
    const value = row.querySelector(".pw-value");
    if (value && value.textContent) {
      await navigator.clipboard.writeText(value.textContent);
      e.target.textContent = "Copied!";
      setTimeout(() => (e.target.textContent = "Copy"), 1500);
    }
  }
});
