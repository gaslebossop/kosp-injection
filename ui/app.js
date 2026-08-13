const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const els = {
  cardIdle: document.getElementById("card-idle"),
  cardProgress: document.getElementById("card-progress"),
  cardResult: document.getElementById("card-result"),
  btnStart: document.getElementById("btn-start"),
  btnAgain: document.getElementById("btn-again"),
  statusText: document.getElementById("status-text"),
  spinner: document.getElementById("spinner"),
  progressFill: document.getElementById("progress-fill"),
  progressPct: document.getElementById("progress-pct"),
  resultIcon: document.getElementById("result-icon"),
  resultText: document.getElementById("result-text"),

  btnCancelProgress: document.getElementById("btn-cancel-progress"),

  overlayPrereqs: document.getElementById("overlay-prereqs"),
  prereqsMessage: document.getElementById("prereqs-message"),
  prereqsDetail: document.getElementById("prereqs-detail"),
  btnPrereqsYes: document.getElementById("btn-prereqs-yes"),
  btnPrereqsNo: document.getElementById("btn-prereqs-no"),

  overlayDevice: document.getElementById("overlay-device"),
  deviceList: document.getElementById("device-list"),
  btnCancelDevice: document.getElementById("btn-cancel-device"),

  overlayAccount: document.getElementById("overlay-account"),
  accountList: document.getElementById("account-list"),
  btnAddAccount: document.getElementById("btn-add-account"),
  btnCancelAccount: document.getElementById("btn-cancel-account"),

  overlayPassword: document.getElementById("overlay-password"),
  modalSubId: document.getElementById("modal-sub-id"),
  inputAppleId: document.getElementById("input-apple-id"),
  inputPassword: document.getElementById("input-password"),
  btnSubmitPassword: document.getElementById("btn-submit-password"),
  btnCancelPassword: document.getElementById("btn-cancel-password"),

  overlay2fa: document.getElementById("overlay-2fa"),
  input2fa: document.getElementById("input-2fa"),
  btnSubmit2fa: document.getElementById("btn-submit-2fa"),
  btnResend2fa: document.getElementById("btn-resend-2fa"),
  btnCancel2fa: document.getElementById("btn-cancel-2fa"),

  overlayCerts: document.getElementById("overlay-certs"),
  certList: document.getElementById("cert-list"),
  btnSubmitCerts: document.getElementById("btn-submit-certs"),
  btnCancelCerts: document.getElementById("btn-cancel-certs"),
};

function hideAllOverlays() {
  for (const o of [els.overlayPrereqs, els.overlayDevice, els.overlayAccount, els.overlayPassword, els.overlay2fa, els.overlayCerts]) {
    o.classList.add("hidden");
  }
}

function cancelUpdate() {
  hideAllOverlays();
  invoke("submit_cancel");
}

function showCard(which) {
  for (const c of [els.cardIdle, els.cardProgress, els.cardResult]) {
    c.classList.add("hidden");
  }
  which.classList.remove("hidden");
}

function setProgress(pct) {
  const clamped = Math.max(0, Math.min(100, pct));
  els.progressFill.style.width = clamped + "%";
  els.progressPct.textContent = clamped.toFixed(1) + " %";
}

function startUpdate() {
  showCard(els.cardProgress);
  els.statusText.textContent = "Demarrage...";
  els.spinner.classList.remove("hidden");
  setProgress(0);
  invoke("start_update").catch((e) => showResult(false, String(e)));
}

function showResult(ok, message) {
  showCard(els.cardResult);
  els.resultIcon.className = "result-icon " + (ok ? "ok" : "err");
  els.resultIcon.textContent = ok ? "✓" : "✕";
  els.resultText.textContent = message;
}

els.btnStart.addEventListener("click", startUpdate);
els.btnAgain.addEventListener("click", startUpdate);
els.btnCancelProgress.addEventListener("click", cancelUpdate);
els.btnCancelDevice.addEventListener("click", cancelUpdate);
els.btnCancelAccount.addEventListener("click", cancelUpdate);
els.btnCancelPassword.addEventListener("click", cancelUpdate);
els.btnCancel2fa.addEventListener("click", cancelUpdate);
els.btnCancelCerts.addEventListener("click", cancelUpdate);

// --- Identifiants Apple ---
els.btnSubmitPassword.addEventListener("click", () => {
  const appleId = els.inputAppleId.value.trim();
  const pw = els.inputPassword.value;
  if (!appleId || !pw) return;
  els.overlayPassword.classList.add("hidden");
  invoke("submit_credentials", { appleId, password: pw });
  els.inputPassword.value = "";
});
els.inputPassword.addEventListener("keydown", (e) => {
  if (e.key === "Enter") els.btnSubmitPassword.click();
});

// --- 2FA ---
els.btnSubmit2fa.addEventListener("click", () => {
  const code = els.input2fa.value.trim();
  if (!code) return;
  els.overlay2fa.classList.add("hidden");
  invoke("submit_2fa", { code });
  els.input2fa.value = "";
});
els.input2fa.addEventListener("keydown", (e) => {
  if (e.key === "Enter") els.btnSubmit2fa.click();
});
els.btnResend2fa.addEventListener("click", () => {
  els.overlay2fa.classList.add("hidden");
  invoke("submit_2fa", { code: "__resend__" });
});

// --- Certificats ---
let selectedCerts = new Set();
els.btnSubmitCerts.addEventListener("click", () => {
  if (selectedCerts.size === 0) return;
  els.overlayCerts.classList.add("hidden");
  invoke("submit_cert_choice", { serials: Array.from(selectedCerts) });
});

// --- Composants Apple manquants ---
els.btnPrereqsYes.addEventListener("click", () => {
  els.overlayPrereqs.classList.add("hidden");
  invoke("submit_confirm", { ok: true });
});
els.btnPrereqsNo.addEventListener("click", () => {
  els.overlayPrereqs.classList.add("hidden");
  invoke("submit_confirm", { ok: false });
});
listen("need-prereqs", (e) => {
  els.prereqsMessage.textContent = e.payload.message;
  els.prereqsDetail.textContent = e.payload.detail;
  els.overlayPrereqs.classList.remove("hidden");
});

// --- Choix de compte Apple ---
els.btnAddAccount.addEventListener("click", () => {
  els.overlayAccount.classList.add("hidden");
  invoke("submit_account_choice", { appleId: null });
});
listen("need-account", (e) => {
  els.accountList.innerHTML = "";
  for (const id of e.payload) {
    const item = document.createElement("div");
    item.className = "cert-item";

    const text = document.createElement("div");
    text.className = "cert-item-text";
    const name = document.createElement("span");
    name.className = "cert-item-name";
    name.textContent = id;
    text.appendChild(name);
    item.appendChild(text);

    item.addEventListener("click", () => {
      els.overlayAccount.classList.add("hidden");
      invoke("submit_account_choice", { appleId: id });
    });
    els.accountList.appendChild(item);
  }
  els.overlayAccount.classList.remove("hidden");
});

// --- Choix d'appareil ---
listen("need-device", (e) => {
  els.deviceList.innerHTML = "";
  for (const dev of e.payload) {
    const item = document.createElement("div");
    item.className = "cert-item";

    const text = document.createElement("div");
    text.className = "cert-item-text";
    const name = document.createElement("span");
    name.className = "cert-item-name";
    name.textContent = dev.name;
    text.appendChild(name);
    item.appendChild(text);

    item.addEventListener("click", () => {
      els.overlayDevice.classList.add("hidden");
      invoke("submit_device", { udid: dev.udid });
    });
    els.deviceList.appendChild(item);
  }
  els.overlayDevice.classList.remove("hidden");
});

// --- Evenements emis par le backend Rust ---
listen("status", (e) => {
  els.statusText.textContent = e.payload;
});

listen("progress", (e) => {
  setProgress(e.payload * 100);
});

listen("need-password", (e) => {
  const knownId = e.payload.appleId;
  if (knownId) {
    els.inputAppleId.value = knownId;
    els.inputAppleId.readOnly = true;
    els.modalSubId.textContent = "Session existante pour " + knownId;
  } else {
    els.inputAppleId.value = "";
    els.inputAppleId.readOnly = false;
    els.modalSubId.textContent = "Identifiants du compte Apple gratuit utilise pour signer l'app.";
  }
  els.overlayPassword.classList.remove("hidden");
  (knownId ? els.inputPassword : els.inputAppleId).focus();
});

listen("need-2fa", () => {
  els.overlay2fa.classList.remove("hidden");
  els.input2fa.focus();
});

listen("need-certs", (e) => {
  selectedCerts = new Set();
  els.certList.innerHTML = "";
  for (const cert of e.payload) {
    const item = document.createElement("label");
    item.className = "cert-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    item.appendChild(checkbox);

    const text = document.createElement("div");
    text.className = "cert-item-text";
    const name = document.createElement("span");
    name.className = "cert-item-name";
    name.textContent = cert.name;
    const machine = document.createElement("span");
    machine.className = "cert-item-meta";
    machine.textContent = cert.machine;
    text.append(name, machine);
    item.appendChild(text);

    checkbox.addEventListener("change", () => {
      item.classList.toggle("selected", checkbox.checked);
      if (checkbox.checked) selectedCerts.add(cert.serial);
      else selectedCerts.delete(cert.serial);
    });
    els.certList.appendChild(item);
  }
  els.overlayCerts.classList.remove("hidden");
});

listen("done", (e) => {
  showResult(true, e.payload);
});

listen("failed", (e) => {
  showResult(false, e.payload);
});
