// Toute la logique d'affichage. Regle du fichier : rien ne s'affiche a
// l'ecran sans etre une phrase que le testeur peut suivre. Les objets
// d'erreur venus du backend (`{title, steps, detail, cancelled}`) sont la
// seule source des messages d'echec — pas de texte technique invente ici.

const tauri = window.__TAURI__;

/** Ecran de secours : une fenetre qui reste vide ou inerte n'apprend rien
 *  a personne. Construit sans innerHTML ni style en ligne, pour rester
 *  affichable meme sous la politique de securite de contenu de l'app. */
function fatal(reason) {
  const box = document.createElement("div");
  box.className = "fatal";
  const h = document.createElement("h2");
  h.textContent = "L'application n'a pas pu démarrer";
  const p = document.createElement("p");
  p.textContent = reason;
  box.append(h, p);
  document.body.replaceChildren(box);
  throw new Error(reason);
}

// Sans le pont Tauri, aucun bouton ne repondrait et l'app aurait l'air
// simplement figee. Mieux vaut le dire.
if (!tauri || !tauri.core || !tauri.event) {
  fatal(
    "Le moteur d'affichage n'a pas chargé le pont interne. Redémarre l'application ; " +
      "si le problème persiste, redémarre le PC."
  );
}

const invoke = (cmd, args) => tauri.core.invoke(cmd, args);
const listen = (name, handler) => tauri.event.listen(name, handler);
const el = (id) => document.getElementById(id);

/** Les sept etapes du pipeline. Les identifiants doivent rester alignes
 *  avec les appels a `stage(...)` du backend Rust. */
const STAGES = [
  { id: "drivers", name: "Composants Apple" },
  { id: "device", name: "Détection de l'iPhone" },
  { id: "version", name: "Dernière version publiée" },
  { id: "download", name: "Téléchargement de l'app" },
  { id: "account", name: "Compte Apple & certificat" },
  { id: "sign", name: "Signature de l'app" },
  { id: "install", name: "Injection sur l'iPhone" },
];

const els = {
  statePill: el("state-pill"),
  devDot: el("dev-dot"),
  devLabel: el("dev-label"),
  devMeta: el("dev-meta"),
  prereq: el("prereq"),
  pipeline: el("pipeline"),

  statusText: el("status-text"),
  progressPct: el("progress-pct"),
  progressFill: el("progress-fill"),

  btnStart: el("btn-start"),
  btnCancel: el("btn-cancel-progress"),
  resultActions: el("result-actions"),
  btnCopy: el("btn-copy"),
  btnLog: el("btn-log"),

  overlayPrereqs: el("overlay-prereqs"),
  prereqsMessage: el("prereqs-message"),
  prereqsDetail: el("prereqs-detail"),
  btnPrereqsYes: el("btn-prereqs-yes"),
  btnPrereqsNo: el("btn-prereqs-no"),

  overlayDevice: el("overlay-device"),
  deviceList: el("device-list"),
  btnCancelDevice: el("btn-cancel-device"),

  overlayAccount: el("overlay-account"),
  accountList: el("account-list"),
  btnAddAccount: el("btn-add-account"),
  btnCancelAccount: el("btn-cancel-account"),

  overlayPassword: el("overlay-password"),
  passwordNote: el("password-note"),
  passwordError: el("password-error"),
  modalSubId: el("modal-sub-id"),
  inputAppleId: el("input-apple-id"),
  inputPassword: el("input-password"),
  btnSubmitPassword: el("btn-submit-password"),
  btnCancelPassword: el("btn-cancel-password"),

  overlay2fa: el("overlay-2fa"),
  twofaTitle: el("twofa-title"),
  twofaNote: el("twofa-note"),
  twofaSub: el("twofa-sub"),
  twofaError: el("twofa-error"),
  twofaCodeBlock: el("twofa-code-block"),
  twofaChoiceBlock: el("twofa-choice-block"),
  twofaMethods: el("twofa-methods"),
  input2fa: el("input-2fa"),
  btnSubmit2fa: el("btn-submit-2fa"),
  btnResend2fa: el("btn-resend-2fa"),
  btnCancel2fa: el("btn-cancel-2fa"),

  overlayCerts: el("overlay-certs"),
  certList: el("cert-list"),
  btnSubmitCerts: el("btn-submit-certs"),
  btnCancelCerts: el("btn-cancel-certs"),

  overlayQuit: el("overlay-quit"),
  btnQuitStay: el("btn-quit-stay"),
  btnQuitForce: el("btn-quit-force"),
};

// Un identifiant absent du HTML donnerait `null` ici, et la premiere ligne
// qui s'en sert casserait tout le script — donc une fenetre inerte, sans
// rien dans l'interface pour dire pourquoi.
const missing = Object.entries(els)
  .filter(([, node]) => !node)
  .map(([key]) => key);
if (missing.length) {
  fatal("Interface incomplète (" + missing.join(", ") + "). Réinstalle l'application.");
}

const overlays = [
  els.overlayPrereqs,
  els.overlayDevice,
  els.overlayAccount,
  els.overlayPassword,
  els.overlay2fa,
  els.overlayCerts,
];

// Journal des etapes traversees. Sert au bouton « Copier le rapport » :
// une erreur seule ne dit pas ou l'on en etait quand elle est tombee.
const trace = [];
const stepNodes = new Map();
let running = false;
let currentStage = null;
let lastFailure = null;
let deviceLabel = "";
let logHintText = "";

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

function buildPipeline() {
  els.pipeline.innerHTML = "";
  stepNodes.clear();

  STAGES.forEach((s, i) => {
    const step = document.createElement("section");
    step.className = "step";
    step.dataset.state = "idle";

    const head = document.createElement("div");
    head.className = "step-head";

    const idx = document.createElement("span");
    idx.className = "step-idx";
    idx.textContent = String(i + 1).padStart(2, "0");

    const name = document.createElement("span");
    name.className = "step-name";
    name.textContent = s.name;

    const state = document.createElement("span");
    state.className = "step-state";
    state.textContent = "";

    head.append(idx, name, state);
    step.appendChild(head);
    els.pipeline.appendChild(step);

    stepNodes.set(s.id, { step, state });
  });
}

function setStepState(id, value, label) {
  const node = stepNodes.get(id);
  if (!node) return;
  node.step.dataset.state = value;
  node.state.textContent = label || "";
}

function resetPipeline() {
  for (const { step, state } of stepNodes.values()) {
    step.dataset.state = "idle";
    state.textContent = "";
    const detail = step.querySelector(".step-detail");
    if (detail) detail.remove();
  }
}

/** Marque l'etape active, et toutes les precedentes comme terminees :
 *  le backend ne signale que l'entree dans une etape, la reussite de la
 *  precedente se deduit du seul fait qu'on soit passe a la suivante. */
function enterStage(id) {
  const index = STAGES.findIndex((s) => s.id === id);
  if (index < 0) return;
  currentStage = id;
  STAGES.forEach((s, i) => {
    if (i < index) setStepState(s.id, "ok", "OK");
    else if (i === index) setStepState(s.id, "run", "EN COURS");
    else setStepState(s.id, "idle", "");
  });
  scrollStepIntoView(id);
}

function scrollStepIntoView(id) {
  const node = stepNodes.get(id);
  if (node) node.step.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

/** Accroche un bloc de detail (echec ou reussite) sous une etape. */
function attachDetail(id, { title, steps, detail }) {
  const node = stepNodes.get(id);
  if (!node) return;
  const existing = node.step.querySelector(".step-detail");
  if (existing) existing.remove();

  const box = document.createElement("div");
  box.className = "step-detail";

  const h = document.createElement("p");
  h.className = "detail-title";
  h.textContent = title;
  box.appendChild(h);

  if (steps && steps.length) {
    const list = document.createElement("ol");
    list.className = "detail-steps";
    for (const s of steps) {
      const li = document.createElement("li");
      li.textContent = s;
      list.appendChild(li);
    }
    box.appendChild(list);
  }

  if (detail) {
    const toggle = document.createElement("button");
    toggle.className = "tech-toggle";
    toggle.textContent = "+ Détails techniques";
    const body = document.createElement("pre");
    body.className = "tech-body hidden";
    body.textContent = detail;
    toggle.addEventListener("click", () => {
      const hidden = body.classList.toggle("hidden");
      toggle.textContent = hidden ? "+ Détails techniques" : "− Détails techniques";
    });
    box.append(toggle, body);
  }

  node.step.appendChild(box);
  box.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

// ---------------------------------------------------------------------------
// Etat global de l'ecran
// ---------------------------------------------------------------------------

function setPill(state, text) {
  els.statePill.dataset.state = state;
  els.statePill.textContent = text;
}

function hideAllOverlays() {
  for (const o of overlays) o.classList.add("hidden");
}
function anyOverlayVisible() {
  return overlays.some((o) => !o.classList.contains("hidden"));
}

function cancelUpdate() {
  hideAllOverlays();
  invoke("submit_cancel").catch(() => {});
}

/** `null` = jauge indeterminee : on ne sait pas combien de temps ca prend. */
function setProgress(value) {
  if (value === null || value === undefined) {
    els.progressFill.classList.add("indeterminate");
    els.progressPct.textContent = "";
    return;
  }
  const pct = Math.max(0, Math.min(100, value * 100));
  els.progressFill.classList.remove("indeterminate");
  els.progressFill.style.width = pct + "%";
  els.progressPct.textContent = pct.toFixed(0) + " %";
}

function setRunning(state) {
  running = state;
  els.btnStart.disabled = state;
  els.btnStart.classList.toggle("hidden", state);
  els.btnCancel.classList.toggle("hidden", !state);
  els.prereq.classList.toggle("hidden", state);
  // Plus rien ne tourne : la question « fermer quand meme ? » n'a plus
  // lieu d'etre, la fermeture ne coupe plus rien.
  if (!state) els.overlayQuit.classList.add("hidden");
}

function startUpdate() {
  if (running) return;
  trace.length = 0;
  lastFailure = null;
  currentStage = null;
  deviceLabel = "";
  els.devDot.classList.remove("live");
  els.devLabel.classList.remove("live");
  els.devLabel.textContent = "Recherche de l'appareil...";
  els.devMeta.textContent = "";

  hideAllOverlays();
  resetPipeline();
  els.resultActions.classList.add("hidden");
  els.progressFill.classList.remove("ok", "err");
  els.progressFill.style.width = "0%";
  els.statusText.textContent = "Démarrage...";
  setPill("run", "EN COURS");
  setProgress(null);
  setRunning(true);
  els.btnStart.textContent = "Relancer l'injection";

  invoke("start_update")
    .catch((e) => showFailure(normalizeFailure(e)))
    .finally(() => setRunning(false));
}

/** Le backend renvoie un objet structure ; tout le reste est un imprevu
 *  que l'on presente quand meme proprement plutot que d'afficher
 *  « [object Object] ». */
function normalizeFailure(e) {
  if (e && typeof e === "object" && typeof e.title === "string") return e;
  return {
    title: "Erreur inattendue",
    steps: [
      "Relance l'injection.",
      "Si le problème se répète, copie le rapport et envoie-le au développeur.",
    ],
    detail: typeof e === "string" ? e : JSON.stringify(e),
    cancelled: false,
  };
}

function showFailure(f) {
  hideAllOverlays();
  lastFailure = f;

  const cancelled = !!f.cancelled;
  // L'echec est accroche a l'etape ou il s'est produit ; s'il tombe avant
  // la premiere etape, la premiere ligne fait l'affaire.
  const target = currentStage || STAGES[0].id;

  setStepState(target, cancelled ? "idle" : "err", cancelled ? "ARRÊTÉ" : "ÉCHEC");
  attachDetail(target, {
    title: f.title,
    steps: f.steps || [],
    detail: cancelled ? null : f.detail,
  });

  setPill(cancelled ? "idle" : "err", cancelled ? "ARRÊTÉ" : "ÉCHEC");
  els.statusText.textContent = f.title;
  els.progressFill.classList.remove("indeterminate");
  if (!cancelled) {
    els.progressFill.classList.add("err");
    els.progressFill.style.width = "100%";
  } else {
    els.progressFill.style.width = "0%";
  }
  els.progressPct.textContent = "";
  els.resultActions.classList.toggle("hidden", cancelled);
  els.btnLog.title = logHintText;
}

function showSuccess(payload) {
  hideAllOverlays();
  lastFailure = null;

  for (const s of STAGES) setStepState(s.id, "ok", "OK");
  attachDetail(STAGES[STAGES.length - 1].id, {
    title: (payload && payload.title) || "Injection terminée",
    steps: (payload && payload.steps) || [],
    detail: null,
  });

  setPill("ok", "TERMINÉ");
  els.statusText.textContent = "Injection terminée";
  els.progressFill.classList.remove("indeterminate", "err");
  els.progressFill.classList.add("ok");
  els.progressFill.style.width = "100%";
  els.progressPct.textContent = "100 %";
  els.resultActions.classList.add("hidden");
}

// ---------------------------------------------------------------------------
// Boutons
// ---------------------------------------------------------------------------

els.btnStart.addEventListener("click", startUpdate);
els.btnCancel.addEventListener("click", cancelUpdate);
els.btnCancelDevice.addEventListener("click", cancelUpdate);
els.btnCancelAccount.addEventListener("click", cancelUpdate);
els.btnCancelPassword.addEventListener("click", cancelUpdate);
els.btnCancel2fa.addEventListener("click", cancelUpdate);
els.btnCancelCerts.addEventListener("click", cancelUpdate);

els.btnQuitStay.addEventListener("click", () => {
  els.overlayQuit.classList.add("hidden");
  invoke("cancel_quit").catch(() => {});
});
els.btnQuitForce.addEventListener("click", () => {
  els.overlayQuit.classList.add("hidden");
  invoke("force_quit").catch(() => {});
});

// Echap ferme la question en cours, ce qui revient a annuler le flux :
// une fenetre modale sans issue au clavier est un piege classique.
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!els.overlayQuit.classList.contains("hidden")) {
    els.overlayQuit.classList.add("hidden");
    invoke("cancel_quit").catch(() => {});
  } else if (anyOverlayVisible()) {
    cancelUpdate();
  }
});

// La WebView2 se comporte par defaut comme un navigateur : menu
// contextuel, F5, Ctrl+R, recherche dans la page. Recharger l'interface
// en pleine injection la remet a zero alors que l'installation, elle,
// continue cote systeme : l'ecran repasse sur « Pret » pendant qu'un
// transfert tourne toujours, et le bouton relance repond « une
// installation est deja en cours ». Ces raccourcis n'ont de toute facon
// aucun sens dans un outil.
document.addEventListener("contextmenu", (e) => e.preventDefault());
document.addEventListener(
  "keydown",
  (e) => {
    const key = String(e.key).toLowerCase();
    const ctrl = e.ctrlKey || e.metaKey;
    const blocked =
      key === "f5" ||
      key === "f7" ||
      (ctrl && ["r", "p", "f", "g", "u", "j", "o", "s"].includes(key)) ||
      (ctrl && e.shiftKey && ["r", "i", "j", "c"].includes(key));
    if (blocked) {
      e.preventDefault();
      e.stopPropagation();
    }
  },
  true
);

// --- Rapport de bug ---
invoke("log_file_path")
  .then((p) => {
    logHintText = "Journal : " + p;
    els.btnLog.title = logHintText;
  })
  .catch(() => {});

function buildReport() {
  const f = lastFailure || {};
  const lines = [
    "Kosp Injection — rapport",
    "Date : " + new Date().toISOString(),
    "Appareil : " + (deviceLabel || "non détecté"),
    "Étape : " + (currentStage || "aucune"),
    "",
    "Erreur : " + (f.title || "aucune"),
  ];
  if (f.steps && f.steps.length) {
    lines.push("", "Pistes proposées :");
    for (const s of f.steps) lines.push("  - " + s);
  }
  if (trace.length) {
    lines.push("", "Étapes traversées :");
    for (const t of trace) lines.push("  " + t);
  }
  if (f.detail) lines.push("", "Détail technique :", f.detail);
  return lines.join("\n");
}

els.btnCopy.addEventListener("click", async () => {
  const text = buildReport();
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (_) {
    // Le presse-papiers moderne peut etre refuse dans une WebView selon
    // le contexte de securite ; le vieux execCommand, lui, passe.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      ok = document.execCommand("copy");
    } catch (_) {
      ok = false;
    }
    document.body.removeChild(ta);
  }
  flash(els.btnCopy, ok ? "Rapport copié" : "Copie impossible", "Copier le rapport");
});

els.btnLog.addEventListener("click", () => {
  invoke("open_log").catch((e) => flash(els.btnLog, String(e), "Journal"));
});

function flash(button, message, restore) {
  button.textContent = message;
  setTimeout(() => {
    button.textContent = restore;
  }, 2200);
}

// ---------------------------------------------------------------------------
// Identifiants Apple
// ---------------------------------------------------------------------------

function showFieldError(node, message) {
  node.textContent = message;
  node.classList.remove("hidden");
}

function submitPassword() {
  const appleId = els.inputAppleId.value.trim();
  const pw = els.inputPassword.value;
  if (!appleId) {
    showFieldError(els.passwordError, "Saisis l'adresse du compte Apple.");
    els.inputAppleId.focus();
    return;
  }
  if (!appleId.includes("@")) {
    showFieldError(els.passwordError, "L'identifiant Apple est une adresse e-mail.");
    els.inputAppleId.focus();
    return;
  }
  if (!pw) {
    showFieldError(els.passwordError, "Saisis le mot de passe du compte Apple.");
    els.inputPassword.focus();
    return;
  }
  els.passwordError.classList.add("hidden");
  els.overlayPassword.classList.add("hidden");
  invoke("submit_credentials", { appleId, password: pw }).catch(() => {});
  els.inputPassword.value = "";
}

els.btnSubmitPassword.addEventListener("click", submitPassword);
for (const input of [els.inputAppleId, els.inputPassword]) {
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submitPassword();
  });
}

// ---------------------------------------------------------------------------
// Double authentification
// ---------------------------------------------------------------------------

function submit2faCode() {
  const code = els.input2fa.value.trim();
  if (code.length < 6) {
    showFieldError(els.twofaError, "Le code compte 6 chiffres.");
    return;
  }
  els.twofaError.classList.add("hidden");
  els.overlay2fa.classList.add("hidden");
  invoke("submit_2fa", { action: "code", code }).catch(() => {});
  els.input2fa.value = "";
}

els.btnSubmit2fa.addEventListener("click", submit2faCode);
// Chiffres seulement : coller un code avec des espaces ou un tiret est
// frequent et donnait un « code incorrect » cote Apple.
els.input2fa.addEventListener("input", () => {
  const cleaned = els.input2fa.value.replace(/\D/g, "").slice(0, 6);
  if (cleaned !== els.input2fa.value) els.input2fa.value = cleaned;
  if (cleaned.length === 6) submit2faCode();
});
els.input2fa.addEventListener("keydown", (e) => {
  if (e.key === "Enter") submit2faCode();
});
els.btnResend2fa.addEventListener("click", () => {
  els.overlay2fa.classList.add("hidden");
  invoke("submit_2fa", { action: "resend" }).catch(() => {});
});

function renderTwofaMethods(numbers) {
  els.twofaMethods.innerHTML = "";

  els.twofaMethods.appendChild(
    listItem("Sur mes appareils Apple", "iPhone, iPad ou Mac connectés au compte", () => {
      els.overlay2fa.classList.add("hidden");
      invoke("submit_2fa", { action: "devices" }).catch(() => {});
    })
  );

  for (const n of numbers) {
    els.twofaMethods.appendChild(
      listItem("Par SMS", n.label, () => {
        els.overlay2fa.classList.add("hidden");
        invoke("submit_2fa", { action: "sms", numberId: n.id }).catch(() => {});
      })
    );
  }
}

/** Ligne cliquable commune aux listes (appareils, comptes, canaux 2FA). */
function listItem(name, meta, onClick) {
  const item = document.createElement("div");
  item.className = "list-item";

  const text = document.createElement("div");
  text.className = "item-text";
  const n = document.createElement("span");
  n.className = "item-name";
  n.textContent = name;
  text.appendChild(n);
  if (meta) {
    const m = document.createElement("span");
    m.className = "item-meta";
    m.textContent = meta;
    text.appendChild(m);
  }
  item.appendChild(text);
  item.addEventListener("click", onClick);
  return item;
}

// ---------------------------------------------------------------------------
// Certificats
// ---------------------------------------------------------------------------

let selectedCerts = new Set();
els.btnSubmitCerts.addEventListener("click", () => {
  if (selectedCerts.size === 0) return;
  els.overlayCerts.classList.add("hidden");
  invoke("submit_cert_choice", { serials: Array.from(selectedCerts) }).catch(() => {});
});

// ---------------------------------------------------------------------------
// Prerequis Apple
// ---------------------------------------------------------------------------

els.btnPrereqsYes.addEventListener("click", () => {
  els.overlayPrereqs.classList.add("hidden");
  invoke("submit_confirm", { ok: true }).catch(() => {});
});
els.btnPrereqsNo.addEventListener("click", () => {
  els.overlayPrereqs.classList.add("hidden");
  invoke("submit_confirm", { ok: false }).catch(() => {});
});

// ---------------------------------------------------------------------------
// Comptes enregistres
// ---------------------------------------------------------------------------

els.btnAddAccount.addEventListener("click", () => {
  els.overlayAccount.classList.add("hidden");
  invoke("submit_account_choice", { appleId: null }).catch(() => {});
});

function renderAccounts(accounts) {
  els.accountList.innerHTML = "";
  for (const id of accounts) {
    const item = listItem(id, null, () => {
      els.overlayAccount.classList.add("hidden");
      invoke("submit_account_choice", { appleId: id }).catch(() => {});
    });

    const forget = document.createElement("button");
    forget.className = "icon-btn";
    forget.title = "Oublier ce compte";
    forget.textContent = "×";
    forget.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      await invoke("forget_account", { appleId: id }).catch(() => {});
      const left = await invoke("list_saved_accounts").catch(() => []);
      if (!left.length) {
        // Plus aucun compte enregistre : la liste vide n'aurait rien a
        // proposer, on enchaine directement sur la saisie manuelle.
        els.overlayAccount.classList.add("hidden");
        invoke("submit_account_choice", { appleId: null }).catch(() => {});
      } else {
        renderAccounts(left);
      }
    });
    item.appendChild(forget);
    els.accountList.appendChild(item);
  }
}

// ---------------------------------------------------------------------------
// Evenements emis par le backend Rust
// ---------------------------------------------------------------------------

listen("stage", (e) => enterStage(e.payload));

listen("status", (e) => {
  els.statusText.textContent = e.payload;
  const last = trace[trace.length - 1];
  if (last !== e.payload) trace.push(e.payload);
});

listen("progress", (e) => setProgress(e.payload));

listen("device", (e) => {
  const p = e.payload || {};
  deviceLabel = `${p.name || "iPhone"} — iOS ${p.ios || "?"}`;
  els.devDot.classList.add("live");
  els.devLabel.classList.add("live");
  els.devLabel.textContent = p.name || "iPhone";
  els.devMeta.textContent = "iOS " + (p.ios || "?");
});

listen("need-prereqs", (e) => {
  els.prereqsMessage.textContent = e.payload.message;
  els.prereqsDetail.textContent = e.payload.detail;
  els.overlayPrereqs.classList.remove("hidden");
});

listen("need-device", (e) => {
  els.deviceList.innerHTML = "";
  for (const dev of e.payload || []) {
    els.deviceList.appendChild(
      listItem(dev.name, dev.usb ? "USB" : "Réseau", () => {
        els.overlayDevice.classList.add("hidden");
        invoke("submit_device", { udid: dev.udid }).catch(() => {});
      })
    );
  }
  els.overlayDevice.classList.remove("hidden");
});

listen("need-account", (e) => {
  renderAccounts(e.payload || []);
  els.overlayAccount.classList.remove("hidden");
});

listen("need-password", (e) => {
  const payload = e.payload || {};
  const knownId = payload.appleId;
  els.passwordError.classList.add("hidden");

  if (payload.note) {
    els.passwordNote.textContent = payload.note;
    els.passwordNote.classList.remove("hidden");
  } else {
    els.passwordNote.classList.add("hidden");
  }

  if (knownId) {
    els.inputAppleId.value = knownId;
    els.modalSubId.textContent = "Ressaisis le mot de passe de " + knownId + ".";
  } else {
    els.inputAppleId.value = "";
    els.modalSubId.textContent =
      "Identifiants du compte Apple gratuit utilisé pour signer l'app.";
  }
  els.inputPassword.value = "";
  els.overlayPassword.classList.remove("hidden");
  (knownId ? els.inputPassword : els.inputAppleId).focus();
});

listen("need-2fa", (e) => {
  const p = e.payload || {};
  els.twofaError.classList.add("hidden");
  els.input2fa.value = "";

  if (p.error) {
    els.twofaNote.textContent = p.error;
    els.twofaNote.classList.remove("hidden");
  } else {
    els.twofaNote.classList.add("hidden");
  }

  if (p.unknown) {
    // Etat particulier : Apple n'a pas dit par ou passer. Envoyer un code
    // maintenant fait echouer la connexion — il faut d'abord choisir un
    // canal, sinon l'app se bloque sur une erreur incomprehensible.
    els.twofaTitle.textContent = "Comment recevoir le code ?";
    els.twofaCodeBlock.classList.add("hidden");
    els.twofaChoiceBlock.classList.remove("hidden");
    renderTwofaMethods(p.numbers || []);
    els.overlay2fa.classList.remove("hidden");
    return;
  }

  els.twofaTitle.textContent = "Code de vérification";
  els.twofaChoiceBlock.classList.add("hidden");
  els.twofaCodeBlock.classList.remove("hidden");
  els.twofaSub.textContent = p.sms
    ? "Entre le code à 6 chiffres reçu par SMS."
    : "Entre le code à 6 chiffres affiché sur tes appareils Apple.";
  els.overlay2fa.classList.remove("hidden");
  els.input2fa.focus();
});

listen("need-certs", (e) => {
  selectedCerts = new Set();
  els.btnSubmitCerts.disabled = true;
  els.certList.innerHTML = "";
  for (const cert of e.payload || []) {
    const item = document.createElement("label");
    item.className = "list-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    item.appendChild(checkbox);

    const text = document.createElement("div");
    text.className = "item-text";
    const name = document.createElement("span");
    name.className = "item-name";
    name.textContent = cert.name;
    const machine = document.createElement("span");
    machine.className = "item-meta";
    machine.textContent = cert.machine;
    text.append(name, machine);
    item.appendChild(text);

    checkbox.addEventListener("change", () => {
      item.classList.toggle("selected", checkbox.checked);
      if (checkbox.checked) selectedCerts.add(cert.serial);
      else selectedCerts.delete(cert.serial);
      els.btnSubmitCerts.disabled = selectedCerts.size === 0;
    });
    els.certList.appendChild(item);
  }
  els.overlayCerts.classList.remove("hidden");
});

listen("done", (e) => showSuccess(e.payload));

// Fermeture de la fenetre demandee alors qu'une injection tourne : le
// backend a suspendu la fermeture et attend la reponse.
listen("confirm-quit", () => els.overlayQuit.classList.remove("hidden"));

// ---------------------------------------------------------------------------

buildPipeline();

// Trace de reference dans le journal : si cette ligne manque, c'est que
// l'interface elle-meme n'a pas demarre, et il est inutile de chercher la
// panne du cote de l'iPhone ou du compte Apple.
invoke("ui_ready").catch(() => {});
