//! Interface graphique (Tauri + WebView2) pour installer/mettre a jour
//! TwitNinf sur l'iPhone branche, via le compte Apple gratuit.
//!
//! Toute la logique interactive (mot de passe, code 2FA, choix de
//! certificat a revoquer) qui etait des prompts `stdin` en CLI devient ici
//! des allers-retours evenement/commande avec le frontend : le flux
//! d'installation, qui tourne dans une tache async, emet un evenement et
//! attend sur un canal jusqu'a ce que l'UI reponde via une commande Tauri.

use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{certificates::DevelopmentCertificate, developer_session::DeveloperSession},
    sideload::{SideloaderBuilder, TeamSelection, builder::MaxCertsBehavior},
    util::{
        keyring_storage::KeyringStorage,
        storage::SideloadingStorage,
    },
};
use rootcause::{Report, option_ext::OptionExt, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::oneshot;

const SOURCE_URL: &str =
    "https://gist.githubusercontent.com/gaslebossop/4d82d6b4a3adaef965765ab37937ef83/raw/apps.json";
const KEYRING_SERVICE: &str = "twitninf-updater";
const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
struct AltStoreSource {
    apps: Vec<AltStoreApp>,
}
#[derive(Deserialize)]
struct AltStoreApp {
    versions: Vec<AltStoreVersion>,
}
#[derive(Deserialize)]
struct AltStoreVersion {
    version: String,
    #[serde(rename = "buildVersion")]
    build_version: String,
    #[serde(rename = "downloadURL")]
    download_url: String,
}

#[derive(Serialize, Clone)]
struct CertOption {
    name: String,
    machine: String,
    serial: String,
}

#[derive(Serialize, Clone)]
struct DeviceOption {
    name: String,
    udid: String,
}

/// Canaux en attente d'une reponse venue de l'UI. Un seul flux
/// d'installation actif a la fois, donc un seul slot par type de question.
#[derive(Default)]
struct PendingInputs {
    running: AtomicBool,
    cancel_tx: Mutex<Option<oneshot::Sender<()>>>,
    confirm_tx: Mutex<Option<oneshot::Sender<bool>>>,
    device_tx: Mutex<Option<oneshot::Sender<String>>>,
    credentials_tx: Mutex<Option<oneshot::Sender<(String, String)>>>,
    twofa_tx: Mutex<Option<oneshot::Sender<TwoFactorCallbackResponse>>>,
    certs_tx: Mutex<Option<std::sync::mpsc::Sender<Vec<String>>>>,
}

#[tauri::command]
fn submit_confirm(state: State<PendingInputs>, ok: bool) {
    if let Some(tx) = state.confirm_tx.lock().unwrap().take() {
        let _ = tx.send(ok);
    }
}

/// Annule le flux en cours : abandonne tous les canaux en attente sans y
/// repondre. Le `oneshot`/`mpsc` en attente cote flux d'installation recoit
/// alors une erreur de fermeture (au lieu d'attendre indefiniment une
/// reponse qui ne viendra jamais), ce qui remonte proprement une erreur
/// "annule" plutot que de bloquer l'app.
#[tauri::command]
fn submit_cancel(state: State<PendingInputs>) {
    // Le signal cancel_tx abandonne le flux immediatement, ou qu'il en soit
    // (telechargement reseau compris, pas seulement en attente d'une
    // question) : dropper une future en cours d'attente l'arrete net.
    // Vider les canaux de question en plus est une precaution de proprete,
    // pas le mecanisme principal.
    if let Some(tx) = state.cancel_tx.lock().unwrap().take() {
        let _ = tx.send(());
    }
    state.confirm_tx.lock().unwrap().take();
    state.device_tx.lock().unwrap().take();
    state.credentials_tx.lock().unwrap().take();
    state.twofa_tx.lock().unwrap().take();
    state.certs_tx.lock().unwrap().take();
}

#[tauri::command]
fn submit_device(state: State<PendingInputs>, udid: String) {
    if let Some(tx) = state.device_tx.lock().unwrap().take() {
        let _ = tx.send(udid);
    }
}

#[tauri::command]
fn submit_credentials(state: State<PendingInputs>, apple_id: String, password: String) {
    if let Some(tx) = state.credentials_tx.lock().unwrap().take() {
        let _ = tx.send((apple_id, password));
    }
}

#[tauri::command]
fn submit_2fa(state: State<PendingInputs>, code: String) {
    if let Some(tx) = state.twofa_tx.lock().unwrap().take() {
        let resp = if code == "__resend__" {
            TwoFactorCallbackResponse::ResendCode
        } else {
            TwoFactorCallbackResponse::SubmitCode(code)
        };
        let _ = tx.send(resp);
    }
}

#[tauri::command]
fn submit_cert_choice(state: State<PendingInputs>, serials: Vec<String>) {
    if let Some(tx) = state.certs_tx.lock().unwrap().take() {
        let _ = tx.send(serials);
    }
}

#[tauri::command]
async fn start_update(app: AppHandle) -> Result<(), String> {
    let state = app.state::<PendingInputs>();
    if state.running.swap(true, Ordering::SeqCst) {
        return Err("une mise a jour est deja en cours".to_string());
    }
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    *state.cancel_tx.lock().unwrap() = Some(cancel_tx);

    // select! plutot qu'un simple .await : si submit_cancel declenche
    // cancel_rx, la future run_update(..) est abandonnee (donc son
    // execution s'arrete net a son prochain point d'attente) au lieu de
    // laisser l'app figee sans issue en attendant une reponse qui ne
    // viendra jamais.
    let result: Result<(), String> = tokio::select! {
        r = run_update(app.clone()) => r.map_err(|e| format!("{e}")),
        _ = cancel_rx => Err("annule".to_string()),
    };

    let state = app.state::<PendingInputs>();
    state.cancel_tx.lock().unwrap().take();
    state.running.store(false, Ordering::SeqCst);
    // Une seule voie de restitution de l'erreur : la valeur renvoyee ici,
    // que le frontend recupere via le .catch() de son invoke(). Emettre en
    // plus un evenement "failed" affichait le message deux fois.
    result
}

async fn run_update(app: AppHandle) -> std::result::Result<(), Report> {
    let http = reqwest::Client::builder()
        .timeout(NETWORK_TIMEOUT)
        .build()
        .context("initialisation du client HTTP")?;

    // Verifie les pilotes avant tout telechargement : sur un PC sans
    // Apple Mobile Device Support, ca evite de tirer 27 Mo d'IPA pour rien
    // avant de decouvrir que l'installation ne pourra pas continuer.
    ensure_apple_drivers(&app).await?;

    app.emit("status", "Recherche de la derniere version...").ok();
    let source: AltStoreSource = http
        .get(SOURCE_URL)
        .send()
        .await
        .context("impossible de joindre la source")?
        .json()
        .await
        .context("apps.json illisible")?;
    let app_entry = source
        .apps
        .first()
        .context("apps.json ne declare aucune app")?;
    // « Derniere version » = le plus grand buildVersion numerique, pas le
    // premier element de la liste — apps.json n'est pas garanti trie.
    let latest = app_entry
        .versions
        .iter()
        .max_by_key(|v| v.build_version.parse::<u64>().unwrap_or(0))
        .context("apps.json ne contient aucune version")?;
    let download_url = latest.download_url.clone();

    app.emit(
        "status",
        format!(
            "Telechargement de la version {} (build {})...",
            latest.version, latest.build_version
        ),
    )
    .ok();
    let bytes = http
        .get(&download_url)
        .send()
        .await
        .context("echec du telechargement de l'IPA")?
        .bytes()
        .await
        .context("echec de lecture de l'IPA")?;
    let ipa_path = std::env::temp_dir().join("TwitNinf-latest.ipa");
    std::fs::write(&ipa_path, &bytes).context("ecriture de l'IPA sur le disque")?;

    app.emit("status", "Recherche de l'iPhone...").ok();
    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .context("Apple Mobile Device Service ne repond pas")?;
    let devices = usbmuxd.get_devices().await.context("liste des appareils")?;
    if devices.is_empty() {
        None::<()>.context("aucun iPhone/iPad branche en USB")?;
    }

    let chosen_udid = if devices.len() == 1 {
        devices[0].udid.clone()
    } else {
        // usbmuxd n'expose pas de nom lisible sans une connexion lockdown
        // supplementaire par appareil — l'UDID suffit pour distinguer les
        // appareils dans le rare cas ou plusieurs sont branches a la fois.
        let options: Vec<DeviceOption> = devices
            .iter()
            .map(|d| DeviceOption {
                name: format!("Appareil ...{}", &d.udid[d.udid.len().saturating_sub(8)..]),
                udid: d.udid.clone(),
            })
            .collect();
        let (tx, rx) = oneshot::channel();
        *app.state::<PendingInputs>().device_tx.lock().unwrap() = Some(tx);
        app.emit("need-device", &options).ok();
        rx.await.context("choix de l'appareil annule")?
    };
    let device = devices
        .iter()
        .find(|d| d.udid == chosen_udid)
        .context("appareil choisi introuvable")?;
    // .default() plutot que .from_env_var() : cette derniere ne peut
    // paniquer que si USBMUXD_SOCKET_ADDRESS est definie et malformee —
    // variable que personne ne positionne ici, autant retirer le risque.
    let provider = device.to_provider(UsbmuxdAddr::default(), "twitninf-updater");

    let keyring = KeyringStorage::new(KEYRING_SERVICE.to_string());
    let existing_id = keyring.retrieve("apple_id").unwrap_or(None);

    let (tx, rx) = oneshot::channel();
    *app.state::<PendingInputs>().credentials_tx.lock().unwrap() = Some(tx);
    app.emit("need-password", serde_json::json!({ "appleId": existing_id })).ok();
    let (apple_id, password) = rx.await.context("saisie des identifiants annulee")?;

    app.emit("status", "Connexion au compte Apple...").ok();
    let app_for_2fa = app.clone();
    let get_2fa_code =
        move |params: TwoFactorCallbackParams| wait_2fa(app_for_2fa.clone(), params.unknown);

    let mut account = AppleAccount::builder(&apple_id)
        .anisette_provider(
            RemoteV3AnisetteProvider::default()
                .context("fournisseur anisette distant")?
                .set_serial_number("twitninf-updater".to_string())
                // KeyringStorage (pas InMemoryStorage) : la lib persiste
                // l'etat anisette sous "anisette_state", perdu a chaque
                // fermeture avec un stockage en memoire — c'est ce qui
                // faisait redemander un code 2FA a chaque lancement.
                .set_storage(Box::new(KeyringStorage::new(KEYRING_SERVICE.to_string()))),
        )
        .login(&password, get_2fa_code)
        .await
        .context("identifiants incorrects ou 2FA refuse")?;

    keyring
        .store("apple_id", &apple_id)
        .context("ecriture de la session")?;

    let dev_session = DeveloperSession::from_account(&mut account)
        .await
        .context("session developpeur Apple")?;

    let app_for_certs = app.clone();
    let cert_selection_prompt = move |certs: &Vec<DevelopmentCertificate>| {
        let options: Vec<CertOption> = certs
            .iter()
            .map(|c| CertOption {
                name: c.name.clone().unwrap_or_else(|| "<sans nom>".to_string()),
                machine: c
                    .machine_name
                    .clone()
                    .unwrap_or_else(|| "<machine inconnue>".to_string()),
                serial: c.serial_number.clone().unwrap_or_default(),
            })
            .collect();

        let (tx, rx) = std::sync::mpsc::channel();
        *app_for_certs.state::<PendingInputs>().certs_tx.lock().unwrap() = Some(tx);
        app_for_certs.emit("need-certs", &options).ok();

        let selected = tokio::task::block_in_place(|| rx.recv().unwrap_or_default());
        if selected.is_empty() { None } else { Some(selected) }
    };

    app.emit("status", "Preparation de la signature...").ok();
    let mut sideloader = SideloaderBuilder::new(dev_session, apple_id.clone())
        .team_selection(TeamSelection::First)
        .max_certs_behavior(MaxCertsBehavior::Prompt(Box::new(cert_selection_prompt)))
        .storage(Box::new(KeyringStorage::new(KEYRING_SERVICE.to_string())))
        .machine_name("twitninf-updater".to_string())
        .build();

    app.emit("status", "Installation en cours...").ok();
    let app_for_progress = app.clone();
    let progress_cb = move |pct: f32| {
        let app = app_for_progress.clone();
        async move {
            app.emit("progress", pct).ok();
        }
    };

    sideloader
        .install_app(&provider, ipa_path, true, Some(progress_cb))
        .await
        .context("echec de l'installation")?;

    app.emit("done", "TwitNinf installe/mis a jour avec succes.")
        .ok();
    Ok(())
}

/// Verifie que le service Windows "Apple Mobile Device Service" repond ;
/// sinon, propose d'installer le paquet WinGet officiel
/// "Apple.AppleMobileDeviceSupport" (source apple.com, hash verifie par
/// WinGet). Prefere a l'installeur iTunes complet : les versions
/// recentes d'iTunes64Setup.exe n'embarquent plus ce composant, et le
/// bootstrapper Apple change de format sans prevenir — WinGet s'occupe
/// du telechargement/verification/elevation lui-meme.
///
/// L'utilisateur confirme d'abord dans l'app (nom/source/taille
/// affiches), puis Windows demande lui-meme l'elevation UAC pour
/// l'installation — deux confirmations distinctes, aucune saisie de mot
/// de passe systeme requise.
/// WinGet est absent sur certaines images minimales (constate sous Windows
/// Sandbox), meme s'il est integre d'office a un vrai poste Windows 10/11
/// a jour. Ses dependances (VCLibs, Windows App Runtime) le sont donc
/// aussi, et doivent correspondre EXACTEMENT a la version de WinGet
/// installee — les liens generiques (aka.ms/Microsoft.VCLibs...) servent
/// parfois une version trop ancienne, ce que Add-AppxPackage rejette avec
/// un message qui donne l'impression que rien n'a ete installe.
///
/// Source fiable : chaque release GitHub de winget-cli embarque dans
/// `DesktopAppInstaller_Dependencies.zip` les .appx de VCLibs et Windows
/// App Runtime a la version exacte qu'elle requiert — memes releases,
/// garanties compatibles entre elles, pas de devinette de version.
async fn ensure_winget(app: &AppHandle) -> std::result::Result<(), Report> {
    let present = tokio::process::Command::new("winget")
        .arg("--version")
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if present {
        return Ok(());
    }

    app.emit("status", "Installation de WinGet et de ses dependances...").ok();
    let work_dir = std::env::temp_dir().join("kosp-winget-deps");
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$work = '{work}'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'
$depsAsset = $release.assets | Where-Object {{ $_.name -eq 'DesktopAppInstaller_Dependencies.zip' }}
$bundleAsset = $release.assets | Where-Object {{ $_.name -like '*.msixbundle' }}

$depsZip = Join-Path $work 'deps.zip'
Invoke-WebRequest -Uri $depsAsset.browser_download_url -OutFile $depsZip
Expand-Archive -Path $depsZip -DestinationPath $work -Force

Get-ChildItem -Path (Join-Path $work 'x64') -Filter '*.appx' | ForEach-Object {{
    Add-AppxPackage -Path $_.FullName -ErrorAction Stop
}}

$bundlePath = Join-Path $work 'winget.msixbundle'
Invoke-WebRequest -Uri $bundleAsset.browser_download_url -OutFile $bundlePath
Add-AppxPackage -Path $bundlePath -ErrorAction Stop
"#,
        work = work_dir.display()
    );
    let status = tokio::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .await
        .context("installation de WinGet et de ses dependances")?;
    if !status.success() {
        None::<()>.context("echec de l'installation de WinGet ou de ses dependances")?;
    }
    Ok(())
}

async fn ensure_apple_drivers(app: &AppHandle) -> std::result::Result<(), Report> {
    if UsbmuxdConnection::default().await.is_ok() {
        return Ok(());
    }

    let (tx, rx) = oneshot::channel();
    *app.state::<PendingInputs>().confirm_tx.lock().unwrap() = Some(tx);
    app.emit(
        "need-prereqs",
        serde_json::json!({
            "message": "Les pilotes Apple (Apple Mobile Device Service) ne sont pas detectes sur ce PC.",
            "detail": "Installer \"Apple Mobile Device Support\" via WinGet (~150 Mo, source apple.com) ?",
        }),
    )
    .ok();
    let confirmed = rx.await.context("confirmation d'installation annulee")?;
    if !confirmed {
        None::<()>.context("pilotes Apple requis — installation refusee")?;
    }

    ensure_winget(&app).await?;

    app.emit(
        "status",
        "Installation d'Apple Mobile Device Support (autorise l'invite Windows si elle apparait)...",
    )
    .ok();
    let status = tokio::process::Command::new("winget")
        .args([
            "install",
            "--id",
            "Apple.AppleMobileDeviceSupport",
            // --source winget : sans ca, winget interroge aussi la source
            // msstore, qui exige d'accepter ses propres conditions
            // d'utilisation au premier lancement — un prompt interactif
            // qui n'a personne pour y repondre en silencieux, et fait
            // echouer toute la recherche au lieu d'utiliser la source
            // winget classique ou le paquet existe deja.
            "--source",
            "winget",
            "--accept-source-agreements",
            "--accept-package-agreements",
            "--silent",
        ])
        .status()
        .await
        .context("lancement de winget")?;
    if !status.success() {
        None::<()>.context("installation refusee ou echouee (invite Windows refusee ?)")?;
    }

    app.emit("status", "Verification des pilotes Apple...").ok();
    UsbmuxdConnection::default().await.context(
        "les pilotes Apple restent indisponibles apres installation — redemarre le PC et reessaie",
    )?;
    Ok(())
}

async fn wait_2fa(
    app: AppHandle,
    unknown: bool,
) -> std::result::Result<TwoFactorCallbackResponse, Report> {
    let (tx, rx) = oneshot::channel();
    *app.state::<PendingInputs>().twofa_tx.lock().unwrap() = Some(tx);
    app.emit("need-2fa", serde_json::json!({ "unknown": unknown })).ok();
    Ok(rx.await.context("saisie du code 2FA annulee")?)
}

/// Le WebView2 Runtime (moteur d'affichage de Tauri) n'est pas toujours
/// present sur un PC — absent par defaut sur une image minimale comme
/// Windows Sandbox, meme s'il l'est presque toujours sur un vrai poste
/// Windows 10/11 a jour. Contrairement aux pilotes Apple, ce n'est pas
/// optionnel : sans lui, Tauri ne peut meme pas creer sa fenetre, donc
/// impossible de demander confirmation via l'interface — on l'installe
/// silencieusement avant de tenter de demarrer.
fn webview2_installed() -> bool {
    const KEY_PATH: &str =
        r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    ["HKLM", "HKCU"].iter().any(|root| {
        std::process::Command::new("reg")
            .args(["query", &format!("{root}\\{KEY_PATH}"), "/v", "pv"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    })
}

fn ensure_webview2() {
    if webview2_installed() {
        return;
    }
    // Bootstrapper Evergreen officiel Microsoft (lien stable documente) :
    // quelques Mo, installe la vraie runtime silencieusement.
    let installer = std::env::temp_dir().join("MicrosoftEdgeWebview2Setup.exe");
    let downloaded = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile '{}'",
                installer.display()
            ),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if downloaded {
        let _ = std::process::Command::new(&installer)
            .args(["/silent", "/install"])
            .status();
    }
    // Si l'installation echoue malgre tout, Tauri affichera son propre
    // message d'erreur natif au moment de creer la fenetre — pas besoin
    // de dupliquer cette gestion ici.
}

fn main() {
    ensure_webview2();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("installation du fournisseur crypto rustls");
    isideload::init().expect("initialisation du rapport d'erreurs");

    tauri::Builder::default()
        .manage(PendingInputs::default())
        .invoke_handler(tauri::generate_handler![
            start_update,
            submit_cancel,
            submit_confirm,
            submit_device,
            submit_credentials,
            submit_2fa,
            submit_cert_choice,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de l'application Tauri");
}
