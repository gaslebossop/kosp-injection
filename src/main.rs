// Pas de fenetre console derriere l'app en release. En debug elle reste,
// c'est pratique pour suivre les logs pendant le developpement.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Interface graphique (Tauri + WebView2) pour installer/mettre a jour
//! TwitNinf sur l'iPhone branche, via le compte Apple gratuit.
//!
//! Toute la logique interactive (mot de passe, code 2FA, choix de
//! certificat a revoquer) qui etait des prompts `stdin` en CLI devient ici
//! des allers-retours evenement/commande avec le frontend : le flux
//! d'installation, qui tourne dans une tache async, emet un evenement et
//! attend sur un canal jusqu'a ce que l'UI reponde via une commande Tauri.
//!
//! Regle de conception pour les erreurs : aucune erreur brute de
//! bibliotheque n'arrive telle quelle a l'ecran. Chaque point de rupture
//! renvoie une [`Failure`] — un titre en francais, la liste des gestes a
//! faire pour s'en sortir, et le message technique replie en dessous pour
//! le rapport de bug. Les erreurs qui remontent du fond des bibliotheques
//! (Apple, iPhone, reseau) passent par [`classify`], qui reconnait les cas
//! connus a partir du texte technique et les remplace par le meme genre de
//! message explicite.

use idevice::{
    IdeviceService,
    lockdown::LockdownClient,
    provider::{IdeviceProvider, UsbmuxdProvider},
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection},
};
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        certificates::DevelopmentCertificate,
        developer_session::DeveloperSession,
        device_type::DeveloperDeviceType,
        devices::DevicesApi,
        teams::TeamsApi,
    },
    sideload::{SideloaderBuilder, TeamSelection, builder::MaxCertsBehavior, install},
    util::{keyring_storage::KeyringStorage, storage::SideloadingStorage},
};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::oneshot;

const SOURCE_URL: &str =
    "https://gist.githubusercontent.com/gaslebossop/4d82d6b4a3adaef965765ab37937ef83/raw/apps.json";
const KEYRING_SERVICE: &str = "twitninf-updater";
const LOG_FILE: &str = "kosp-injection.log";
/// Delai d'etablissement de connexion HTTP. Volontairement court : au-dela,
/// c'est qu'il n'y a pas de reseau, inutile de faire patienter.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Delai entre deux paquets recus. Ce n'est PAS un delai total : un IPA de
/// 30 Mo sur une connexion lente met plusieurs minutes, et un timeout
/// global (`.timeout()`) l'aurait coupe en plein telechargement.
const READ_TIMEOUT: Duration = Duration::from_secs(90);
/// Delai des echanges lockdown avec l'iPhone. Un iPhone qui vient d'etre
/// branche, ou fige sur sa demande d'autorisation, ne repond jamais : sans
/// borne, l'app resterait bloquee sur « Recherche de l'iPhone » a vie.
const DEVICE_TIMEOUT: Duration = Duration::from_secs(25);
/// Nombre de mots de passe Apple errones tolERes avant d'arreter les frais.
/// Apple verrouille un compte apres une poignee d'echecs — mieux vaut
/// s'arreter nous-memes en l'expliquant que de faire bloquer le compte.
const MAX_LOGIN_ATTEMPTS: usize = 3;

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
    usb: bool,
}

/// Ce que l'UI affiche quand quelque chose echoue : un titre lisible, les
/// gestes concrets a faire, et le detail technique (replie) pour le
/// rapport de bug.
#[derive(Serialize, Clone, Debug)]
struct Failure {
    title: String,
    steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// `true` = l'utilisateur a annule : l'UI l'affiche en neutre, pas en
    /// rouge, et ne propose pas d'envoyer un rapport.
    cancelled: bool,
    /// Interne : cette erreur justifie de redemander l'identifiant/mot de
    /// passe plutot que d'abandonner le flux.
    #[serde(skip)]
    retry_credentials: bool,
}

impl Failure {
    fn new(title: &str, steps: &[&str]) -> Self {
        Failure {
            title: title.to_string(),
            steps: steps.iter().map(|s| s.to_string()).collect(),
            detail: None,
            cancelled: false,
            retry_credentials: false,
        }
    }

    fn cancelled(title: &str) -> Self {
        Failure {
            title: title.to_string(),
            steps: Vec::new(),
            detail: None,
            cancelled: true,
            retry_credentials: false,
        }
    }

    fn retryable(mut self) -> Self {
        self.retry_credentials = true;
        self
    }

    fn with_detail(mut self, detail: impl std::fmt::Display) -> Self {
        let detail = detail.to_string();
        let detail = detail.trim();
        if !detail.is_empty() {
            self.detail = Some(detail.to_string());
        }
        self
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.title)
    }
}

/// Traduit une erreur brute en [`Failure`] : d'abord en cherchant un cas
/// connu dans le texte technique, sinon en retombant sur le titre/les
/// etapes fournis par l'appelant.
trait Explain<T> {
    fn explain(self, title: &str, steps: &[&str]) -> Result<T, Failure>;
}

impl<T, E: std::fmt::Display> Explain<T> for Result<T, E> {
    fn explain(self, title: &str, steps: &[&str]) -> Result<T, Failure> {
        self.map_err(|e| {
            let detail = e.to_string();
            classify(&detail)
                .unwrap_or_else(|| Failure::new(title, steps))
                .with_detail(detail)
        })
    }
}

trait ExplainOption<T> {
    fn or_fail(self, title: &str, steps: &[&str]) -> Result<T, Failure>;
}

impl<T> ExplainOption<T> for Option<T> {
    fn or_fail(self, title: &str, steps: &[&str]) -> Result<T, Failure> {
        self.ok_or_else(|| Failure::new(title, steps))
    }
}

/// Reconnait les pannes courantes a partir du texte technique. Les
/// bibliotheques Apple/iPhone empilent leurs messages sur plusieurs
/// niveaux : on cherche donc des fragments caracteristiques n'importe ou
/// dans la chaine, du cas le plus precis au plus general.
fn classify(detail: &str) -> Option<Failure> {
    let d = detail.to_lowercase();
    let has = |needle: &str| d.contains(needle);
    let any = |needles: &[&str]| needles.iter().any(|n| d.contains(n));

    // --- Etat de l'iPhone -------------------------------------------------
    if any(&["developer mode is not enabled", "developermodenotenabled"]) {
        return Some(Failure::new(
            "Le mode developpeur n'est pas active sur l'iPhone",
            &[
                "Sur l'iPhone : Reglages > Confidentialite et securite > Mode developpeur.",
                "Active l'interrupteur, puis accepte le redemarrage de l'iPhone.",
                "Apres le redemarrage, deverrouille l'iPhone et relance l'installation.",
                "Si l'entree « Mode developpeur » n'apparait pas, laisse l'iPhone branche 30 s et rouvre les Reglages.",
            ],
        ));
    }
    if any(&["passwordprotected", "devicelocked", "device locked", "device is locked"]) {
        return Some(Failure::new(
            "L'iPhone est verrouille",
            &[
                "Deverrouille l'ecran de l'iPhone avec le code ou Face ID.",
                "Laisse l'ecran allume pendant toute l'installation.",
                "Relance l'installation.",
            ],
        ));
    }
    if has("pairingdialogresponsepending") {
        return Some(Failure::new(
            "L'iPhone attend ta reponse",
            &[
                "Regarde l'ecran de l'iPhone : la question « Se fier a cet ordinateur ? » est affichee.",
                "Touche « Se fier », puis saisis le code de l'iPhone.",
                "Relance l'installation.",
            ],
        ));
    }
    if has("userdeniedpairing") {
        return Some(Failure::new(
            "L'autorisation a ete refusee sur l'iPhone",
            &[
                "Debranche puis rebranche le cable USB.",
                "Quand l'iPhone demande « Se fier a cet ordinateur ? », touche « Se fier ».",
                "Saisis le code de l'iPhone si on te le demande, puis relance.",
            ],
        ));
    }
    if any(&[
        "invalidhostid",
        "device does not have pairing file",
        "missing pairrecorddata",
    ]) {
        return Some(Failure::new(
            "L'iPhone n'autorise pas encore ce PC",
            &[
                "Deverrouille l'iPhone et laisse-le branche en USB.",
                "Debranche puis rebranche le cable : la question « Se fier a cet ordinateur ? » doit apparaitre.",
                "Touche « Se fier » et saisis le code de l'iPhone.",
                "Si la question n'apparait plus : Reglages > General > Transferer ou reinitialiser > Reinitialiser > Reinitialiser les reglages reseau et localisation, puis rebranche.",
            ],
        ));
    }
    if any(&["free development profiles", "maxfreeapplimit"]) {
        return Some(Failure::new(
            "Limite de 3 apps atteinte pour ce compte Apple gratuit",
            &[
                "Un compte Apple gratuit ne peut garder que 3 apps installees a la fois.",
                "Sur l'iPhone, supprime une app installee avec ce meme compte.",
                "Relance l'installation.",
            ],
        ));
    }
    if any(&["no space", "out of space", "insufficient space", "not enough space"]) {
        return Some(Failure::new(
            "Espace insuffisant sur l'iPhone",
            &[
                "Libere au moins 500 Mo sur l'iPhone (Reglages > General > Stockage iPhone).",
                "Relance l'installation.",
            ],
        ));
    }
    if has("applicationverificationfailed") {
        return Some(Failure::new(
            "L'iPhone a refuse la signature de l'app",
            &[
                "Sur l'iPhone, supprime l'ancienne version de TwitNinf si elle est encore installee.",
                "Reglages > General > VPN et gestion de l'appareil : supprime le profil de developpeur existant.",
                "Relance l'installation.",
            ],
        ));
    }

    // --- Cable / transport ------------------------------------------------
    if any(&[
        "os error 10054",
        "os error 10053",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "device refused connection",
    ]) {
        return Some(Failure::new(
            "La liaison avec l'iPhone a ete coupee",
            &[
                "Ne debranche pas l'iPhone pendant l'installation.",
                "Utilise un cable de donnees (certains cables ne font que charger) et un port USB directement sur le PC, sans hub.",
                "Deverrouille l'iPhone, garde l'ecran allume, puis relance.",
            ],
        ));
    }

    // --- Compte Apple -----------------------------------------------------
    if any(&["-21669", "incorrect verification code"]) {
        return Some(Failure::new(
            "Code de verification incorrect",
            &[
                "Verifie les 6 chiffres recus sur ton iPhone ou par SMS.",
                "Demande un nouveau code si l'ancien a plus de quelques minutes.",
            ],
        ));
    }
    if any(&[
        "-20101",
        "your apple id or password",
        "incorrect apple id or password",
    ]) {
        return Some(
            Failure::new(
                "Identifiant ou mot de passe Apple incorrect",
                &[
                    "Verifie l'adresse du compte Apple et le mot de passe.",
                    "Attention a la disposition du clavier et aux majuscules.",
                ],
            )
            .retryable(),
        );
    }
    if any(&["-36607", "account has been disabled", "account is locked"]) {
        return Some(Failure::new(
            "Le compte Apple est bloque",
            &[
                "Va sur iforgot.apple.com pour debloquer le compte.",
                "Reessaie ensuite depuis l'app.",
            ],
        ));
    }
    if has("app-specific password") {
        return Some(Failure::new(
            "Ce compte exige un mot de passe pour application",
            &[
                "Cree un mot de passe pour application sur account.apple.com > Connexion et securite.",
                "Utilise ce mot de passe a la place du mot de passe habituel.",
            ],
        ));
    }
    if any(&["-22421", "session has expired", "session expired"]) {
        return Some(Failure::new(
            "La session Apple a expire",
            &["Relance simplement l'installation : une nouvelle session sera ouverte."],
        ));
    }
    if any(&["anisette", "not provisioned"]) {
        return Some(Failure::new(
            "Le service d'authentification Apple ne repond pas",
            &[
                "C'est un service externe, momentanement indisponible.",
                "Verifie ta connexion Internet, puis reessaie dans quelques minutes.",
            ],
        ));
    }
    if any(&["no developer teams", "no teams"]) {
        return Some(Failure::new(
            "Ce compte Apple n'a pas d'equipe de developpement",
            &[
                "Connecte-toi une fois sur developer.apple.com avec ce compte et accepte les conditions.",
                "Relance ensuite l'installation.",
            ],
        ));
    }
    if any(&["maximum number of certificates", "too many certificates"]) {
        return Some(Failure::new(
            "Trop de certificats sur ce compte Apple",
            &[
                "Relance l'installation : l'app proposera d'en revoquer un.",
                "Revoquer un certificat casse les apps signees avec, sur les autres PC.",
            ],
        ));
    }
    if any(&["app id limit", "maximum app id", "maximum number of app ids"]) {
        return Some(Failure::new(
            "Limite d'identifiants d'app atteinte chez Apple",
            &[
                "Apple limite un compte gratuit a 10 identifiants d'app par periode de 7 jours.",
                "Il faut attendre que la periode glissante se libere, ou utiliser un autre compte Apple.",
            ],
        ));
    }

    // --- Reseau -----------------------------------------------------------
    if any(&[
        "dns error",
        "failed to lookup",
        "error sending request",
        "connect error",
        "timed out",
        "operation timeout",
    ]) {
        return Some(Failure::new(
            "Pas de connexion Internet utilisable",
            &[
                "Verifie que le PC est bien connecte a Internet.",
                "Si tu es derriere un VPN ou un pare-feu d'entreprise, desactive-le le temps de l'installation.",
                "Relance ensuite.",
            ],
        ));
    }

    None
}

/// Canaux en attente d'une reponse venue de l'UI. Un seul flux
/// d'installation actif a la fois, donc un seul slot par type de question.
#[derive(Default)]
struct PendingInputs {
    running: AtomicBool,
    cancel_tx: Mutex<Option<oneshot::Sender<()>>>,
    confirm_tx: Mutex<Option<oneshot::Sender<bool>>>,
    device_tx: Mutex<Option<oneshot::Sender<String>>>,
    account_tx: Mutex<Option<oneshot::Sender<Option<String>>>>,
    credentials_tx: Mutex<Option<oneshot::Sender<(String, String)>>>,
    twofa_tx: Mutex<Option<oneshot::Sender<TwoFactorCallbackResponse>>>,
    certs_tx: Mutex<Option<std::sync::mpsc::Sender<Vec<String>>>>,
}

/// `lock().unwrap()` transforme le moindre panic ailleurs dans le
/// programme en Mutex empoisonne, donc en panic a chaque verrou suivant :
/// l'app se fige definitivement pour une erreur sans rapport. Le contenu
/// reste parfaitement exploitable ici (des `Option<Sender>`), on le
/// recupere donc au lieu de propager le poison.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Comptes Apple enregistres, avec mot de passe, dans le Gestionnaire
/// d'identification Windows (chiffre par DPAPI, lie au compte utilisateur
/// — pas de fichier en clair sur le disque). "account_list" garde la
/// liste des identifiants connus ; "password/<apple_id>" le mot de passe
/// de chacun, en entrees separees.
fn list_accounts(keyring: &KeyringStorage) -> Vec<String> {
    keyring
        .retrieve("account_list")
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}

fn get_saved_password(keyring: &KeyringStorage, apple_id: &str) -> Option<String> {
    keyring
        .retrieve(&format!("password/{apple_id}"))
        .ok()
        .flatten()
        .filter(|p| !p.is_empty())
}

fn save_account(keyring: &KeyringStorage, apple_id: &str, password: &str) {
    let mut accounts = list_accounts(keyring);
    if !accounts.iter().any(|a| a == apple_id) {
        accounts.push(apple_id.to_string());
    }
    // Enregistrer le compte est un confort, pas une etape du flux :
    // si le Gestionnaire d'identification refuse (strategie d'entreprise,
    // profil restreint), l'installation vient de reussir et n'a aucune
    // raison d'etre declaree en echec pour autant.
    if let Ok(json) = serde_json::to_string(&accounts) {
        if let Err(e) = keyring.store("account_list", &json) {
            tracing::warn!("liste des comptes non enregistree: {e}");
        }
    }
    if let Err(e) = keyring.store(&format!("password/{apple_id}"), password) {
        tracing::warn!("mot de passe non enregistre: {e}");
    }
}

fn forget_account_inner(keyring: &KeyringStorage, apple_id: &str) {
    let accounts: Vec<String> = list_accounts(keyring)
        .into_iter()
        .filter(|a| a != apple_id)
        .collect();
    if let Ok(json) = serde_json::to_string(&accounts) {
        let _ = keyring.store("account_list", &json);
    }
    let _ = keyring.delete(&format!("password/{apple_id}"));
}

// ---------------------------------------------------------------------------
// Commandes appelees par l'UI
// ---------------------------------------------------------------------------

#[tauri::command]
fn submit_confirm(state: State<PendingInputs>, ok: bool) {
    if let Some(tx) = lock(&state.confirm_tx).take() {
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
    // Vider les canaux de question en plus n'est pas qu'une precaution : la
    // reponse aux certificats est attendue par un `recv()` bloquant, que
    // seule la fermeture de son emetteur peut debloquer.
    if let Some(tx) = lock(&state.cancel_tx).take() {
        let _ = tx.send(());
    }
    lock(&state.confirm_tx).take();
    lock(&state.device_tx).take();
    lock(&state.account_tx).take();
    lock(&state.credentials_tx).take();
    lock(&state.twofa_tx).take();
    lock(&state.certs_tx).take();
}

#[tauri::command]
fn submit_device(state: State<PendingInputs>, udid: String) {
    if let Some(tx) = lock(&state.device_tx).take() {
        let _ = tx.send(udid);
    }
}

/// `apple_id: None` = « ajouter un nouveau compte » (choisi dans le
/// selecteur multi-compte), pas un compte existant.
#[tauri::command]
fn submit_account_choice(state: State<PendingInputs>, apple_id: Option<String>) {
    if let Some(tx) = lock(&state.account_tx).take() {
        let _ = tx.send(apple_id);
    }
}

#[tauri::command]
fn forget_account(apple_id: String) {
    forget_account_inner(&KeyringStorage::new(KEYRING_SERVICE.to_string()), &apple_id);
}

#[tauri::command]
fn list_saved_accounts() -> Vec<String> {
    list_accounts(&KeyringStorage::new(KEYRING_SERVICE.to_string()))
}

#[tauri::command]
fn submit_credentials(state: State<PendingInputs>, apple_id: String, password: String) {
    if let Some(tx) = lock(&state.credentials_tx).take() {
        let _ = tx.send((apple_id, password));
    }
}

/// `action` vaut "code" (avec `code`), "resend", "devices" (renvoyer sur
/// les appareils de confiance) ou "sms" (avec `number_id`). Les deux
/// dernieres servent quand Apple ne dit pas quelle methode utiliser et que
/// c'est a l'utilisateur de choisir : envoyer un code dans cet etat-la
/// fait echouer la connexion cote bibliotheque.
#[tauri::command]
fn submit_2fa(
    state: State<PendingInputs>,
    action: String,
    code: Option<String>,
    number_id: Option<u32>,
) {
    let resp = match action.as_str() {
        "resend" => TwoFactorCallbackResponse::ResendCode,
        "devices" => TwoFactorCallbackResponse::SendToDevices,
        "sms" => match number_id {
            Some(id) => TwoFactorCallbackResponse::SendSms(id),
            None => TwoFactorCallbackResponse::SendToDevices,
        },
        _ => TwoFactorCallbackResponse::SubmitCode(code.unwrap_or_default()),
    };
    if let Some(tx) = lock(&state.twofa_tx).take() {
        let _ = tx.send(resp);
    }
}

#[tauri::command]
fn submit_cert_choice(state: State<PendingInputs>, serials: Vec<String>) {
    if let Some(tx) = lock(&state.certs_tx).take() {
        let _ = tx.send(serials);
    }
}

/// Ouvre le journal dans l'explorateur pour que le testeur puisse le
/// joindre a un rapport de bug.
#[tauri::command]
fn open_log() -> Result<(), String> {
    let path = log_path();
    if !path.exists() {
        return Err("Aucun journal n'a encore ete ecrit.".to_string());
    }
    std::process::Command::new("explorer")
        .arg("/select,")
        .arg(&path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("ouverture du journal impossible : {e}"))
}

#[tauri::command]
fn log_file_path() -> String {
    log_path().display().to_string()
}

#[tauri::command]
async fn start_update(app: AppHandle) -> Result<(), Failure> {
    let state = app.state::<PendingInputs>();
    if state.running.swap(true, Ordering::SeqCst) {
        return Err(Failure::new(
            "Une installation est deja en cours",
            &["Attends la fin de l'installation en cours, ou annule-la avant d'en relancer une."],
        ));
    }
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    *lock(&state.cancel_tx) = Some(cancel_tx);

    // select! plutot qu'un simple .await : si submit_cancel declenche
    // cancel_rx, la future run_update(..) est abandonnee (donc son
    // execution s'arrete net a son prochain point d'attente) au lieu de
    // laisser l'app figee sans issue en attendant une reponse qui ne
    // viendra jamais.
    let result: Result<(), Failure> = tokio::select! {
        r = run_update(app.clone()) => r,
        _ = cancel_rx => Err(Failure::cancelled("Installation annulee")),
    };

    let state = app.state::<PendingInputs>();
    lock(&state.cancel_tx).take();
    // Les canaux de question survivent a un flux interrompu par une erreur
    // (le flux meurt sans les vider). Les remettre a zero ici evite qu'une
    // reponse tardive de l'UI soit consommee par l'installation suivante.
    lock(&state.confirm_tx).take();
    lock(&state.device_tx).take();
    lock(&state.account_tx).take();
    lock(&state.credentials_tx).take();
    lock(&state.twofa_tx).take();
    lock(&state.certs_tx).take();
    state.running.store(false, Ordering::SeqCst);

    if let Err(ref f) = result {
        tracing::error!("echec: {} | {:?}", f.title, f.detail);
    }
    // Une seule voie de restitution de l'erreur : la valeur renvoyee ici,
    // que le frontend recupere via le .catch() de son invoke(). Emettre en
    // plus un evenement "failed" affichait le message deux fois.
    result
}

// ---------------------------------------------------------------------------
// Emission d'etat vers l'UI
// ---------------------------------------------------------------------------

fn status(app: &AppHandle, text: impl Into<String>) {
    let text = text.into();
    tracing::info!("{text}");
    app.emit("status", text).ok();
}

/// Entree dans une etape du pipeline. L'UI affiche les sept etapes en
/// permanence et marque celle-ci comme active : quand ca casse, on voit
/// immediatement OU ca a casse, sans avoir a lire un message.
/// Les identifiants doivent rester alignes avec la liste de `ui/app.js`.
fn stage(app: &AppHandle, id: &str) {
    app.emit("stage", id).ok();
}

/// `Some(0.0..=1.0)` = barre chiffree, `None` = barre indeterminee (on ne
/// sait pas combien de temps ca va prendre).
fn progress(app: &AppHandle, value: Option<f32>) {
    app.emit("progress", value).ok();
}

// ---------------------------------------------------------------------------
// Flux d'installation
// ---------------------------------------------------------------------------

struct DeviceDetails {
    name: String,
    udid: String,
    ios_version: String,
    ios_major: u32,
}

async fn run_update(app: AppHandle) -> Result<(), Failure> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .user_agent("KospInjection/1.0")
        .build()
        .explain(
            "Impossible d'initialiser la connexion reseau",
            &["Redemarre l'application. Si ca persiste, redemarre le PC."],
        )?;

    // L'ordre compte : tout ce qui est verifiable sans reseau et sans
    // attente passe en premier. Ca evite de tirer 30 Mo d'IPA pour
    // decouvrir ensuite qu'aucun iPhone n'est branche — le cas le plus
    // frequent de tous.
    progress(&app, None);
    stage(&app, "drivers");
    ensure_apple_drivers(&app).await?;

    stage(&app, "device");
    status(&app, "Recherche de l'iPhone...");
    let provider = find_device(&app).await?;
    let device = probe_device(&app, &provider).await?;
    status(
        &app,
        format!("{} detecte (iOS {})", device.name, device.ios_version),
    );
    app.emit(
        "device",
        serde_json::json!({
            "name": device.name,
            "ios": device.ios_version,
        }),
    )
    .ok();

    stage(&app, "version");
    status(&app, "Recherche de la derniere version...");
    let source: AltStoreSource = http
        .get(SOURCE_URL)
        .send()
        .await
        .explain(
            "Impossible de joindre le serveur de mise a jour",
            &[
                "Verifie que le PC est connecte a Internet.",
                "Desactive VPN et pare-feu d'entreprise le temps de l'installation.",
                "Relance ensuite.",
            ],
        )?
        .error_for_status()
        .explain(
            "Le serveur de mise a jour a refuse la demande",
            &["Reessaie dans quelques minutes. Si ca persiste, previens le developpeur."],
        )?
        .json()
        .await
        .explain(
            "La liste des versions est illisible",
            &["Le fichier de versions publie est invalide. Previens le developpeur."],
        )?;

    let app_entry = source.apps.first().or_fail(
        "Aucune app publiee",
        &["La liste des versions ne declare aucune app. Previens le developpeur."],
    )?;
    // « Derniere version » = le plus grand buildVersion numerique, pas le
    // premier element de la liste — apps.json n'est pas garanti trie.
    let latest = app_entry
        .versions
        .iter()
        .max_by_key(|v| v.build_version.parse::<u64>().unwrap_or(0))
        .or_fail(
            "Aucune version publiee",
            &["L'app publiee ne declare aucune version. Previens le developpeur."],
        )?;

    stage(&app, "download");
    let ipa_path = download_ipa(&app, &http, latest).await?;

    stage(&app, "account");
    let keyring = KeyringStorage::new(KEYRING_SERVICE.to_string());
    let (mut account, apple_id, password) = login_flow(&app, &keyring).await?;

    status(&app, "Ouverture de la session developpeur Apple...");
    progress(&app, None);
    let mut dev_session = DeveloperSession::from_account(&mut account)
        .await
        .explain(
            "Impossible d'ouvrir la session developpeur Apple",
            &[
                "Connecte-toi une fois sur developer.apple.com avec ce compte et accepte les conditions.",
                "Relance ensuite l'installation.",
            ],
        )?;

    // Le mot de passe n'est enregistre qu'ici : une fois que la connexion
    // ET la session developpeur ont abouti. Enregistrer plus tot revient a
    // memoriser des identifiants qui ne marchent pas.
    save_account(&keyring, &apple_id, &password);

    let teams = dev_session.list_teams().await.explain(
        "Impossible de lire les equipes du compte Apple",
        &[
            "Verifie ta connexion Internet.",
            "Connecte-toi une fois sur developer.apple.com avec ce compte et accepte les conditions.",
        ],
    )?;
    let team = teams.into_iter().next().or_fail(
        "Ce compte Apple n'a pas d'equipe de developpement",
        &[
            "Connecte-toi une fois sur developer.apple.com avec ce compte et accepte les conditions.",
            "Relance ensuite l'installation.",
        ],
    )?;

    status(&app, "Enregistrement de l'iPhone sur le compte Apple...");
    dev_session
        .ensure_device_registered(
            &team,
            &device.name,
            &device.udid,
            None::<DeveloperDeviceType>,
        )
        .await
        .explain(
            "Impossible d'enregistrer l'iPhone sur le compte Apple",
            &[
                "Un compte Apple gratuit est limite a 100 appareils enregistres par an.",
                "Verifie la connexion Internet, puis relance.",
            ],
        )?;

    let sideloader_team = team.clone();
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
        *lock(&app_for_certs.state::<PendingInputs>().certs_tx) = Some(tx);
        app_for_certs.emit("need-certs", &options).ok();

        // La bibliotheque impose un callback synchrone : il faut donc
        // bloquer le thread. block_in_place previent tokio de sortir la
        // tache du pool le temps de l'attente, sinon les autres commandes
        // (dont submit_cert_choice, qui doit repondre ici) ne pourraient
        // plus s'executer.
        let selected = tokio::task::block_in_place(|| rx.recv().unwrap_or_default());
        if selected.is_empty() {
            None
        } else {
            Some(selected)
        }
    };

    let mut sideloader = SideloaderBuilder::new(dev_session, apple_id.clone())
        .team_selection(TeamSelection::First)
        .max_certs_behavior(MaxCertsBehavior::Prompt(Box::new(cert_selection_prompt)))
        .storage(Box::new(KeyringStorage::new(KEYRING_SERVICE.to_string())))
        .machine_name("twitninf-updater".to_string())
        .build();

    stage(&app, "sign");
    status(&app, "Signature de l'app...");
    progress(&app, Some(0.0));
    let app_for_sign = app.clone();
    let last_sign_pct = std::sync::Arc::new(AtomicU64::new(u64::MAX));
    let sign_cb = move |pct: f32| {
        let app = app_for_sign.clone();
        let last = last_sign_pct.clone();
        async move {
            // Un evenement par pourcent entier : la signature appelle ce
            // callback pour chaque sous-bundle, inutile de saturer la
            // WebView d'evenements qui rendent le meme pixel.
            let step = (pct * 100.0).clamp(0.0, 100.0) as u64;
            if last.swap(step, Ordering::Relaxed) != step {
                app.emit("progress", Some(pct)).ok();
            }
        }
    };

    let (signed_path, _special) = sideloader
        .sign_app(ipa_path, Some(sideloader_team), true, Some(sign_cb))
        .await
        .explain(
            "La signature de l'app a echoue",
            &[
                "Verifie ta connexion Internet (la signature dialogue avec Apple).",
                "Si le probleme persiste, essaie avec un autre compte Apple gratuit.",
            ],
        )?;

    // Le transfert dure souvent plus longtemps que la signature. La
    // bibliotheque expose sa progression uniquement si on appelle
    // l'installation nous-memes — sinon la barre resterait figee sans que
    // rien n'indique que ca avance encore.
    stage(&app, "install");
    status(&app, "Transfert vers l'iPhone...");
    progress(&app, Some(0.0));
    let app_for_install = app.clone();
    let last_install_pct = std::sync::Arc::new(AtomicU64::new(u64::MAX));
    let install_result = install::install_app(&provider, &signed_path, move |pct: u64| {
        let pct = pct.min(100);
        if last_install_pct.swap(pct, Ordering::Relaxed) != pct {
            app_for_install
                .emit("progress", Some(pct as f32 / 100.0))
                .ok();
            if pct >= 70 {
                app_for_install
                    .emit("status", "Installation sur l'iPhone...")
                    .ok();
            }
        }
    })
    .await;

    // Le dossier signe est un temporaire de plusieurs centaines de Mo :
    // on le retire meme quand l'installation a echoue.
    let _ = std::fs::remove_dir_all(&signed_path);

    install_result.explain(
        "L'installation sur l'iPhone a echoue",
        &[
            "Garde l'iPhone deverrouille, branche en USB, ecran allume.",
            "Verifie qu'il reste au moins 500 Mo de libre sur l'iPhone.",
            "Supprime l'ancienne version de TwitNinf sur l'iPhone, puis relance.",
        ],
    )?;

    progress(&app, Some(1.0));
    let mut next_steps = vec![
        "Sur l'iPhone : Reglages > General > VPN et gestion de l'appareil.".to_string(),
        format!("Ouvre le profil au nom de {apple_id}, puis touche « Faire confiance »."),
        "TwitNinf peut alors etre ouvert depuis l'ecran d'accueil.".to_string(),
    ];
    if device.ios_major >= 16 {
        next_steps.push(
            "Si l'app refuse de s'ouvrir : Reglages > Confidentialite et securite > Mode developpeur, active-le et redemarre l'iPhone."
                .to_string(),
        );
    }
    next_steps.push(
        "Avec un compte Apple gratuit, l'app doit etre reinstallee tous les 7 jours.".to_string(),
    );

    app.emit(
        "done",
        serde_json::json!({
            "title": format!("TwitNinf {} installe sur {}", latest.version, device.name),
            "steps": next_steps,
        }),
    )
    .ok();
    Ok(())
}

/// Trouve l'iPhone a utiliser. Distingue explicitement les trois cas que
/// l'utilisateur peut corriger : rien de branche, branche mais vu
/// uniquement par le Wi-Fi, plusieurs appareils a la fois.
async fn find_device(app: &AppHandle) -> Result<UsbmuxdProvider, Failure> {
    let mut usbmuxd = UsbmuxdConnection::default().await.explain(
        "Le service Apple ne repond plus",
        &[
            "Redemarre le PC, puis relance l'application.",
            "Si le probleme persiste, reinstalle « Apple Devices » depuis le Microsoft Store.",
        ],
    )?;
    let devices = usbmuxd.get_devices().await.explain(
        "Impossible de lister les appareils Apple",
        &[
            "Debranche puis rebranche l'iPhone.",
            "Redemarre le PC si le probleme persiste.",
        ],
    )?;

    let no_device_steps = [
        "Branche l'iPhone au PC avec un cable USB.",
        "Utilise un cable de donnees : beaucoup de cables ne servent qu'a charger.",
        "Branche-le sur un port USB du PC directement, sans hub ni station d'accueil.",
        "Deverrouille l'iPhone et laisse l'ecran allume.",
        "Quand l'iPhone demande « Se fier a cet ordinateur ? », touche « Se fier » et saisis ton code.",
        "Si rien ne se passe : debranche, rebranche, attends 5 secondes, puis relance.",
    ];

    if devices.is_empty() {
        return Err(Failure::new(
            "Aucun iPhone n'est branche en USB",
            &no_device_steps,
        ));
    }

    let usb: Vec<_> = devices
        .iter()
        .filter(|d| matches!(d.connection_type, Connection::Usb))
        .collect();

    if usb.is_empty() {
        // Vu par le Wi-Fi seulement : la synchronisation Wi-Fi permet de
        // lister l'appareil mais pas d'y installer une app signee.
        return Err(Failure::new(
            "L'iPhone est vu en Wi-Fi, pas en USB",
            &[
                "L'installation exige une liaison USB : le Wi-Fi ne suffit pas.",
                "Branche l'iPhone avec un cable de donnees, directement sur le PC.",
                "Deverrouille l'iPhone, puis relance l'installation.",
            ],
        ));
    }

    let chosen_udid = if usb.len() == 1 {
        usb[0].udid.clone()
    } else {
        // usbmuxd n'expose pas de nom lisible sans une connexion lockdown
        // supplementaire par appareil — l'UDID suffit pour distinguer les
        // appareils dans le rare cas ou plusieurs sont branches a la fois.
        let options: Vec<DeviceOption> = usb
            .iter()
            .map(|d| DeviceOption {
                name: format!("Appareil ...{}", &d.udid[d.udid.len().saturating_sub(8)..]),
                udid: d.udid.clone(),
                usb: true,
            })
            .collect();
        let (tx, rx) = oneshot::channel();
        *lock(&app.state::<PendingInputs>().device_tx) = Some(tx);
        app.emit("need-device", &options).ok();
        rx.await
            .map_err(|_| Failure::cancelled("Choix de l'appareil annule"))?
    };

    let device = devices
        .iter()
        .find(|d| d.udid == chosen_udid)
        .or_fail(
            "L'iPhone choisi n'est plus branche",
            &["Rebranche l'iPhone et relance l'installation."],
        )?;

    // .default() plutot que .from_env_var() : cette derniere ne peut
    // paniquer que si USBMUXD_SOCKET_ADDRESS est definie et malformee —
    // variable que personne ne positionne ici, autant retirer le risque.
    Ok(device.to_provider(UsbmuxdAddr::default(), "twitninf-updater"))
}

/// Verifie que l'iPhone est reellement exploitable — autorise pour ce PC,
/// deverrouille, joignable — avant d'aller plus loin, et recupere au
/// passage son nom et sa version d'iOS. Sans ce controle, le meme probleme
/// n'apparaitrait qu'apres le telechargement et la connexion Apple, sous
/// la forme d'une erreur de bibliotheque incomprehensible.
async fn probe_device(
    app: &AppHandle,
    provider: &UsbmuxdProvider,
) -> Result<DeviceDetails, Failure> {
    status(app, "Verification de l'iPhone...");

    let timeout_failure = || {
        Failure::new(
            "L'iPhone ne repond pas",
            &[
                "Deverrouille l'iPhone et laisse l'ecran allume.",
                "Regarde s'il affiche « Se fier a cet ordinateur ? » et touche « Se fier ».",
                "Debranche, rebranche, puis relance l'installation.",
            ],
        )
    };

    let probe = async {
        let mut lockdown = LockdownClient::connect(provider).await.explain(
            "Impossible de dialoguer avec l'iPhone",
            &[
                "Debranche puis rebranche l'iPhone.",
                "Utilise un cable de donnees, branche directement sur le PC.",
                "Deverrouille l'iPhone, puis relance.",
            ],
        )?;

        // Lisible sans session : c'est notre seul moyen de connaitre la
        // version d'iOS meme quand l'appareil n'est pas encore autorise.
        let ios_version = lockdown
            .get_value(Some("ProductVersion"), None)
            .await
            .ok()
            .and_then(|v| v.as_string().map(|s| s.to_string()))
            .unwrap_or_else(|| "inconnue".to_string());
        let ios_major = ios_version
            .split('.')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let pairing = provider.get_pairing_file().await.explain(
            "L'iPhone n'autorise pas encore ce PC",
            &[
                "Deverrouille l'iPhone et laisse-le branche en USB.",
                "Debranche puis rebranche le cable : la question « Se fier a cet ordinateur ? » doit apparaitre.",
                "Touche « Se fier » et saisis le code de l'iPhone.",
                "Relance ensuite l'installation.",
            ],
        )?;

        lockdown.start_session(&pairing).await.explain(
            "L'iPhone refuse la session",
            &[
                "Deverrouille l'iPhone : une session ne peut pas s'ouvrir sur un ecran verrouille.",
                "Debranche, rebranche, touche « Se fier » si la question apparait.",
                "Relance ensuite l'installation.",
            ],
        )?;

        let name = lockdown
            .get_value(Some("DeviceName"), None)
            .await
            .ok()
            .and_then(|v| v.as_string().map(|s| s.to_string()))
            .unwrap_or_else(|| "iPhone".to_string());

        let udid = lockdown
            .get_value(Some("UniqueDeviceID"), None)
            .await
            .ok()
            .and_then(|v| v.as_string().map(|s| s.to_string()))
            .or_fail(
                "L'iPhone n'a pas renvoye son identifiant",
                &[
                    "Debranche puis rebranche l'iPhone, deverrouille-le, et relance.",
                ],
            )?;

        Ok::<_, Failure>(DeviceDetails {
            name,
            udid,
            ios_version,
            ios_major,
        })
    };

    match tokio::time::timeout(DEVICE_TIMEOUT, probe).await {
        Ok(result) => result,
        Err(_) => Err(timeout_failure()),
    }
}

/// Telecharge l'IPA en suivant sa progression. En streaming plutot qu'en
/// un `.bytes()` unique : sur une connexion lente, un telechargement de
/// 30 Mo sans retour visuel passe pour un plantage.
async fn download_ipa(
    app: &AppHandle,
    http: &reqwest::Client,
    latest: &AltStoreVersion,
) -> Result<PathBuf, Failure> {
    status(
        app,
        format!(
            "Telechargement de la version {} (build {})...",
            latest.version, latest.build_version
        ),
    );
    progress(app, Some(0.0));

    let mut response = http
        .get(&latest.download_url)
        .send()
        .await
        .explain(
            "Le telechargement de l'app n'a pas demarre",
            &[
                "Verifie que le PC est connecte a Internet.",
                "Desactive VPN et pare-feu d'entreprise le temps du telechargement.",
                "Relance ensuite.",
            ],
        )?
        .error_for_status()
        .explain(
            "Le fichier de l'app est introuvable sur le serveur",
            &["La version publiee n'est pas telechargeable. Previens le developpeur."],
        )?;

    let total = response.content_length();
    let ipa_path = std::env::temp_dir().join("TwitNinf-latest.ipa");
    let mut file = std::fs::File::create(&ipa_path).explain(
        "Impossible d'ecrire le fichier temporaire",
        &[
            "Libere de l'espace sur le disque systeme (au moins 1 Go).",
            "Verifie qu'un antivirus ne bloque pas le dossier temporaire.",
        ],
    )?;

    let mut downloaded: u64 = 0;
    let mut last_pct = u64::MAX;
    loop {
        let chunk = response.chunk().await.explain(
            "Le telechargement a ete interrompu",
            &[
                "La connexion s'est coupee en cours de route.",
                "Verifie le reseau (Wi-Fi instable, VPN), puis relance.",
            ],
        )?;
        let Some(chunk) = chunk else { break };
        file.write_all(&chunk).explain(
            "Ecriture du telechargement impossible",
            &[
                "Libere de l'espace sur le disque systeme (au moins 1 Go).",
                "Verifie qu'un antivirus ne bloque pas le dossier temporaire.",
            ],
        )?;
        downloaded += chunk.len() as u64;

        if let Some(total) = total.filter(|t| *t > 0) {
            let pct = downloaded * 100 / total;
            if pct != last_pct {
                last_pct = pct;
                progress(app, Some(downloaded as f32 / total as f32));
                app.emit(
                    "status",
                    format!(
                        "Telechargement de la version {} — {:.1} / {:.1} Mo",
                        latest.version,
                        downloaded as f64 / 1_048_576.0,
                        total as f64 / 1_048_576.0
                    ),
                )
                .ok();
            }
        }
    }
    file.flush().ok();
    drop(file);

    // Un serveur qui coupe en plein transfert renvoie un fichier tronque,
    // et l'erreur n'apparaitrait qu'a la signature sous la forme d'un
    // « bundle invalide » qui n'aide personne.
    if let Some(total) = total.filter(|t| *t > 0) {
        if downloaded != total {
            return Err(Failure::new(
                "Le telechargement est incomplet",
                &[
                    "Le fichier recu est plus court que prevu : la connexion a lache.",
                    "Verifie le reseau, puis relance l'installation.",
                ],
            )
            .with_detail(format!("{downloaded} octets recus sur {total} attendus")));
        }
    }
    if downloaded < 4096 || !starts_with_zip_magic(&ipa_path) {
        return Err(Failure::new(
            "Le fichier telecharge n'est pas une app valide",
            &[
                "Le serveur a renvoye autre chose qu'un IPA (page d'erreur, portail Wi-Fi...).",
                "Deconnecte-toi de tout portail captif, puis relance.",
            ],
        ));
    }

    Ok(ipa_path)
}

/// Un IPA est une archive ZIP : les deux premiers octets valent "PK". Le
/// test attrape le cas ou un portail Wi-Fi captif renvoie une page HTML a
/// la place du fichier.
fn starts_with_zip_magic(path: &std::path::Path) -> bool {
    use std::io::Read as _;
    let mut buf = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
        && &buf == b"PK"
}

/// Connexion au compte Apple, avec reprise sur mot de passe refuse.
///
/// Le point sensible : quand un seul compte est enregistre, le mot de
/// passe memorise est utilise sans rien demander. S'il a change depuis
/// (ou s'il a ete mal saisi la premiere fois), il n'existait aucun moyen
/// de le corriger — l'app echouait a chaque lancement sur le meme message.
/// D'ou la boucle : un refus d'identifiants redemande la saisie, en
/// pre-remplissant l'adresse et en expliquant pourquoi.
async fn login_flow(
    app: &AppHandle,
    keyring: &KeyringStorage,
) -> Result<(AppleAccount, String, String), Failure> {
    let mut saved_choice = choose_saved_account(app, keyring).await?;
    let mut prefill: Option<String> = None;
    let mut note: Option<String> = None;
    let mut attempts = 0usize;

    loop {
        attempts += 1;
        if attempts > MAX_LOGIN_ATTEMPTS {
            return Err(Failure::new(
                "Trop de tentatives de connexion",
                &[
                    "Apple bloque temporairement un compte apres plusieurs mots de passe errones.",
                    "Verifie le mot de passe sur account.apple.com, puis relance l'application.",
                ],
            ));
        }

        let current_note = note.take();
        let (apple_id, password) = match saved_choice.take() {
            Some(id) => match get_saved_password(keyring, &id) {
                Some(pw) => (id, pw),
                // Le compte est dans la liste mais son mot de passe a
                // disparu du trousseau (entree supprimee a la main,
                // profil Windows recree...). On redemande au lieu de
                // s'arreter sur une impasse.
                None => {
                    ask_credentials(
                        app,
                        Some(&id),
                        Some("Le mot de passe enregistre pour ce compte est introuvable."),
                    )
                    .await?
                }
            },
            None => ask_credentials(app, prefill.as_deref(), current_note.as_deref()).await?,
        };

        status(app, "Connexion au compte Apple...");
        progress(app, None);
        match try_login(app, &apple_id, &password).await {
            Ok(account) => return Ok((account, apple_id, password)),
            Err(f) if f.retry_credentials => {
                note = Some(f.title.clone());
                prefill = Some(apple_id);
            }
            Err(f) => return Err(f),
        }
    }
}

/// Un seul compte connu : connexion directe avec le mot de passe
/// enregistre, aucune fenetre a montrer. Plusieurs : selecteur rapide
/// (avec une option "ajouter un compte"). Aucun : ecran de saisie
/// classique, comme au tout premier lancement.
async fn choose_saved_account(
    app: &AppHandle,
    keyring: &KeyringStorage,
) -> Result<Option<String>, Failure> {
    let accounts = list_accounts(keyring);
    match accounts.len() {
        0 => Ok(None),
        1 => Ok(Some(accounts[0].clone())),
        _ => {
            let (tx, rx) = oneshot::channel();
            *lock(&app.state::<PendingInputs>().account_tx) = Some(tx);
            app.emit("need-account", &accounts).ok();
            rx.await
                .map_err(|_| Failure::cancelled("Choix du compte annule"))
        }
    }
}

async fn ask_credentials(
    app: &AppHandle,
    prefill: Option<&str>,
    note: Option<&str>,
) -> Result<(String, String), Failure> {
    let (tx, rx) = oneshot::channel();
    *lock(&app.state::<PendingInputs>().credentials_tx) = Some(tx);
    app.emit(
        "need-password",
        serde_json::json!({ "appleId": prefill, "note": note }),
    )
    .ok();
    rx.await
        .map_err(|_| Failure::cancelled("Saisie des identifiants annulee"))
}

async fn try_login(
    app: &AppHandle,
    apple_id: &str,
    password: &str,
) -> Result<AppleAccount, Failure> {
    let app_for_2fa = app.clone();
    let get_2fa_code = move |params: TwoFactorCallbackParams| wait_2fa(app_for_2fa.clone(), params);

    let anisette = RemoteV3AnisetteProvider::default()
        .explain(
            "Le service d'authentification Apple est injoignable",
            &[
                "C'est un service externe, parfois indisponible quelques minutes.",
                "Verifie ta connexion Internet, puis reessaie.",
            ],
        )?
        .set_serial_number("twitninf-updater".to_string())
        // KeyringStorage (pas InMemoryStorage) : la lib persiste
        // l'etat anisette sous "anisette_state", perdu a chaque
        // fermeture avec un stockage en memoire — c'est ce qui
        // faisait redemander un code 2FA a chaque lancement.
        .set_storage(Box::new(KeyringStorage::new(KEYRING_SERVICE.to_string())));

    AppleAccount::builder(apple_id)
        .anisette_provider(anisette)
        .login(password, get_2fa_code)
        .await
        .explain(
            "Connexion au compte Apple impossible",
            &[
                "Verifie l'adresse du compte Apple et le mot de passe.",
                "Assure-toi que la double authentification est active sur ce compte.",
                "Verifie ta connexion Internet, puis reessaie.",
            ],
        )
        // Un refus au moment de la connexion vaut presque toujours
        // « identifiants a resaisir » : sans ca, un mot de passe memorise
        // devenu obsolete condamnerait l'app a echouer indefiniment.
        .map_err(|f| if f.cancelled { f } else { f.retryable() })
}

/// Demande le code 2FA a l'UI. `params.unknown` signale qu'Apple n'a pas
/// dit quelle methode utiliser : dans cet etat, envoyer un code fait
/// echouer la connexion cote bibliotheque, il faut d'abord choisir un
/// canal. L'UI recoit donc de quoi afficher soit la saisie de code, soit
/// le choix du canal.
async fn wait_2fa(
    app: AppHandle,
    params: TwoFactorCallbackParams,
) -> std::result::Result<TwoFactorCallbackResponse, rootcause::Report> {
    use rootcause::prelude::ResultExt;

    let numbers: Vec<serde_json::Value> = params
        .numbers
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": n.id,
                "label": if n.number_with_dial_code.is_empty() {
                    format!("Numero se terminant par {}", n.last_two_digits)
                } else {
                    n.number_with_dial_code.clone()
                },
            })
        })
        .collect();

    // Le message brut d'Apple ("-21669 - Incorrect verification code.")
    // n'a pas sa place a l'ecran : on le repasse par le meme traducteur
    // que les erreurs fatales pour afficher une phrase utile.
    let error = params.last_error.as_deref().map(|e| {
        classify(e)
            .map(|f| f.title)
            .unwrap_or_else(|| "Le code precedent n'a pas ete accepte.".to_string())
    });

    let (tx, rx) = oneshot::channel();
    *lock(&app.state::<PendingInputs>().twofa_tx) = Some(tx);
    app.emit(
        "need-2fa",
        serde_json::json!({
            "unknown": params.unknown,
            "sms": params.sms,
            "numbers": numbers,
            "error": error,
        }),
    )
    .ok();
    Ok(rx.await.context("saisie du code de verification annulee")?)
}

// ---------------------------------------------------------------------------
// Prerequis Windows
// ---------------------------------------------------------------------------

/// Teste si un service Windows existe, quel que soit son etat.
fn windows_service_exists(name: &str) -> bool {
    std::process::Command::new("sc")
        .args(["query", name])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
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
async fn ensure_apple_drivers(app: &AppHandle) -> Result<(), Failure> {
    status(app, "Verification des composants Apple...");
    if UsbmuxdConnection::default().await.is_ok() {
        return Ok(());
    }

    // Distinction indispensable : pilotes absents (il faut installer) ou
    // pilotes presents mais service arrete (il faut le demarrer). Proposer
    // une installation de 150 Mo a quelqu'un dont le service est
    // simplement arrete envoie sur une fausse piste.
    const SERVICE: &str = "Apple Mobile Device Service";
    if windows_service_exists(SERVICE) {
        status(app, "Demarrage du service Apple...");
        let started = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Start-Service -Name '{SERVICE}'"),
            ])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);

        if started && UsbmuxdConnection::default().await.is_ok() {
            return Ok(());
        }
        return Err(Failure::new(
            "Le service Apple est installe mais arrete",
            &[
                "Ouvre « Services » depuis le menu Demarrer.",
                "Trouve « Apple Mobile Device Service », clic droit > Demarrer.",
                "Si le demarrage echoue, redemarre le PC et relance l'application.",
            ],
        ));
    }

    let (tx, rx) = oneshot::channel();
    *lock(&app.state::<PendingInputs>().confirm_tx) = Some(tx);
    app.emit(
        "need-prereqs",
        serde_json::json!({
            "message": "Les pilotes Apple (Apple Mobile Device Service) ne sont pas installes sur ce PC.",
            "detail": "Sans eux, Windows ne peut pas parler a l'iPhone. Installer « Apple Mobile Device Support » via WinGet (~150 Mo, telecharge depuis apple.com) ?",
        }),
    )
    .ok();
    let confirmed = rx
        .await
        .map_err(|_| Failure::cancelled("Installation des pilotes annulee"))?;
    if !confirmed {
        return Err(Failure::new(
            "Les pilotes Apple sont indispensables",
            &[
                "Sans les pilotes Apple, Windows ne detecte pas l'iPhone.",
                "Relance l'installation et accepte l'installation des pilotes,",
                "ou installe « Apple Devices » depuis le Microsoft Store puis relance.",
            ],
        ));
    }

    ensure_winget(app).await?;

    status(
        app,
        "Installation d'Apple Mobile Device Support (autorise l'invite Windows si elle apparait)...",
    );
    let status_code = tokio::process::Command::new("winget")
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
        .explain(
            "WinGet n'a pas pu etre lance",
            &[
                "Installe « Apple Devices » depuis le Microsoft Store.",
                "Redemarre ensuite le PC et relance l'application.",
            ],
        )?;
    if !status_code.success() {
        return Err(Failure::new(
            "L'installation des pilotes Apple a echoue",
            &[
                "Une invite Windows a peut-etre ete refusee : relance et accepte-la.",
                "Sinon, installe « Apple Devices » depuis le Microsoft Store.",
                "Redemarre le PC apres l'installation, puis relance l'application.",
            ],
        ));
    }

    status(app, "Verification des pilotes Apple...");
    UsbmuxdConnection::default().await.explain(
        "Les pilotes Apple ne repondent toujours pas",
        &[
            "Redemarre le PC : les pilotes ne sont actifs qu'apres un redemarrage.",
            "Relance ensuite l'application.",
        ],
    )?;
    Ok(())
}

/// WinGest est absent sur certaines images minimales (constate sous Windows
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
async fn ensure_winget(app: &AppHandle) -> Result<(), Failure> {
    let present = tokio::process::Command::new("winget")
        .arg("--version")
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if present {
        return Ok(());
    }

    status(app, "Installation de WinGet et de ses dependances...");
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
    let status_code = tokio::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .await
        .explain(
            "PowerShell n'a pas pu etre lance",
            &[
                "Installe « Apple Devices » depuis le Microsoft Store.",
                "Redemarre le PC, puis relance l'application.",
            ],
        )?;
    if !status_code.success() {
        return Err(Failure::new(
            "WinGet n'a pas pu etre installe sur ce PC",
            &[
                "Installe « Apple Devices » depuis le Microsoft Store : ca suffit a faire fonctionner l'app.",
                "Redemarre le PC apres l'installation, puis relance l'application.",
            ],
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WebView2 et demarrage
// ---------------------------------------------------------------------------

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

fn log_path() -> PathBuf {
    std::env::temp_dir().join(LOG_FILE)
}

/// Journal sur disque : sans fenetre console en release, c'est le seul
/// moyen pour un testeur de renvoyer autre chose que « ca marche pas ».
/// L'UI affiche le chemin et propose de l'ouvrir depuis l'ecran d'erreur.
fn init_logging() {
    let path = log_path();
    // Repart d'un fichier vide a chaque lancement : le journal doit
    // decrire la session en cours, pas l'accumulation de toutes.
    let _ = std::fs::write(&path, b"");
    let writer = move || -> Box<dyn std::io::Write> {
        match std::fs::OpenOptions::new().append(true).open(&path) {
            Ok(f) => Box::new(f),
            Err(_) => Box::new(std::io::sink()),
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(writer)
        .try_init();
}

fn main() {
    ensure_webview2();
    init_logging();

    // install_default() n'echoue que si un fournisseur est deja installe,
    // ce qui n'est pas un probleme : les bibliotheques en aval en
    // installent un elles-memes si besoin. Paniquer ici tuait l'app avant
    // meme d'avoir une fenetre pour dire pourquoi.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if let Err(e) = isideload::init() {
        tracing::warn!("rapport d'erreurs non initialise: {e}");
    }

    tauri::Builder::default()
        .manage(PendingInputs::default())
        .invoke_handler(tauri::generate_handler![
            start_update,
            submit_cancel,
            submit_confirm,
            submit_device,
            submit_account_choice,
            submit_credentials,
            submit_2fa,
            submit_cert_choice,
            forget_account,
            list_saved_accounts,
            open_log,
            log_file_path,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de l'application Tauri");
}
