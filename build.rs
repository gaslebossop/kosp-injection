fn main() {
    // Le manifeste par defaut de Tauri ne declare ni compatibilite Windows
    // 10/11 ni conscience de la mise a l'echelle : voir les commentaires du
    // fichier XML pour le detail de ce que corrige le notre.
    println!("cargo:rerun-if-changed=windows-app-manifest.xml");
    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows-app-manifest.xml"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("compilation des ressources Tauri impossible");
}
