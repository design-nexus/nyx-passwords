//! Nyx Passwords: the window. The vault itself lives in `nyx-passwordsd`.

mod app;
mod dialog_dismissal;

use gtk::{gio, glib, prelude::*};

fn main() -> glib::ExitCode {
    nyx_core::app::init(nyx_passwords::daemon::APP);
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|s| s == "--help" || s == "-h") {
        println!(
            "Usage: nyx-passwords [--unlock] [--section all|favorites|recent|login|note|card|identity|trash|settings] [--item ID]"
        );
        return glib::ExitCode::SUCCESS;
    }
    if std::env::var_os("GSK_RENDERER").is_none() {
        // SAFETY: set before any thread starts.
        unsafe { std::env::set_var("GSK_RENDERER", "ngl") };
    }
    // NYX_PASSWORDS_APP_ID runs a test copy beside the real one (its own window class).
    // Dialogs are windows outside the application and take their class from the program
    // name, so the test copy's carry its class too.
    if let Ok(test) = std::env::var("NYX_PASSWORDS_APP_ID") {
        glib::set_prgname(Some(test.as_str()));
    }
    let id = std::env::var("NYX_PASSWORDS_APP_ID").unwrap_or_else(|_| "io.github.design_nexus.nyx.Passwords".into());
    nyx_core::control::describe_if_asked(&app::control::description(&id));
    // D-Bus starts Passwords with --gapplication-service for a call from nyx, Glimpse or
    // Nyx Assistant (status, lock): no window, and it quits once idle. GLib won't parse
    // the flag for apps that handle their own command line.
    let mut args = args;
    let service = args.iter().any(|a| a == "--gapplication-service");
    args.retain(|a| a != "--gapplication-service");
    let mut flags = gio::ApplicationFlags::HANDLES_COMMAND_LINE;
    if service {
        flags |= gio::ApplicationFlags::IS_SERVICE;
    }
    let app = gtk::Application::builder().application_id(id).flags(flags).build();
    app.connect_startup(move |app| {
        app::control::serve(app);
        if service {
            app.set_inactivity_timeout(10_000);
        }
    });
    app.connect_command_line(|app, cl| {
        let argv: Vec<String> = cl.arguments().iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let section = argv.iter().position(|s| s == "--section").and_then(|i| argv.get(i + 1)).cloned();
        let item = argv.iter().position(|s| s == "--item").and_then(|i| argv.get(i + 1)).cloned();
        // --approve (from the daemon): only the approval card, not the main window.
        if argv.iter().any(|s| s == "--approve") {
            app::approve::open(app);
            return glib::ExitCode::SUCCESS;
        }
        // --unlock (from Glimpse) just brings the window up: it opens on the unlock page
        // while the vault is locked.
        let ui = app::ui::present(app, section.as_deref());
        if let Some(id) = item {
            app::ui::open_item(&ui, &id);
        }
        glib::ExitCode::SUCCESS
    });
    app.connect_shutdown(|_| app::prefs::flush());
    app.run_with_args(&args)
}
