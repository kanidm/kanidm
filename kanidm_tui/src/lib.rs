use tracing::error;

use crossterm::{
    event::{self,Event as CEvent},
    terminal::{disable_raw_mode, enable_raw_mode,},
};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{io, thread};
use tui::{
    backend::Backend,
    backend::CrosstermBackend,
};
use app::{App,MenuTitle,Event};
mod ui;
mod app;
mod messages;

/// App holds the state of the TUI application

pub struct KanidmTUI{
}

impl KanidmTUI{
    pub fn debug(&self) -> bool {
        //self.copt.debug
        false
    }

    pub fn exec(&self) {
        println!("Kanidm TUI is loading");
        match get_stdout() {
            Ok(stdout) => {
                enable_raw_mode().expect("Could not enabling raw mod");
                let terminal_backend = CrosstermBackend::new(stdout);
                self.start(terminal_backend);
            }
            Err(_) => error!("Failed to get stdout: are you trying to pipe 'kanidm tui'?"),
        }
        disable_raw_mode().expect("Could not disabl raw mode");
    }
    pub fn default()-> KanidmTUI{
        KanidmTUI{
        }

    }

    fn start<B>(&self, terminal_backend: B)
    where
        B: Backend + Send + 'static,
    {
        let mut app = App::new(terminal_backend);
        app.active_menu_item = MenuTitle::Home;
        let (tx, rx) = mpsc::channel();
        let refresh_rate = Duration::from_secs(10);
        thread::spawn(move || loop {
            app.last_refresh = Instant::now();
            let timeout = refresh_rate
                .checked_sub(app.last_refresh.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            if event::poll(timeout).expect("Could not poll events") {
                if let CEvent::Key(key) = event::read().expect("Could not read crossterm event") {
                    tx.send(Event::Input(key))
                        .expect("Could not send crossterm event");
                }
            }
            if app.last_refresh.elapsed() >= refresh_rate {
                if let Ok(_) = tx.send(Event::Refresh) {
                    app.last_refresh = Instant::now();
                }
            }
        });
        //let mut terminal = Terminal::new(terminal_backend).expect("Could not create terminal");
        //terminal.clear().expect("failed to clear terminal");
        //terminal.hide_cursor().expect("failed to hide cursor");
        app.start(rx);
        disable_raw_mode().expect("Could not disable raw mode");
        
    }

}




fn get_stdout() -> io::Result<io::Stdout> {
    Ok(io::stdout())
}
