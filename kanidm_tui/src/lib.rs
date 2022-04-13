use compact_jwt::JwsUnverified;
use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::{AuthAllowed, AuthResponse, AuthState, UserAuthToken};
#[cfg(target_family = "unix")]
use libc::umask;
use std::collections::BTreeMap;
use std::fs::{create_dir, File};
use std::io::ErrorKind;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{debug, error, warn};
use webauthn_authenticator_rs::{u2fhid::U2FHid, RequestChallengeResponse, WebauthnAuthenticator};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{io, thread};
use structopt::StructOpt;
use tui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Tabs},
    Terminal,
};
use unicode_width::UnicodeWidthStr;

static TOKEN_DIR: &str = "~/.cache";
static TOKEN_PATH: &str = "~/.cache/kanidm_tokens";

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug", env = "KANIDM_DEBUG")]
    pub debug: bool,
    #[structopt(short = "H", long = "url", env = "KANIDM_URL")]
    pub addr: Option<String>,
    #[structopt(short = "D", long = "name", env = "KANIDM_NAME")]
    pub username: Option<String>,
    #[structopt(parse(from_os_str), short = "C", long = "ca", env = "KANIDM_CA_PATH")]
    pub ca_path: Option<PathBuf>,
    //This is used in kanidm tui no need to prompt for password
    #[structopt(short = "p", long = "password", env = "KANIDM_PASS")]
    pub password: Option<String>,
}
#[derive(Debug, StructOpt)]
struct LoginOpt {
    #[structopt(flatten)]
    copt: CommonOpt,
    // TODO adding webauthn
    //#[structopt(short = "w", long = "webauthn")]
    //webauthn: bool,
}
enum Event<T> {
    Input(T),
    Refresh,
}
#[derive(Copy, Clone, Debug)]
enum MenuTitle {
    Home,
    Login,
}
impl From<MenuTitle> for usize {
    fn from(input: MenuTitle) -> usize {
        match input {
            MenuTitle::Home => 0,
            MenuTitle::Login => 1,
        }
    }
}
#[derive(Copy, Clone, Debug)]
enum InputMode {
    Normal,
    EnterUser,
    EnterPass,
}

/// KanidmTUI holds the state of the TUI application
pub struct KanidmTUI {
    username: String,
    password: String,
    masked_password: String,
    /// Current input mode
    input_mode: InputMode,
    active_menu_item: MenuTitle,
    last_refresh: Instant,
    copt: CommonOpt,
}
impl Default for KanidmTUI {
    fn default() -> KanidmTUI {
        KanidmTUI {
            username: String::new(),
            password: String::new(),
            masked_password: String::new(),
            input_mode: InputMode::Normal,
            active_menu_item: MenuTitle::Home,
            last_refresh: Instant::now(),
            //TODO Fix this
            copt: CommonOpt {
                debug: false,
                addr: None,
                username: Some(String::new()),
                ca_path: None,
                password: Some(String::new()),
            },
        }
    }
}
impl KanidmTUI {
    pub fn debug(&self) -> bool {
        //self.copt.debug
        false
    }

    pub fn exec(&self) {
        println!("Kanidm TUI is loading");
        let mut kanidm_tui = KanidmTUI::default();
        kanidm_tui.active_menu_item = MenuTitle::Home;
        let mut login_list_state = ListState::default();
        login_list_state.select(Some(0));

        let (tx, rx) = mpsc::channel();
        let refresh_rate = Duration::from_secs(10);
        thread::spawn(move || loop {
            kanidm_tui.last_refresh = Instant::now();
            let timeout = refresh_rate
                .checked_sub(kanidm_tui.last_refresh.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            if event::poll(timeout).expect("Could not poll events") {
                if let CEvent::Key(key) = event::read().expect("Could not read crossterm event") {
                    tx.send(Event::Input(key))
                        .expect("Could not send crossterm event");
                }
            }
            if kanidm_tui.last_refresh.elapsed() >= refresh_rate {
                if let Ok(_) = tx.send(Event::Refresh) {
                    kanidm_tui.last_refresh = Instant::now();
                }
            }
        });
        // Setup terminal
        enable_raw_mode().expect("Could not enabling raw mod");
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .expect("Could not capture stdout");
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).expect("Could not create terminal");

        loop {
            terminal
                .draw(|f| {
                    let chunk = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(
                            [
                                Constraint::Length(3),
                                Constraint::Length(1),
                                Constraint::Min(3),
                                Constraint::Length(3),
                            ]
                            .as_ref(),
                        )
                        .split(f.size());

                    let status_block = Block::default().title("Server").borders(Borders::ALL);
                    f.render_widget(render_titles(kanidm_tui.active_menu_item), chunk[0]);

                    let main_chunk = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(
                            [Constraint::Percentage(80), Constraint::Percentage(20)].as_ref(),
                        )
                        .split(chunk[2]);
                    match kanidm_tui.active_menu_item {
                        MenuTitle::Home => {
                            f.render_widget(render_home(), main_chunk[0]);
                            let help_message = Paragraph::new(vec![Spans::from(vec![Span::raw(
            "You can see list of Logins at the right pane, If it is empty press 'L' to login ",
        )])]);
                            f.render_widget(help_message, chunk[1]);
                        }
                        MenuTitle::Login => {
                            let login_block_chunk = Layout::default()
                                .direction(Direction::Vertical)
                                .constraints(
                                    [
                                        Constraint::Length(3),
                                        Constraint::Length(3),
                                        Constraint::Min(3),
                                    ]
                                    .as_ref(),
                                )
                                .split(main_chunk[0]);
                            let (user_block, pass_block) = render_login_inputs(&kanidm_tui);
                            let (msg, style) = match kanidm_tui.input_mode {
                                InputMode::Normal => {
                                    (vec![], Style::default().add_modifier(Modifier::RAPID_BLINK))
                                }
                                _ => (
                                    vec![
                                        Span::raw("Press "),
                                        Span::styled(
                                            "Esc",
                                            Style::default().add_modifier(Modifier::BOLD),
                                        ),
                                        Span::raw(" to stop editing, "),
                                        Span::styled(
                                            "Enter",
                                            Style::default().add_modifier(Modifier::BOLD),
                                        ),
                                        Span::raw(" login to server"),
                                    ],
                                    Style::default(),
                                ),
                            };
                            let mut text = Text::from(Spans::from(msg));
                            text.patch_style(style);
                            let help_message = Paragraph::new(text);
                            f.render_widget(help_message, chunk[1]);
                            f.render_widget(user_block, login_block_chunk[0]);
                            f.render_widget(pass_block, login_block_chunk[1]);
                            match kanidm_tui.input_mode {
                                InputMode::Normal => {}
                                InputMode::EnterUser => {
                                    // Make the cursor visible and ask tui-rs to put it at the specified coordinates after rendering
                                    f.set_cursor(
                                        // Put cursor past the end of the input text
                                        login_block_chunk[0].x
                                            + kanidm_tui.username.width() as u16
                                            + 1,
                                        // Move one line down, from the border to the input line
                                        login_block_chunk[0].y + 1,
                                    )
                                }
                                InputMode::EnterPass => {
                                    // Same as username but we use masked_password
                                    f.set_cursor(
                                        login_block_chunk[1].x
                                            + kanidm_tui.masked_password.width() as u16
                                            + 1,
                                        login_block_chunk[1].y + 1,
                                    )
                                }
                            }
                        }
                    }
                    f.render_stateful_widget(
                        render_logins_block(),
                        main_chunk[1],
                        &mut login_list_state,
                    );
                    f.render_widget(status_block, chunk[3]);
                })
                .expect("Could not draw to terminal");
            match kanidm_tui.input_mode {
                InputMode::Normal => {
                    match rx.recv().expect("Could not receive from channel") {
                        Event::Input(event) => match event.code {
                            // Restore Terminal
                            KeyCode::Char('q') => {
                                disable_raw_mode().expect("Could not disabl raw mode");
                                execute!(
                                    terminal.backend_mut(),
                                    LeaveAlternateScreen,
                                    DisableMouseCapture,
                                )
                                .expect("Could not leave screen");
                                terminal.show_cursor().expect("Could not show cursor");
                                break;
                            }
                            KeyCode::Char('c') => {
                                let selected = login_list_state
                                    .selected()
                                    .expect("Could not get selected login");
                                if selected == get_logins().len() - 1 {
                                    login_list_state.select(Some(0));
                                } else {
                                    login_list_state.select(Some(selected + 1));
                                }
                            }
                            KeyCode::Char('l') => {
                                kanidm_tui.active_menu_item = MenuTitle::Login;
                                kanidm_tui.input_mode = InputMode::EnterUser;
                            }
                            KeyCode::Char('h') => kanidm_tui.active_menu_item = MenuTitle::Home,
                            _ => {}
                        },
                        Event::Refresh => {
                            self.cleanup();
                        }
                    }
                }
                InputMode::EnterUser => match rx.recv().expect("Could not receive from channel") {
                    Event::Input(event) => match event.code {
                        KeyCode::Tab => kanidm_tui.input_mode = InputMode::EnterPass,
                        KeyCode::Char(c) => {
                            kanidm_tui.username.push(c);
                        }
                        KeyCode::Backspace => {
                            kanidm_tui.username.pop();
                        }
                        KeyCode::Esc => {
                            kanidm_tui.username = "".to_string();
                            kanidm_tui.password = "".to_string();
                            kanidm_tui.masked_password = "".to_string();
                            kanidm_tui.input_mode = InputMode::Normal;
                            kanidm_tui.active_menu_item = MenuTitle::Home;
                        }
                        KeyCode::Enter => {
                            kanidm_tui.input_mode = InputMode::EnterPass;
                        }

                        _ => {}
                    },
                    Event::Refresh => {
                        self.cleanup();
                    }
                },
                InputMode::EnterPass => match rx.recv().expect("Could not receive from channel") {
                    Event::Input(event) => match event.code {
                        KeyCode::Tab => kanidm_tui.input_mode = InputMode::EnterUser,
                        KeyCode::Char(c) => {
                            kanidm_tui.password.push(c);
                            kanidm_tui.masked_password.push('*');
                        }
                        KeyCode::Backspace => {
                            kanidm_tui.password.pop();
                            kanidm_tui.masked_password.pop();
                        }
                        KeyCode::Esc => {
                            kanidm_tui.username = "".to_string();
                            kanidm_tui.password = "".to_string();
                            kanidm_tui.input_mode = InputMode::Normal;
                            kanidm_tui.active_menu_item = MenuTitle::Home;
                        }
                        KeyCode::Enter => {
                            self.login_to_server(&kanidm_tui);
                            kanidm_tui.username = "".to_string();
                            kanidm_tui.password = "".to_string();
                            kanidm_tui.masked_password = "".to_string();
                            kanidm_tui.input_mode = InputMode::Normal;
                            kanidm_tui.active_menu_item = MenuTitle::Home;
                        }

                        _ => {}
                    },
                    Event::Refresh => {
                        self.cleanup();
                    }
                },
            }
        }
    }
    fn login_to_server(&self, kanidm_tui: &KanidmTUI) {
        let copt = CommonOpt {
            debug: self.copt.debug.clone(),
            addr: self.copt.addr.clone(),
            username: Some(kanidm_tui.username.clone()),
            ca_path: self.copt.ca_path.clone(),
            password: Some(kanidm_tui.password.clone()),
        };
        let login = LoginOpt {
            copt: copt,
            // TODO add webauthn
            //webauthn: false,
        };
        login.exec();
    }
    fn cleanup(&self) {
        let tokens = read_valid_tokens();

        let now = time::OffsetDateTime::now_utc();

        let tokens: BTreeMap<_, _> = tokens
            .into_iter()
            .filter_map(|(u, (t, uat))| {
                if now >= uat.expiry {
                    //Expired
                    None
                } else {
                    Some((u, t))
                }
            })
            .collect();
        if let Err(_e) = write_tokens(&tokens) {
            error!("Error persisting authentication token store");
            std::process::exit(1);
        };
    }
}
fn render_home<'a>() -> Paragraph<'a> {
    let home = Paragraph::new(vec![
        Spans::from(vec![Span::raw("")]),
        Spans::from(vec![Span::styled(
            "Kanidm TUI",
            Style::default().fg(Color::Red),
        )]),
        Spans::from(vec![Span::raw("")]),
        Spans::from(vec![Span::raw(
            "Kanidm is a modern and simple identity management platform written in rust.",
        )]),
    ])
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White))
            .title("Home")
            .border_type(BorderType::Plain),
    );
    home
}
fn render_login_inputs(kanidm_tui: &KanidmTUI) -> (Paragraph, Paragraph) {
    let username = Paragraph::new(kanidm_tui.username.as_ref())
        .style(match kanidm_tui.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::EnterUser => Style::default().fg(Color::Yellow),
            InputMode::EnterPass => Style::default(),
        })
        .block(Block::default().borders(Borders::ALL).title("Username"));
    let password = Paragraph::new(kanidm_tui.masked_password.as_ref())
        .style(match kanidm_tui.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::EnterPass => Style::default().fg(Color::Yellow),
            InputMode::EnterUser => Style::default(),
        })
        .block(Block::default().borders(Borders::ALL).title("Password"));

    (username, password)
}
fn render_logins_block<'a>() -> List<'a> {
    let logins = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::White))
        .title("Press 'c' To change Logins")
        .border_type(BorderType::Plain);

    let login_list = get_logins();
    let items: Vec<_> = login_list
        .iter()
        .map(|login| {
            ListItem::new(Spans::from(vec![Span::styled(
                get_login_name(login).clone(),
                Style::default(),
            )]))
        })
        .collect();
    let login_list_block = List::new(items).block(logins).highlight_style(
        Style::default()
            .bg(Color::Yellow)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    );
    login_list_block
}
fn render_titles<'a>(active_menu_item: MenuTitle) -> Tabs<'a> {
    // TODO Suggestion: Menu should cover these:
    // let menu_titles = vec!["Login","Logout","Account", "Group", "Recycle_bin","Session","System","Add", "Delete", "Quit"];
    let menu_titles = vec!["Home", "Login", "Quit"];
    let menu = menu_titles
        .iter()
        .map(|t| {
            let (first, rest) = t.split_at(1);
            Spans::from(vec![
                Span::styled(
                    first,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::UNDERLINED),
                ),
                Span::styled(rest, Style::default().fg(Color::White)),
            ])
        })
        .collect();

    let tabs = Tabs::new(menu)
        .select(active_menu_item.into())
        .block(
            Block::default()
                .title("Kanidm Manager")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Yellow))
        .divider(Span::raw("|"));
    tabs
}

fn get_logins() -> BTreeMap<String, (String, UserAuthToken)> {
    let tokens = read_valid_tokens();
    tokens
}
fn get_login_name(login: (&std::string::String, &(std::string::String, UserAuthToken))) -> String {
    let (name, _) = login;
    name.to_string()
}
impl LoginOpt {
    fn do_password(
        &self,
        client: &mut KanidmClient,
        password: String,
    ) -> Result<AuthResponse, ClientError> {
        client.auth_step_password(password.as_str())
    }

    fn do_backup_code(&self, client: &mut KanidmClient) -> Result<AuthResponse, ClientError> {
        print!("Enter Backup Code: ");
        // We flush stdout so it'll write the buffer to screen, continuing operation. Without it, the application halts.
        #[allow(clippy::unwrap_used)]
        io::stdout().flush().unwrap();
        let mut backup_code = String::new();
        loop {
            if let Err(e) = io::stdin().read_line(&mut backup_code) {
                error!("Failed to read from stdin -> {:?}", e);
                return Err(ClientError::SystemError);
            };
            if !backup_code.trim().is_empty() {
                break;
            };
        }
        client.auth_step_backup_code(backup_code.trim())
    }

    fn do_totp(&self, client: &mut KanidmClient) -> Result<AuthResponse, ClientError> {
        let totp = loop {
            print!("Enter TOTP: ");
            // We flush stdout so it'll write the buffer to screen, continuing operation. Without it, the application halts.
            if let Err(e) = io::stdout().flush() {
                error!("Somehow we failed to flush stdout: {:?}", e);
            };
            let mut buffer = String::new();
            if let Err(e) = io::stdin().read_line(&mut buffer) {
                error!("Failed to read from stdin -> {:?}", e);
                return Err(ClientError::SystemError);
            };

            let response = buffer.trim();
            match response.parse::<u32>() {
                Ok(i) => break i,
                Err(_) => eprintln!("Invalid Number"),
            };
        };
        client.auth_step_totp(totp)
    }

    fn do_webauthn(
        &self,
        client: &mut KanidmClient,
        pkr: RequestChallengeResponse,
    ) -> Result<AuthResponse, ClientError> {
        let mut wa = WebauthnAuthenticator::new(U2FHid::new());
        println!("Your authenticator will now flash for you to interact with it.");
        let auth = wa
            .do_authentication(client.get_origin(), pkr)
            .unwrap_or_else(|e| {
                error!("Failed to interact with webauthn device. -- {:?}", e);
                std::process::exit(1);
            });

        client.auth_step_webauthn_complete(auth)
    }

    pub fn exec(&self) {
        let mut client = self.copt.to_unauth_client();

        // TODO: remove this anon, nobody should do default anonymous
        let username = self.copt.username.as_deref().unwrap_or("anonymous");

        // What auth mechanisms exist?
        let mechs: Vec<_> = client
            .auth_step_init(username)
            .unwrap_or_else(|e| {
                error!("Error during authentication init phase: {:?}", e);
                std::process::exit(1);
            })
            .into_iter()
            .collect();

        let mech = match mechs.len() {
            0 => {
                error!("Error during authentication init phase: Server offered no authentication mechanisms");
                std::process::exit(1);
            }
            1 =>
            {
                #[allow(clippy::expect_used)]
                mechs
                    .get(0)
                    .expect("can not fail - bounds already checked.")
            }
            _ => {
                error!("Username and password should not be empty in tui");
                std::process::exit(1);
            }
        };

        let mut allowed = client.auth_step_begin((*mech).clone()).unwrap_or_else(|e| {
            error!("Error during authentication begin phase: {:?}", e);
            std::process::exit(1);
        });

        // We now have the first auth state, so we can proceed until complete.
        loop {
            debug!("Allowed mechanisms -> {:?}", allowed);
            // What auth can proceed?
            let choice = match allowed.len() {
                0 => {
                    error!(
                        "Error during authentication phase: Server offered no method to proceed"
                    );
                    std::process::exit(1);
                }
                1 =>
                {
                    #[allow(clippy::expect_used)]
                    allowed
                        .get(0)
                        .expect("can not fail - bounds already checked.")
                }
                _ => {
                    error!("Username and password should not be empty in tui");
                    std::process::exit(1);
                }
            };
            let res = match choice {
                AuthAllowed::Anonymous => client.auth_step_anonymous(),
                AuthAllowed::Password => self.do_password(&mut client, self.copt.password.as_ref().unwrap_or(&"".to_string()).clone()),
                AuthAllowed::BackupCode => self.do_backup_code(&mut client),
                AuthAllowed::Totp => self.do_totp(&mut client),
                AuthAllowed::Webauthn(chal) => self.do_webauthn(&mut client, chal.clone()),
            };

            // Now update state.
            let state = res
                .unwrap_or_else(|e| {
                    error!("Error in authentication phase: {:?}", e);
                    std::process::exit(1);
                })
                .state;

            // What auth state are we in?
            allowed = match &state {
                AuthState::Continue(allowed) => allowed.to_vec(),
                AuthState::Success(_token) => break,
                AuthState::Denied(reason) => {
                    error!("Authentication Denied: {:?}", reason);
                    std::process::exit(1);
                }
                _ => {
                    error!("Error in authentication phase: invalid authstate");
                    std::process::exit(1);
                }
            };
            // Loop again.
        }

        // Read the current tokens
        let mut tokens = read_tokens().unwrap_or_else(|_| {
            error!("Error retrieving authentication token store");
            std::process::exit(1);
        });
        // Add our new one
        match client.get_token() {
            Some(t) => tokens.insert(username.to_string(), t),
            None => {
                error!("Error retrieving client session");
                std::process::exit(1);
            }
        };

        // write them out.
        if write_tokens(&tokens).is_err() {
            error!("Error persisting authentication token store");
            std::process::exit(1);
        };

        // Success!
        println!("Login Success for {}", username);
    }
}
impl CommonOpt {
    pub fn to_unauth_client(&self) -> KanidmClient {
        let config_path: String = shellexpand::tilde("~/.config/kanidm").into_owned();

        let client_builder = KanidmClientBuilder::new()
            .read_options_from_optional_config("/etc/kanidm/config")
            .and_then(|cb| cb.read_options_from_optional_config(&config_path))
            .unwrap_or_else(|e| {
                error!("Failed to parse config (if present) -- {:?}", e);
                std::process::exit(1);
            });
        debug!(
            "Successfully loaded configuration, looked in /etc/kanidm/config and {}",
            &config_path
        );

        let client_builder = match &self.addr {
            Some(a) => client_builder.address(a.to_string()),
            None => client_builder,
        };

        let ca_path: Option<&str> = self.ca_path.as_ref().map(|p| p.to_str()).flatten();
        let client_builder = match ca_path {
            Some(p) => client_builder
                .add_root_certificate_filepath(p)
                .unwrap_or_else(|e| {
                    error!("Failed to add ca certificate -- {:?}", e);
                    std::process::exit(1);
                }),
            None => client_builder,
        };

        client_builder.build().unwrap_or_else(|e| {
            error!("Failed to build client instance -- {:?}", e);
            std::process::exit(1);
        })
    }
}

#[allow(clippy::result_unit_err)]
pub fn read_tokens() -> Result<BTreeMap<String, String>, ()> {
    let token_path = PathBuf::from(shellexpand::tilde(TOKEN_PATH).into_owned());
    if !token_path.exists() {
        debug!(
            "Token cache file path {:?} does not exist, returning an empty token store.",
            TOKEN_PATH
        );
        return Ok(BTreeMap::new());
    }

    debug!("Attempting to read tokens from {:?}", &token_path);
    // If the file does not exist, return Ok<map>
    let file = match File::open(&token_path) {
        Ok(f) => f,
        Err(e) => {
            match e.kind() {
                ErrorKind::PermissionDenied => {
                    // we bail here because you won't be able to write them back...
                    error!(
                        "Permission denied reading token store file {:?}",
                        &token_path
                    );
                    return Err(());
                }
                // other errors are OK to continue past
                _ => {
                    warn!(
                        "Cannot read tokens from {} due to error: {:?} ... continuing.",
                        TOKEN_PATH, e
                    );
                    return Ok(BTreeMap::new());
                }
            };
        }
    };
    let reader = BufReader::new(file);

    // Else try to read
    serde_json::from_reader(reader).map_err(|e| {
        error!(
            "JSON/IO error reading tokens from {:?} -> {:?}",
            &token_path, e
        );
    })
}

#[allow(clippy::result_unit_err)]
pub fn write_tokens(tokens: &BTreeMap<String, String>) -> Result<(), ()> {
    let token_dir = PathBuf::from(shellexpand::tilde(TOKEN_DIR).into_owned());
    let token_path = PathBuf::from(shellexpand::tilde(TOKEN_PATH).into_owned());

    token_dir
        .parent()
        .ok_or_else(|| {
            error!(
                "Parent directory to {} is invalid (root directory?).",
                TOKEN_DIR
            );
        })
        .and_then(|parent_dir| {
            if parent_dir.exists() {
                Ok(())
            } else {
                error!("Parent directory to {} does not exist.", TOKEN_DIR);
                Err(())
            }
        })?;

    if !token_dir.exists() {
        create_dir(token_dir).map_err(|e| {
            error!("Unable to create directory - {} {:?}", TOKEN_DIR, e);
        })?;
    }

    // Take away group/everyone read/write
    #[cfg(target_family = "unix")]
    let before = unsafe { umask(0o177) };

    let file = File::create(&token_path).map_err(|e| {
        #[cfg(target_family = "unix")]
        let _ = unsafe { umask(before) };
        error!("Can not write to {} -> {:?}", TOKEN_PATH, e);
    })?;

    #[cfg(target_family = "unix")]
    let _ = unsafe { umask(before) };

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, tokens).map_err(|e| {
        error!(
            "JSON/IO error writing tokens to file {:?} -> {:?}",
            &token_path, e
        );
    })
}

fn read_valid_tokens() -> BTreeMap<String, (String, UserAuthToken)> {
    read_tokens()
        .unwrap_or_else(|_| {
            error!("Error retrieving authentication token store");
            std::process::exit(1);
        })
        .into_iter()
        .filter_map(|(u, t)| {
            let jwtu = JwsUnverified::from_str(&t)
                .map_err(|e| {
                    error!(?e, "Unable to parse token from str");
                })
                .ok()?;

            jwtu.validate_embeded()
                .map_err(|e| {
                    error!(?e, "Unable to verify token signature, may be corrupt");
                })
                .map(|jwt| {
                    let uat = jwt.inner;
                    (u, (t, uat))
                })
                .ok()
        })
        .collect()
}
