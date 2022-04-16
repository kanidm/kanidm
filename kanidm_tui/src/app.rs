use std::collections::BTreeMap;
use std::path::PathBuf;
use tracing::error;
use crate::login::{LoginOpt,read_valid_tokens,write_tokens};


use crossterm::
    event::KeyEvent;
use std::time::Instant;
use std::sync::mpsc::Receiver;
use tui::
    backend::Backend;
use crate::ui::Display;
use crate::messages::handle_instructions;


#[derive(Debug)]
pub struct CommonOpt {
    pub debug: bool,
    pub addr: Option<String>,
    pub username: Option<String>,
    pub ca_path: Option<PathBuf>,
    pub password: Option<String>,
}

pub enum Event<T> {
    Input(T),
    Refresh,
}
#[derive(Copy, Clone, Debug)]
pub enum MenuTitle {
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
pub enum InputMode {
    Normal,
    EnterUser,
    EnterPass,
    Starting,
} 

pub struct App<B>
where B: Backend{
    pub username: String,
    pub password: String,
    pub masked_password: String,
    /// Current input mode
    pub input_mode: InputMode,
    pub active_menu_item: MenuTitle,
    pub last_refresh: Instant,
    pub copt: CommonOpt,
    pub help_message: String,
    display: Display<B>,
    pub login_list_no: usize,
}
impl <B>App<B> 
where B: Backend{
    pub fn new(terminal_backend: B) -> Self {
        let display = Display::new(terminal_backend);
        App {
            username: String::new(),
            password: String::new(),
            masked_password: String::new(),
            input_mode: InputMode::Starting,
            active_menu_item: MenuTitle::Home,
            last_refresh: Instant::now(),
            help_message: String::new(),
            display,
            login_list_no: 0,
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
    pub fn start(&mut self,rx: Receiver<Event<KeyEvent>>){
        handle_instructions(self,rx);
    }
    pub fn login_to_server(&mut self) {
        let copt = CommonOpt {
            debug: self.copt.debug.clone(),
            addr: self.copt.addr.clone(),
            username: Some(self.username.clone()),
            ca_path: self.copt.ca_path.clone(),
            password: Some(self.password.clone()),
        };
        let login = LoginOpt {
            copt: copt,
            // TODO add webauthn
            //webauthn: false,
        };
        match login.exec(){
            Ok(text) => self.help_message=text,
            Err(e) =>self.help_message=format!("{:?}",e),
        };
    }
    pub fn cleanup(&self) {
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
    pub fn render(&mut self){
        self.display.render(self.active_menu_item,self.input_mode,self.username.clone(),self.masked_password.clone(),self.login_list_no,self.help_message.clone());
    }
    pub fn render_default(&mut self){
        self.help_message="You can see list of Logins at the right pane, If it is empty press 'L' to login".to_string();
        self.render();
    }
    pub fn render_login(&mut self){
        self.active_menu_item = MenuTitle::Login;
        self.input_mode = InputMode::EnterUser;
        self.help_message= "Press Esc to stop editing, Enter login to server".to_string();
        self.render();
    }
    pub fn render_after_login(&mut self){
        self.username = "".to_string();
        self.password = "".to_string();
        self.masked_password = "".to_string();
        self.input_mode = InputMode::Normal;
        self.active_menu_item = MenuTitle::Home;
        self.render();
    }

}



