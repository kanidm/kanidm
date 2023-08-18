#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
// We allow expect since it forces good error messages at the least.
#![allow(clippy::expect_used)]
#![allow(warnings)]
#[macro_use]
extern crate tracing;

use crate::common::OpType;
use async_recursion::async_recursion;
use cursive::{
    align::HAlign,
    event::{Event, EventResult},
    view::{Nameable, Resizable},
    views::{Dialog, DummyView, EditView, LinearLayout, TextView, ViewRef},
    CbSink, Cursive, CursiveExt, CursiveRunner, View,
};
use dialoguer::{console::Term, theme::ColorfulTheme, Confirm, Input};
use kanidm_client::KanidmClient;
use kanidm_proto::internal::{IdentifyUserRequest, IdentifyUserResponse};
use regex::Regex;
use std::{
    borrow::BorrowMut,
    cell::RefCell,
    f32::consts::E,
    io::{stdin, stdout, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    join,
    runtime::{self, Builder},
    sync::{
        mpsc::{
            channel, error::TryRecvError, unbounded_channel, UnboundedReceiver, UnboundedSender,
        },
        oneshot::{self, Receiver},
    },
    task,
    time::interval,
};
use url::Url;
use uuid::Uuid;

include!("../opt/kanidm.rs");

pub mod badlist;
pub mod common;
pub mod domain;
pub mod group;
pub mod oauth2;
pub mod person;
pub mod raw;
pub mod recycle;
pub mod serviceaccount;
pub mod session;
pub mod session_expiry;
pub mod synch;
mod webauthn;

impl SelfOpt {
    pub fn debug(&self) -> bool {
        match self {
            SelfOpt::Whoami(copt) => copt.debug,
            SelfOpt::IdentifyUser(copt) => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            SelfOpt::Whoami(copt) => {
                let client = copt.to_client(OpType::Read).await;

                match client.whoami().await {
                    Ok(o_ent) => {
                        match o_ent {
                            Some(ent) => {
                                println!("{}", ent);
                            }
                            None => {
                                error!("Authentication with cached token failed, can't query information.");
                                // TODO: remove token when we know it's not valid
                            }
                        }
                    }
                    Err(e) => println!("Error: {:?}", e),
                }
            }
            SelfOpt::IdentifyUser(copt) => {
                let client = copt.to_client(OpType::Write).await;
                let whoami_response = match client.whoami().await {
                    Ok(o_ent) => {
                        match o_ent {
                            Some(ent) => ent,
                            None => {
                                eprintln!("Authentication with cached token failed, can't query information.");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                        return;
                    }
                };

                let spn = match whoami_response
                    .attrs
                    .get("spn")
                    .map(|v| v.first())
                    .flatten()
                {
                    Some(spn) => spn,
                    None => {
                        eprintln!("Failed to retrieve the id from whoami response :/\nExiting....");
                        return;
                    }
                };
                run_identity_verification_tui(spn, client).await;
            } // end PersonOpt::Validity
        }
    }
}

impl SystemOpt {
    pub fn debug(&self) -> bool {
        match self {
            SystemOpt::PwBadlist { commands } => commands.debug(),
            SystemOpt::Oauth2 { commands } => commands.debug(),
            SystemOpt::Domain { commands } => commands.debug(),
            SystemOpt::Synch { commands } => commands.debug(),
            SystemOpt::AuthSessionExpiry { commands } => commands.debug(),
            SystemOpt::PrivilegedSessionExpiry { commands } => commands.debug(),
        }
    }

    pub async fn exec(&self) {
        match self {
            SystemOpt::PwBadlist { commands } => commands.exec().await,
            SystemOpt::Oauth2 { commands } => commands.exec().await,
            SystemOpt::Domain { commands } => commands.exec().await,
            SystemOpt::Synch { commands } => commands.exec().await,
            SystemOpt::AuthSessionExpiry { commands } => commands.exec().await,
            SystemOpt::PrivilegedSessionExpiry { commands } => commands.exec().await,
        }
    }
}

impl KanidmClientOpt {
    pub fn debug(&self) -> bool {
        match self {
            KanidmClientOpt::Raw { commands } => commands.debug(),
            KanidmClientOpt::Login(lopt) => lopt.debug(),
            KanidmClientOpt::Reauth(lopt) => lopt.debug(),
            KanidmClientOpt::Logout(lopt) => lopt.debug(),
            KanidmClientOpt::Session { commands } => commands.debug(),
            KanidmClientOpt::CSelf { commands } => commands.debug(),
            KanidmClientOpt::Group { commands } => commands.debug(),
            KanidmClientOpt::Person { commands } => commands.debug(),
            KanidmClientOpt::ServiceAccount { commands } => commands.debug(),
            KanidmClientOpt::System { commands } => commands.debug(),
            KanidmClientOpt::Recycle { commands } => commands.debug(),
            KanidmClientOpt::Version {} => {
                println!("kanidm {}", env!("KANIDM_PKG_VERSION"));
                true
            }
        }
    }

    pub async fn exec(&self) {
        match self {
            KanidmClientOpt::Raw { commands } => commands.exec().await,
            KanidmClientOpt::Login(lopt) => lopt.exec().await,
            KanidmClientOpt::Reauth(lopt) => lopt.exec().await,
            KanidmClientOpt::Logout(lopt) => lopt.exec().await,
            KanidmClientOpt::Session { commands } => commands.exec().await,
            KanidmClientOpt::CSelf { commands } => commands.exec().await,
            KanidmClientOpt::Person { commands } => commands.exec().await,
            KanidmClientOpt::ServiceAccount { commands } => commands.exec().await,
            KanidmClientOpt::Group { commands } => commands.exec().await,
            KanidmClientOpt::System { commands } => commands.exec().await,
            KanidmClientOpt::Recycle { commands } => commands.exec().await,
            KanidmClientOpt::Version {} => (),
        }
    }
}

pub(crate) fn password_prompt(prompt: &str) -> Option<String> {
    for _ in 0..3 {
        let password = rpassword::prompt_password(prompt).ok()?;

        let password_confirm =
            rpassword::prompt_password("Retype the new password to confirm: ").ok()?;

        if password == password_confirm {
            return Some(password);
        } else {
            error!("Passwords do not match");
        }
    }
    None
}

// TODO: this regex is also used in the webui (https://github.com/kanidm/kanidm/blob/003234c2d0a52146683628156e2a106bf61fe9f4/server/web_ui/src/views/identityverification.rs#L60) should we move it to proto?

lazy_static::lazy_static! {
    pub static ref VALIDATE_TOTP_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new(r"^\d{6}$").expect("Invalid singleline regex found")
    };
}
// here I used a simple function instead of a struct because all the channel stuff requires ownership, so if we were to use a struct with a `run` method, it would have to take ownership of everything
// so might as well just use a function
pub async fn run_identity_verification_tui(self_id: &String, client: KanidmClient) {
    //unbounded channel to send messages to the controller from the ui
    let (controller_tx, mut controller_rx) = unbounded_channel::<IdentifyUserMsg>();
    // unbounded channel to send messages to the ui from the controller
    let (ui_tx, mut ui_rx) = unbounded_channel::<IdentifyUserState>();

    // we manually send the initial start message
    controller_tx.send(IdentifyUserMsg::Start);

    // oneshot channel to get the callback sink from the ui
    let (cb_tx, mut cb_rx) = oneshot::channel::<CbSink>();
    // we start the ui in its own thread
    let gui_handle = std::thread::spawn(move || {
        let mut ui = Ui::new(controller_tx, ui_rx);
        if cb_tx.send(ui.get_cb()).is_err() {
            eprintln!("Callback oneshot channel closed too soon! Aborting..."); // TODO: what the hell are we supposed to tell the user?
            return;
        };
        ui.0.run();
    });

    start_business_logic_loop(controller_rx, cb_rx, ui_tx, self_id, client).await;

    if let Err(e) = gui_handle.join() {
        eprintln!("The UI thread returned an error: {:?}", e);
    };
}

async fn start_business_logic_loop(
    mut controller_rx: UnboundedReceiver<IdentifyUserMsg>,
    mut cb_rx: Receiver<CbSink>,
    ui_tx: UnboundedSender<IdentifyUserState>,
    self_id: &String,
    client: KanidmClient,
) {
    let Ok(cb) = cb_rx.await else {
        eprintln!("Callback oneshot channel closed too soon! Aborting..."); // TODO: what the hell are we supposed to tell the user?
        return;
    };

    let send_msg_and_call_callback = |msg: IdentifyUserState| {
        if ui_tx.send(msg).is_err() {
            eprintln!("UI channel closed too soon! Aborting..."); // TODO: what the hell are we supposed to tell the user?
            return;
        }
        if cb.send(Box::new(Ui::update_state_callback)).is_err() {
            eprintln!("Callback channel closed too soon! Aborting..."); // TODO: what the hell are we supposed to tell the user?
            return;
        };
    };
    let self_id = Arc::new(self_id.clone());
    // conveniently when the `quit()` is called on the ui it also drops the controller_tx since it's stored in the `user_data` so as per the doc `controller_rx.recv()` will return None and therefore the loop will exit
    while let Some(msg) = controller_rx.recv().await {
        // ** NEVER EVER CALL `break` inside the loop as it will drop the mpsc receiver and sender and the ui won't be able to process whatever message is sent to it
        // ** instead use `continue` so that the loop will only exit when the ui drops its controllers
        let (id, req) = match &msg {
            IdentifyUserMsg::Start => (&self_id, IdentifyUserRequest::Start),
            IdentifyUserMsg::SubmitOtherId { other_id } => (other_id, IdentifyUserRequest::Start),
            IdentifyUserMsg::SubmitCode {
                code: totp,
                other_id,
            } => (
                other_id,
                IdentifyUserRequest::SubmitCode { other_totp: *totp },
            ),
            IdentifyUserMsg::CodeConfirmedFirst { other_id } => {
                send_msg_and_call_callback(IdentifyUserState::WaitForCode {
                    other_id: other_id.clone(), // I know it's bad cloning but organizing things this way allows us to just have this clone and the one below throughout the whole loop
                });
                continue;
            }
            IdentifyUserMsg::CodeConfirmedSecond { other_id } => {
                send_msg_and_call_callback(IdentifyUserState::Success {
                    other_id: other_id.clone(), // (the second clone mentioned above)
                });
                continue;
            }
            IdentifyUserMsg::ReDisplayCodeFirst { other_id }
            | IdentifyUserMsg::ReDisplayCodeSecond { other_id } => {
                (other_id, IdentifyUserRequest::DisplayCode)
            }
        };
        let res = match client.idm_person_identify_user(&id, req).await {
            Ok(res) => res,
            Err(e) => {
                let err = IdentifyUserState::Error {
                    msg: format!("{:?}", e),
                };
                send_msg_and_call_callback(err);
                continue;
            }
        };
        let state = match res {
            IdentifyUserResponse::IdentityVerificationUnavailable => IdentifyUserState::Error { msg: "Unfortunately the identity verification feature is not available for your account.".to_string() },
            IdentifyUserResponse::IdentityVerificationAvailable => IdentifyUserState::IdDisplayAndSubmit {self_id: self_id.to_string()},
            IdentifyUserResponse::ProvideCode { step, totp } => {
                match msg {
                    IdentifyUserMsg::SubmitOtherId { other_id} | IdentifyUserMsg::ReDisplayCodeFirst { other_id}=> IdentifyUserState::DisplayCodeFirst { self_totp: totp, step, other_id },
                    IdentifyUserMsg::SubmitCode { other_id, ..} | IdentifyUserMsg::ReDisplayCodeSecond { other_id} => IdentifyUserState::DisplayCodeSecond { self_totp: totp, step, other_id },
                    _ => IdentifyUserState::invalid_state_error()
                }
            },
            IdentifyUserResponse::WaitForCode => {
                match msg {
                    IdentifyUserMsg::SubmitOtherId { other_id } | IdentifyUserMsg::SubmitCode { other_id, .. }=>  IdentifyUserState::WaitForCode { other_id },
                    _ => IdentifyUserState::invalid_state_error()
                }
            },
            IdentifyUserResponse::Success => {
                match msg {
                    IdentifyUserMsg::SubmitCode { code, other_id } => IdentifyUserState::Success { other_id },
                     _ => IdentifyUserState::invalid_state_error()
                }
            },
            IdentifyUserResponse::CodeFailure => {
                match msg {
                    IdentifyUserMsg::SubmitCode { other_id, .. } => IdentifyUserState::Error { msg: format!("The provided code doesn't belong to {other_id}") },
                    _ => IdentifyUserState::invalid_state_error()
                }
            },
        IdentifyUserResponse::InvalidUserId => IdentifyUserState::Error { msg: format!("{id}'s account exists but cannot access the identity verification feature") }
        };
        send_msg_and_call_callback(state);
    }
}

// this is kind of awkward but Cursive doesn't allow us to store data in the `user_data` without having to clone it every time we access it,
// so since the `other_id` String will never change during the execution of the program, we can just use an Arc to avoid cloning it every time
#[derive(Debug, Clone, PartialEq)]
enum IdentifyUserState {
    IdDisplayAndSubmit {
        self_id: String,
    },
    WaitForCode {
        other_id: Arc<String>,
    },
    DisplayCodeFirst {
        self_totp: u32,
        step: u32,
        other_id: Arc<String>,
    },
    DisplayCodeSecond {
        self_totp: u32,
        step: u32,
        other_id: Arc<String>,
    },
    Success {
        other_id: Arc<String>,
    },
    Error {
        msg: String,
    },
}

impl IdentifyUserState {
    pub fn invalid_state_error() -> Self {
        IdentifyUserState::Error {
            msg: "The user identification flow is in an invalid state :/".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum IdentifyUserMsg {
    Start,
    SubmitOtherId { other_id: Arc<String> },
    SubmitCode { code: u32, other_id: Arc<String> },
    CodeConfirmedFirst { other_id: Arc<String> },
    CodeConfirmedSecond { other_id: Arc<String> },
    ReDisplayCodeFirst { other_id: Arc<String> },
    ReDisplayCodeSecond { other_id: Arc<String> },
}

struct Ui(Cursive);

struct UiUserData {
    controller_tx: UnboundedSender<IdentifyUserMsg>,
    ui_rx: UnboundedReceiver<IdentifyUserState>,
}

impl Ui {
    fn new(
        controller_tx: UnboundedSender<IdentifyUserMsg>,
        ui_rx: UnboundedReceiver<IdentifyUserState>,
    ) -> Self {
        let mut cursive = Cursive::new();
        let controller_tx_clone = controller_tx.clone();
        cursive.add_global_callback('q', |s| {
            s.quit();
        });
        cursive.set_autorefresh(true);
        cursive.set_user_data(UiUserData {
            controller_tx,
            ui_rx,
        });

        Ui(cursive)
    }

    fn get_cb(&self) -> CbSink {
        self.0.cb_sink().clone()
    }

    fn render_state(
        s: &mut Cursive,
        state: IdentifyUserState,
        controller_tx: UnboundedSender<IdentifyUserMsg>,
    ) {
        match state {
            IdentifyUserState::IdDisplayAndSubmit { self_id } => {
                let controller_tx_clone = controller_tx.clone();
                let layout = LinearLayout::vertical()
                    .child(DummyView.fixed_height(1))
                    .child(
                        TextView::new(format!(
                            "When asked for your ID, provide the following: {}",
                            self_id
                        ))
                        .h_align(HAlign::Center),
                    )
                    .child(DummyView.fixed_height(1))
                    .child(
                        TextView::new("-----------------------------------------------")
                            .h_align(HAlign::Center),
                    )
                    .child(DummyView.fixed_height(1))
                    .child(
                        TextView::new("Ask for the other person's ID, and insert it here!")
                            .h_align(HAlign::Center),
                    )
                    .child(DummyView.fixed_height(1))
                    .child(
                        EditView::new()
                            .content("sample@id.com")
                            .on_submit(move |s, user_id: &str| {
                                &controller_tx.send(IdentifyUserMsg::SubmitOtherId {
                                    other_id: Arc::new(user_id.to_string()),
                                });
                                Self::loading_view(s);
                            })
                            .with_name("id-user-input"),
                    );
                // we have to redeclare this because we consumed it in the prev closure
                s.add_layer(
                    Dialog::around(layout)
                        .button("Quit", |s| {
                            s.quit();
                        })
                        .button("Continue", move |s| {
                            let user_id = s
                                .call_on_name("id-user-input", |view: &mut EditView| {
                                    view.get_content()
                                })
                                .unwrap();
                            controller_tx_clone.send(IdentifyUserMsg::SubmitOtherId {
                                other_id: Arc::new(user_id.to_string()),
                            });
                            Self::loading_view(s);
                        }),
                );
            }
            IdentifyUserState::WaitForCode { other_id } => {
                s.pop_layer();
                let other_id_clone = other_id.clone();
                let controller_tx_clone = controller_tx.clone();
                let layout = LinearLayout::vertical()
                    .child(TextView::new(format!(
                        "Ask for {}'s code, and insert it here!",
                        &other_id
                    )))
                    .child(DummyView.fixed_height(1))
                    .child(
                        EditView::new()
                            .content("123456")
                            .on_submit(move |s, code: &str| {
                                let code_u32 = code.parse::<u32>().unwrap(); // TODO: show user feedback
                                &controller_tx.send(IdentifyUserMsg::SubmitCode {
                                    code: code_u32,
                                    other_id: other_id_clone.clone(),
                                });
                                Self::loading_view(s);
                            })
                            .with_name("totp-input"),
                    );
                s.add_layer(
                    Dialog::around(layout)
                        .button("Quit", |s| {
                            s.quit();
                        })
                        .button("Continue", move |s| {
                            let code = s
                                .call_on_name("totp-input", |view: &mut EditView| {
                                    view.get_content()
                                })
                                .unwrap();
                            let code_u32 = code.parse::<u32>().unwrap(); // TODO: show user feedback
                            controller_tx_clone.send(IdentifyUserMsg::SubmitCode {
                                code: code_u32,
                                other_id: other_id.clone(),
                            });
                            Self::loading_view(s);
                        }),
                );
            }
            IdentifyUserState::DisplayCodeFirst {
                self_totp,
                step,
                other_id,
            } => {
                s.pop_layer();
                let layout = LinearLayout::vertical()
                    .child(TextView::new(format!(
                        "Provide the following code when asked: {self_totp}"
                    )))
                    .child(TotpCountdownView::new(
                        step as u64,
                        controller_tx.clone(),
                        IdentifyUserMsg::ReDisplayCodeFirst {
                            other_id: other_id.clone(),
                        },
                    ));
                s.add_layer(Dialog::around(layout).button("Continue", move |s| {
                    Self::confirmation_view(
                        s,
                        other_id.clone(),
                        controller_tx.clone(),
                        IdentifyUserMsg::CodeConfirmedFirst {
                            other_id: other_id.clone(),
                        },
                    );
                }));
            }
            IdentifyUserState::DisplayCodeSecond {
                self_totp,
                step,
                other_id,
            } => {
                s.pop_layer();
                let layout = LinearLayout::vertical()
                    .child(TextView::new(format!(
                        "Provide the following code when asked: {self_totp}"
                    )))
                    .child(TotpCountdownView::new(
                        step as u64,
                        controller_tx.clone(),
                        IdentifyUserMsg::ReDisplayCodeSecond {
                            other_id: other_id.clone(),
                        },
                    ));
                s.add_layer(Dialog::around(layout).button("Continue", move |s| {
                    Self::confirmation_view(
                        s,
                        other_id.clone(),
                        controller_tx.clone(),
                        IdentifyUserMsg::CodeConfirmedSecond {
                            other_id: other_id.clone(),
                        },
                    );
                }));
            }
            IdentifyUserState::Success { other_id } => {
                s.pop_layer();
                let layout = LinearLayout::vertical().child(TextView::new(format!(
                    "{other_id}'s identity has been successfully verified!"
                )));

                s.add_layer(Dialog::around(layout).button("Quit", |s| {
                    s.quit();
                }));
            }
            IdentifyUserState::Error { msg } => Self::error_state_view(s, &msg),
        };
    }

    fn update_state_callback(s: &mut Cursive) {
        let user_data = match s.user_data::<UiUserData>() {
            Some(data) => data,
            None => {
                return Self::error_state_view(
                    s,
                    "It looks like some data got corrupted, you have to start from scratch",
                )
            }
        };
        if let Some(state) = user_data.ui_rx.blocking_recv() {
            let controller_rx = user_data.controller_tx.to_owned(); // we have to take ownership so the mut borrow `s` can be passed to `render_state`
            Ui::render_state(s, state, controller_rx);
        }
    }

    fn confirmation_view(
        s: &mut Cursive,
        other_id: Arc<String>,
        controller_tx: UnboundedSender<IdentifyUserMsg>,
        msg: IdentifyUserMsg,
    ) {
        s.add_layer(
            Dialog::around(TextView::new(format!("Did you confirm that {other_id} correctly verified your code? If you proceed, you won't be able to go back.")))
                .button("Yes, proceed", move |s| {
                    s.pop_layer();
                    controller_tx.send(msg.to_owned());
                })
                .button("No, exit", |s| {
                    s.quit();
                }),
        );
    }

    fn error_state_view(s: &mut Cursive, msg: &str) {
        s.pop_layer();
        let layout = LinearLayout::vertical()
            .child(DummyView.fixed_height(1))
            .child(TextView::new(msg));

        s.add_layer(
            Dialog::around(layout)
                .title("An error occurred!")
                .button("Quit", |s| {
                    s.quit();
                }),
        );
    }

    fn loading_view(s: &mut Cursive) {
        s.pop_layer();
        s.add_layer(TextView::new("Hold tight while we're loading..."));
    }
}

struct TotpCountdownView {
    msg: IdentifyUserMsg,
    ticks_left: u64,
    step: u64,
    controller_tx: UnboundedSender<IdentifyUserMsg>,
    should_call_callback: RefCell<bool>, // we need to use a refcell since we need to mutate this data inside the `draw` method which has a `&self` reference
}

impl TotpCountdownView {
    fn new(
        step: u64,
        controller_tx: UnboundedSender<IdentifyUserMsg>,
        msg: IdentifyUserMsg,
    ) -> Self {
        Self {
            should_call_callback: RefCell::new(true),
            msg,
            ticks_left: Self::get_ticks_left_from_now(step),
            step,
            controller_tx,
        }
    }

    fn get_ticks_left_from_now(step: u64) -> u64 {
        #[allow(clippy::expect_used)]
        let dur = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("invalid duration from epoch now");
        (step - dur.as_secs() % (step))
    }
}

impl View for TotpCountdownView {
    fn draw(&self, printer: &cursive::Printer) {
        let ticks_left_from_now = Self::get_ticks_left_from_now(self.step);
        // basically whenever the ticks_left reset to step, i.e. the first time this function has been called after we got to a new totp window, then we
        // call the callback to fetch a new code which will be displayed at best in the next tick. On very slow connections the user might see the old
        // code for a bit. If we want to get rid of this we would need to pass to the struct a callback to show a loading screen
        if ticks_left_from_now == self.step && *self.should_call_callback.borrow() {
            self.controller_tx.send(self.msg.to_owned()).unwrap();
            *self.should_call_callback.borrow_mut() = false;
        };
        printer.print((0, 0), &format!("{:?} seconds left", ticks_left_from_now));
    }
}
