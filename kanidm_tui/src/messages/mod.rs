use crate::{App,Event,MenuTitle};
use tui::backend::Backend;
use crossterm::event::{KeyCode,KeyEvent};
use std::sync::mpsc::Receiver;
use crate::app::{InputMode,get_logins};


pub fn handle_instructions<B>(app: &mut App<B>,rx: Receiver<Event<KeyEvent>>)
where B: Backend
{
   loop{
       match app.input_mode {
                InputMode::Normal => {
                    match rx.recv().expect("Could not receive from channel") {
                        Event::Input(event) => match event.code {
                            KeyCode::Char('q') => {
                                break;
                            }
                            KeyCode::Char('c') => {
                                let selected = app.login_list_no;
                                if selected == get_logins().len() - 1 {
                                    app.login_list_no=0;
                                } else {
                                    app.login_list_no+=1;
                                }
                                app.render();
                            }
                            KeyCode::Char('l') => {
                                app.active_menu_item = MenuTitle::Login;
                                app.input_mode = InputMode::EnterUser;
                                app.render();
                            }
                            KeyCode::Char('h') => app.active_menu_item = MenuTitle::Home,
                            _ => {}
                        },
                        Event::Refresh => {
                            app.cleanup();
                            app.render();

                            
                        }
                    }
                }
                InputMode::EnterUser => match rx.recv().expect("Could not receive from channel") {
                    Event::Input(event) => match event.code {
                        KeyCode::Tab => {
                            app.input_mode = InputMode::EnterPass;
                            app.render();
                        }

                        KeyCode::Char(c) => {
                            app.username.push(c);
                            app.render();
                        }
                        KeyCode::Backspace => {
                            app.username.pop();
                            app.render();
                        }
                        KeyCode::Esc => {
                            app.username = "".to_string();
                            app.password = "".to_string();
                            app.masked_password = "".to_string();
                            app.input_mode = InputMode::Normal;
                            app.active_menu_item = MenuTitle::Home;
                            app.render();
                        }
                        KeyCode::Enter => {
                            app.input_mode = InputMode::EnterPass;
                            app.render();
                        }

                        _ => {}
                    },
                    Event::Refresh => {
                        app.cleanup();
                        app.render();
                    }
                },
                InputMode::EnterPass => match rx.recv().expect("Could not receive from channel") {
                    Event::Input(event) => match event.code {
                        KeyCode::Tab => app.input_mode = InputMode::EnterUser,
                        KeyCode::Char(c) => {
                            app.password.push(c);
                            app.masked_password.push('*');
                            app.render();
                        }
                        KeyCode::Backspace => {
                            app.password.pop();
                            app.masked_password.pop();
                            app.render();
                        }
                        KeyCode::Esc => {
                            app.username = "".to_string();
                            app.password = "".to_string();
                            app.input_mode = InputMode::Normal;
                            app.active_menu_item = MenuTitle::Home;
                            app.render();
                        }
                        KeyCode::Enter => {
                            app.login_to_server();
                            app.username = "".to_string();
                            app.password = "".to_string();
                            app.masked_password = "".to_string();
                            app.input_mode = InputMode::Normal;
                            app.active_menu_item = MenuTitle::Home;
                            app.render();
                        }


                        _ => {}
                    },
                    Event::Refresh => {
                        app.cleanup();
                        app.render();
                    }
                
                }
                InputMode::Starting =>{
                    app.input_mode=InputMode::Normal;
                    app.render();
                },
            }

   }



}
