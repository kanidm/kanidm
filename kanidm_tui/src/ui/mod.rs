use tui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Tabs},
    Terminal,
}; 
use crate::app::{MenuTitle,InputMode};
use crate::login::{get_login_name,get_logins};
use unicode_width::UnicodeWidthStr;
pub struct Display<B>
where
    B: Backend
{
    terminal: Terminal<B>,
}
impl <B>Display<B>
where B: Backend{
    pub fn new(terminal_backend: B) -> Self{
        let mut terminal = Terminal::new(terminal_backend).expect("failed to create terminal");
        terminal.clear().expect("failed to clear terminal");
        Display{
            terminal
        }
    }

    pub fn render(&mut self,active_menu_item: MenuTitle,input_mode: InputMode,username: String,masked_password: String,login_list_no: usize,help_message: String){
    let mut login_list_state = ListState::default();
    let _ =login_list_state.select(Some(login_list_no));
        self.terminal
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
                    f.render_widget(render_titles(active_menu_item), chunk[0]);

                    let main_chunk = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(
                            [Constraint::Percentage(80), Constraint::Percentage(20)].as_ref(),
                        )
                        .split(chunk[2]);
                    match active_menu_item {
                        MenuTitle::Home => {
                            f.render_widget(render_home(), main_chunk[0]);
                            let help_message_paragraph = Paragraph::new(vec![Spans::from(vec![Span::raw(help_message,)])]);
                            f.render_widget(help_message_paragraph, chunk[1]);
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
                            let (user_block, pass_block) = render_login_inputs(username.clone(),masked_password.clone(),input_mode);
                            let (msg, style) = match input_mode {
                                InputMode::Normal => {
                                    (vec![], Style::default().add_modifier(Modifier::RAPID_BLINK))
                                }
                                _ => (vec![Spans::from(vec![Span::raw(help_message,)])], Style::default().add_modifier(Modifier::BOLD)),
                            };
                            let mut text = Text::from(msg);
                            text.patch_style(style);
                            let help_message = Paragraph::new(text);
                            f.render_widget(help_message, chunk[1]);
                            f.render_widget(user_block, login_block_chunk[0]);
                            f.render_widget(pass_block, login_block_chunk[1]);
                            match input_mode {
                                
                                InputMode::EnterUser => {
                                    // Make the cursor visible and ask tui-rs to put it at the specified coordinates after rendering
                                    f.set_cursor(
                                        // Put cursor past the end of the input text
                                        login_block_chunk[0].x
                                            + username.width() as u16
                                            + 1,
                                        // Move one line down, from the border to the input line
                                        login_block_chunk[0].y + 1,
                                    )
                                }
                                InputMode::EnterPass => {
                                    // Same as username but we use masked_password
                                    f.set_cursor(
                                        login_block_chunk[1].x
                                            + masked_password.width() as u16
                                            + 1,
                                        login_block_chunk[1].y + 1,
                                    )
                                }
                                _ => {}
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
             
    }

}
  fn render_login_inputs(username: String,masked_password: String,input_mode: InputMode) -> (Paragraph<'static>, Paragraph<'static>) {
    let username = Paragraph::new(username.clone())
        .style(match input_mode {
            InputMode::EnterUser => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        })
        .block(Block::default().borders(Borders::ALL).title("Username"));
    let password = Paragraph::new(masked_password.clone())
        .style(match input_mode {
            InputMode::EnterPass => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        })
        .block(Block::default().borders(Borders::ALL).title("Password"));

    (username, password)
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
 
