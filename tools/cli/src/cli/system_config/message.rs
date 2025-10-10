use kanidm_proto::cli::OpType;

use crate::{KanidmClientParser, MessageOpt, OutputMode};
// use kanidm_proto::scim_v1::{ScimEntryGetQuery};

impl MessageOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            MessageOpt::List => {
                let client = opt.to_client(OpType::Read).await;
                let query = None;

                match client.idm_message_list(query).await {
                    Ok(list) => match opt.output_mode {
                        OutputMode::Json => {
                            let json = serde_json::to_string(&list)
                                .expect("Failed to serialise list to JSON!");
                            println!("{json}");
                        }
                        OutputMode::Text => {
                            // Print each entry on a new line
                            list.resources.iter().for_each(|entry| {
                                println!("message_id:   {}", entry.header.id);
                                println!("send_after:   {}", entry.send_after.date_time);
                                println!(
                                    "sent_at:      {}",
                                    entry
                                        .sent_at
                                        .as_ref()
                                        .map(|sdt| sdt.date_time.to_string())
                                        .unwrap_or_else(|| "queued".into())
                                );
                                println!("delete_after: {}", entry.delete_after.date_time);
                                println!("template:     {}", entry.message_template.display_type());

                                for mail in entry.mail_destination.iter() {
                                    println!("to:           {}", mail.value);
                                }

                                println!();
                            });
                            eprintln!("--");
                            eprintln!("Success");
                        }
                    },
                    Err(e) => crate::handle_client_error(e, opt.output_mode),
                }
            }

            MessageOpt::Get { message_id } => {
                let client = opt.to_client(OpType::Read).await;

                match client.idm_message_get(*message_id).await {
                    Ok(entry) => match opt.output_mode {
                        OutputMode::Json => {
                            let json = serde_json::to_string(&entry)
                                .expect("Failed to serialise entry to JSON!");
                            println!("{json}");
                        }
                        OutputMode::Text => {
                            println!("message_id:   {}", entry.header.id);
                            println!("send_after:   {}", entry.send_after.date_time);
                            println!(
                                "sent_at:      {}",
                                entry
                                    .sent_at
                                    .as_ref()
                                    .map(|sdt| sdt.date_time.to_string())
                                    .unwrap_or_else(|| "queued".into())
                            );
                            println!("delete_after: {}", entry.delete_after.date_time);

                            println!("template:     {}", entry.message_template.display_type());

                            for mail in entry.mail_destination.iter() {
                                println!("to:           {}", mail.value);
                            }
                            println!();
                            eprintln!("--");
                            eprintln!("Success");
                        }
                    },
                    Err(err) => {
                        crate::handle_client_error(err, opt.output_mode);
                    }
                }
            }

            MessageOpt::MarkAsSent { message_id } => {
                let client = opt.to_client(OpType::Write).await;

                if let Err(e) = client.idm_message_mark_sent(*message_id).await {
                    crate::handle_client_error(e, opt.output_mode);
                } else {
                    opt.output_mode.print_message("Message Marked as Sent");
                }
            }

            MessageOpt::SendTestMessage { to } => {
                let client = opt.to_client(OpType::Write).await;

                if let Err(e) = client.idm_message_send_test(to).await {
                    crate::handle_client_error(e, opt.output_mode);
                } else {
                    opt.output_mode.print_message("Message Queued");
                }
            }
        }
    }
}
