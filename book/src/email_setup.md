# Outgoing Email

TBD



`idm_message_senders`

```
kanidm_mail_sender -c /tmp/kanidm/config -m /tmp/kanidm/mail-sender -t test@example.com

kanidm_mail_sender -c /tmp/kanidm/config -m /tmp/kanidm/mail-sender
```


```
# Ensure this token is ReadWrite!!!
token = ""
schedule = "*/5 * * * * * *"
mail_from_address = "tobias@example.com"
mail_reply_to_address = "tobias@example.com"
mail_from_display_name = "Kanidm Mail Sender"
# Must support TLS
mail_relay = "smtp.example.com"
mail_username = "tobias@example.com"
mail_password = ""
```



kanidm system message-queue list


`kanidm system message-queue send-test-message TO_ACCOUNT`

```
kanidm system message-queue list
message_id:   0a9318dc-920f-4944-9ce4-91b4322b5dad
send_after:   2026-02-18 2:49:43.163072 +00:00:00
sent_at:      queued
delete_after: 2026-02-25 2:49:43.163072 +00:00:00
template:     test_message_v1
to:           william@blackhats.net.au

--
Success
```


== Once the message has been sent:


```
message_id:   0a9318dc-920f-4944-9ce4-91b4322b5dad
send_after:   2026-02-18 2:49:43.163072 +00:00:00
sent_at:      2026-02-18 2:52:48.733806 +00:00:00
delete_after: 2026-02-25 2:49:43.163072 +00:00:00
template:     test_message_v1
to:           william@blackhats.net.au

--
Success
```


