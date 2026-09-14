# Email setup on Render Free

The app sends QR emails through Brevo's HTTPS API on Render Free. Gmail recipients
work with this approach. Render Free blocks outbound SMTP ports 25, 465, and 587,
so Gmail SMTP credentials alone cannot fix delivery on this plan.
See [Render's free service limitations](https://render.com/docs/free#other-limitations).

## Configure the sender

1. Create or sign in to your Brevo account and complete its account activation
   requirements for transactional email.
2. Add the address you want to send from and complete sender verification.
   Follow [Brevo's sender instructions](https://help.brevo.com/hc/en-us/articles/208836149-Create-a-new-sender-From-name-and-From-email).
   The sender is your address; students' Gmail addresses remain the recipients.
3. Create an **API key**, not an SMTP key. Follow
   [Brevo's transactional email setup](https://developers.brevo.com/docs/send-a-transactional-email).
4. In Render, open **naap-parking-management > Environment**, then add or update:

   | Variable | Value |
   | --- | --- |
   | `MAIL_PROVIDER` | `brevo` |
   | `BREVO_API_KEY` | Your Brevo API key |
   | `MAIL_FROM_EMAIL` | The sender address verified in Brevo |
   | `MAIL_FROM_NAME` | `NAAP Parking` |

5. Save the environment changes and redeploy. Existing services need these
   values entered in Render; pushing `render.yaml` does not supply secret keys.

Keep the key in Render's Environment settings. Do not put it in Git or paste it
into chat. Existing SMTP settings are ignored when `MAIL_PROVIDER=brevo`.

If your sender is a Gmail address, you cannot authenticate the `gmail.com` domain
yourself. Brevo may substitute its sending domain; follow any sender requirements
shown in your account. If you own a domain, authenticate it in Brevo for a
consistent sender identity. See
[Brevo's domain authentication guidance](https://help.brevo.com/hc/en-us/articles/16045394674066-Troubleshooting-issues-with-domain-authentication).

## Check a delivery

1. Open **Stickers**, choose an active sticker whose student has a valid email,
   and select **Email QR**.
2. Check the recipient and QR preview, then select **Send email**.
3. Check **QR Email Delivery**. Missing configuration is reported before a request
   is queued. Invalid keys or unauthorized senders fail with an actionable message;
   temporary network or service failures are retried automatically.
4. **Sent** means the email provider accepted the message. Check the recipient's
   Gmail inbox and Spam folder, and Brevo's transactional logs for delivery or
   bounce details. After fixing a failed delivery's configuration, select **Retry**.
   If an error says the provider returned no receipt, check its logs before retrying.

QR images are attached as PNG files. Optional encrypted backup emails use a
`.naapbackup.txt` attachment because mail providers restrict custom extensions.
The contents remain encrypted, and the restore form accepts this filename.

## Local SMTP

Outside Render Free, `MAIL_PROVIDER=smtp` retains the existing SMTP transport.
Configure the `SMTP_*` variables documented in `.env.example`. Use a host that
allows outbound SMTP; changing only the provider setting does not remove Render's
port restrictions.
