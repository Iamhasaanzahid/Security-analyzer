import smtplib
from email.message import EmailMessage


def send_alert(subject, body, to_email):
    # यहाँ अपनी ईमेल सेटिंग्स डालें
    from_email = "your-email@example.com"
    password = "your-email-password"

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.example.com", 465) as smtp:
            smtp.login(from_email, password)
            smtp.send_message(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
