import random
import smtplib
from email.message import EmailMessage

# इन मेमोरी स्टोरेज (डेटाबेस की जगह)
pending_verifications = {}
users = {}


def generate_verification_code():
    return str(random.randint(100000, 999999))


def send_verification_email(email, code):
    from_email = "your-email@example.com"
    password = "your-email-password"

    msg = EmailMessage()
    msg.set_content(f"आपका वेरिफिकेशन कोड है: {code}")
    msg["Subject"] = "Email Verification Code"
    msg["From"] = from_email
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.example.com", 465) as smtp:
        smtp.login(from_email, password)
        smtp.send_message(msg)


def initiate_registration(username, email, password):
    code = generate_verification_code()
    pending_verifications[email] = {
        "username": username,
        "password": password,
        "code": code,
    }
    send_verification_email(email, code)
    print(f"Verification code sent to {email}")


def verify_account(email, entered_code):
    record = pending_verifications.get(email)
    if record and record["code"] == entered_code:
        users[email] = {
            "username": record["username"],
            "password": record["password"],
        }
        del pending_verifications[email]
        print("Account verified and created successfully.")
        return True
    print("Invalid verification code.")
    return False
