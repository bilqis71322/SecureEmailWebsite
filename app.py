from flask import Flask, render_template, request, redirect, url_for, session, flash
import os, base64, random, smtplib, hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "replace_this_with_a_random_secret_key"  # change for production

# ====== CONFIG ======
SMTP_EMAIL = "securemailproject4@gmail.com"        # your Gmail (sender account)
SMTP_APP_PASSWORD = "fkdlrkgfeaewhguh"       # 16-char Gmail app password
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

KEYS_DIR = "keys"  # folder with sender/receiver keys
# ====================


def send_email(to_email, subject, body):
    """Send an email using Gmail SMTP."""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
    server.sendmail(SMTP_EMAIL, [to_email], msg.as_string())
    server.quit()


# ---------- HOME ----------
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


# ---------- SENDER LOGIN + OTP ----------
@app.route("/sender_login", methods=["GET", "POST"])
def sender_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            flash("Enter sender email.", "danger")
            return redirect(url_for("sender_login"))

        otp = f"{random.randint(0, 999999):06d}"
        session["sender_email"] = email
        session["sender_otp"] = otp

        try:
            send_email(email, "Sender OTP - Secure Email Web App",
                       f"Your sender OTP is: {otp}")
            flash("OTP sent to sender email.", "info")
        except Exception as e:
            flash("Failed to send sender OTP: " + str(e), "danger")
            return redirect(url_for("sender_login"))

        return render_template("sender_otp_verify.html", email=email)

    return render_template("sender_login.html")


@app.route("/sender_verify_otp", methods=["POST"])
def sender_verify_otp():
    user_otp = request.form.get("otp", "").strip()
    stored_otp = session.get("sender_otp")

    if user_otp == stored_otp:
        session["sender_authenticated"] = True
        flash("Sender OTP verified. You can now encrypt messages.", "success")
        return redirect(url_for("encrypt"))
    else:
        flash("Incorrect sender OTP.", "danger")
        return redirect(url_for("sender_login"))


# ---------- RECEIVER LOGIN + OTP ----------
@app.route("/receiver_login", methods=["GET", "POST"])
def receiver_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            flash("Enter receiver email.", "danger")
            return redirect(url_for("receiver_login"))

        otp = f"{random.randint(0, 999999):06d}"
        session["receiver_email"] = email
        session["receiver_otp"] = otp

        try:
            send_email(email, "Receiver OTP - Secure Email Web App",
                       f"Your receiver OTP is: {otp}")
            flash("OTP sent to receiver email.", "info")
        except Exception as e:
            flash("Failed to send receiver OTP: " + str(e), "danger")
            return redirect(url_for("receiver_login"))

        return render_template("receiver_otp_verify.html", email=email)

    return render_template("receiver_login.html")


@app.route("/receiver_verify_otp", methods=["POST"])
def receiver_verify_otp():
    user_otp = request.form.get("otp", "").strip()
    stored_otp = session.get("receiver_otp")

    if user_otp == stored_otp:
        session["receiver_authenticated"] = True
        flash("Receiver OTP verified. You can now decrypt messages.", "success")
        return redirect(url_for("decrypt"))
    else:
        flash("Incorrect receiver OTP.", "danger")
        return redirect(url_for("receiver_login"))


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))


# ---------- ENCRYPT (SENDER ONLY) ----------
@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if not session.get("sender_authenticated"):
        flash("Sender must log in first.", "warning")
        return redirect(url_for("sender_login"))

    if request.method == "POST":
        receiver_email = request.form.get("receiver_email", "").strip()
        message = request.form.get("message", "").strip()

        if not receiver_email or not message:
            flash("Enter receiver email and message.", "danger")
            return redirect(url_for("encrypt"))

        try:
            # 1. AES encrypt message
            aes_key = get_random_bytes(16)  # AES-128
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

            # 2. RSA encrypt AES key using receiver's public key
            with open(os.path.join(KEYS_DIR, "receiver_public.pem"), "rb") as f:
                receiver_pub = RSA.import_key(f.read())
            rsa_cipher = PKCS1_OAEP.new(receiver_pub)
            enc_aes_key = rsa_cipher.encrypt(aes_key)

            # 3. Digital signature using sender's private key
            with open(os.path.join(KEYS_DIR, "sender_private.pem"), "rb") as f:
                sender_priv = RSA.import_key(f.read())
            h = SHA256.new(message.encode())
            signature = pkcs1_15.new(sender_priv).sign(h)

            # 4. Combine + base64 encode
            combined = base64.b64encode(
                enc_aes_key + cipher_aes.nonce + tag + ciphertext
            ).decode()
            signature_b64 = base64.b64encode(signature).decode()

            # Email contents
            email_body = (
                f"Encrypted-Payload:\n{combined}\n\n"
                f"Signature:\n{signature_b64}\n\n"
                f"--End--"
            )

            send_email(receiver_email, "🔐 Secure Encrypted Message", email_body)
            flash("Encrypted message signed and sent to receiver.", "success")

            # Also show values on page
            return render_template(
                "encrypt.html",
                combined=combined,
                signature_b64=signature_b64,
                receiver_email=receiver_email,
                message=message,
            )

        except Exception as e:
            flash("Error during encryption or sending: " + str(e), "danger")

    return render_template("encrypt.html")


# ---------- DECRYPT (RECEIVER ONLY) ----------
@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if not session.get("receiver_authenticated"):
        flash("Receiver must log in first.", "warning")
        return redirect(url_for("receiver_login"))

    if request.method == "POST":
        combined_b64 = request.form.get("combined", "").strip()
        signature_b64 = request.form.get("signature", "").strip()

        if not combined_b64 or not signature_b64:
            flash("Paste both encrypted payload and signature.", "danger")
            return redirect(url_for("decrypt"))

        try:
            data = base64.b64decode(combined_b64)
            # 256 bytes for RSA-2048 encrypted AES key
            enc_aes_key = data[:256]
            nonce = data[256:272]
            tag = data[272:288]
            ciphertext = data[288:]

            # Decrypt AES key using receiver's private key
            with open(os.path.join(KEYS_DIR, "receiver_private.pem"), "rb") as f:
                receiver_priv = RSA.import_key(f.read())
            rsa_cipher = PKCS1_OAEP.new(receiver_priv)
            aes_key = rsa_cipher.decrypt(enc_aes_key)

            # AES decrypt
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

            # Verify signature with sender public key
            with open(os.path.join(KEYS_DIR, "sender_public.pem"), "rb") as f:
                sender_pub = RSA.import_key(f.read())
            signature = base64.b64decode(signature_b64)
            h = SHA256.new(plaintext.encode())

            try:
                pkcs1_15.new(sender_pub).verify(h, signature)
                sig_status = "Signature verified: sender is authentic."
            except (ValueError, TypeError):
                sig_status = "Signature verification FAILED."

            return render_template(
                "decrypt.html",
                plaintext=plaintext,
                sig_status=sig_status,
                combined_b64=combined_b64,
                signature_b64=signature_b64,
            )

        except Exception as e:
            flash("Error during decryption or verification: " + str(e), "danger")

    return render_template("decrypt.html")


if __name__ == "__main__":
    os.makedirs(KEYS_DIR, exist_ok=True)
    app.run(debug=True)
