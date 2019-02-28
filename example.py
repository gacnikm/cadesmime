import email
import smtplib
from email.mime.image import MIMEImage
from email.mime.text import MIMEText

from cadesmime.cadesmime import CADESMIMESignature

#create message and add required email data
message = CADESMIMESignature() # or CADESMIMEmbedded
message.add_header('From', 'sender@example.com')
message.add_header('Subject', 'CADESMIME test email')
message.add_header('To', 'receiver@example.com')

#set signing certificate, PKCS12 format only
with open("path/to/certificate", "rb") as key_file:
    message.set_sign_certificate(key_file,"certificate password")

#create and add content, wrapped as MIME objects
text = MIMEText("This is some text", policy=email.policy.SMTPUTF8)
image = MIMEImage(open('image.png', 'rb').read(), policy=email.policy.SMTPUTF8)
message.attach(text)
message.attach(image)

#sign
message.sign()

#send with eg. smtpserver
smtpserver = smtplib.SMTP("smtp.gmail.com", 587)
smtpserver.ehlo()
smtpserver.starttls()
smtpserver.ehlo()
smtpserver.login('email', 'password')
smtpserver.send_message(message)
smtpserver.close()