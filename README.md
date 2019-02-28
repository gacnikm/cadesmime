A basic python S/MIME CADES signature.
Tested with Gmail and Thunderbird.
Gmail breaks CADESMIMEmbedded.

**WARNING**: does not do validation! 

**Requirements**
- pytz
- cryptography
- asn1crypto

**Example usage**
<pre>
from cadesmime.cadesmime import CADESMIMESignature

#create message and add required email data
message = CADESMIMESignature() # same for CADESMIMEmbedded
message.add_header('From', 'sender@example.com')
message.add_header('Subject', 'CADESMIME test email')
message.add_header('To', 'receiver@example.com')

#set signing certificate, PKCS12 format only
with open("path/to/certificate", "rb") as key_file:
    message.set_sign_certificate(key_file,"certificate password")

#create and add content
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
</pre>

To validate the embedded signature, save it:
<pre>
with open("test.p7m", 'wb') as f:
    f.write(message.get_payload(decode=True))
</pre>
and then send the p7m file to service at https://joinup.ec.europa.eu/dss-webapp/validation.

To save as an *.eml file:
<pre>
with open("email_message.eml", 'wb') as f:
    f.write(message.as_bytes())
</pre>


