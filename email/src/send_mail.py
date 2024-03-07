from dataclasses import dataclass
import os

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

type HTML = str

@dataclass
class EmailContent:
    sub: str
    html_content: HTML

def send_mail(to, fro, email: EmailContent):
    
    message = Mail(
        from_email=fro,
        to_emails=to,
        subject=email.sub,
        html_content= email.html_content)
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e.message)
