import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


def send_mail(to, fro, sub, mesg):
    
    message = Mail(
        from_email=fro,
        to_emails=to,
        subject=sub,
        html_content= f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification</title>
    <style>
        body {{
        background-color: #1a1a1a;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            color: #ffffff;
            font-family: 'Arial', sans-serif; }}
            .otp-container {{
                background-color: #333333;
                color: #ffffff;
                margin: 20px 0;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                width: 300px;
                text-align: center;
            }}

            h1 {{
                color: #3498db;
            }}
            font-size: 18px;
        
    </style>
</head>
<body>
    <div class="otp-container">
        <h1>Verification</h1>
        <p>Here is your verification code:  <strong>{mesg}</strong>. Thanks for using our services.</p>
    </div>
</body>
</html>''')
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e.message)

send_mail("himanshujha199@gmail.com","himanshu.jha.ug22@nsut.ac.in","OTP verification","123123")