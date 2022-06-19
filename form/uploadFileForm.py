from flask_wtf import FlaskForm
from wtforms import (FileField, EmailField, SubmitField)
from wtforms.validators import (Email)


class UploadFileForm(FlaskForm):
    file = FileField('File')
    sign_file = FileField('File')
    email = EmailField("Reciever's email",  validators=[
        Email("Please enter your email address.")], render_kw={"placeholder": "Email"})
    submit = SubmitField('UPLOAD')
