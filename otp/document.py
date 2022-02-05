import importlib.resources as pkg_resources

from weasyprint import HTML
from jinja2 import Template
import qrcode
import base64
import io
from . import templates

import git

template_text = pkg_resources.read_text(templates, 'template.html')
template = Template(template_text)

def _create_base_64_qr_png(uri):
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="#eeeeee")

    buffer = io.BytesIO()
    buffer.seek(0)
    img.save(buffer, format="png")
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("utf-8")


def _get_commit_hash():
    repo = git.Repo(search_parent_directories=True)
    return repo.head.object.hexsha

def to_pdf(accounts, output_path):
    images = [_create_base_64_qr_png(account.otp_uri()) for account in accounts]

    render_result = template.render(accounts=accounts, images=images, commit=_get_commit_hash())

    HTML(string=render_result).write_pdf(output_path)
