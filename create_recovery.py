import click
import hashlib

from bpylist import archiver
from Crypto.Cipher import AES

import otp
import otp.backup
import otp.document


archiver.update_class_map({'NSMutableData': otp.MutableData})
archiver.update_class_map({'NSMutableString': otp.MutableString})
archiver.update_class_map({'ACOTPFolder': otp.OTPFolder})
archiver.update_class_map({'ACOTPAccount': otp.OTPAccount})

def read_archive(encrypted_otpauth_account, key_name: str="Authenticator") -> dict:
    # Get IV and key for wrapping archive
    iv = bytes(16)
    key = hashlib.sha256(key_name.encode('utf-8')).digest()

    # Decrypt wrapping archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_otpauth_account.read())
    data = data[:-data[-1]]

    # Decode wrapping archive
    return archiver.Unarchive(data).top_object()


@click.command(name="Create OTP Recovery")
@click.argument("backup_file", type=click.File("rb"))
@click.argument("output_file", type=click.File("wb"))
@click.password_option(confirmation_prompt=False)
def main(backup_file, output_file, password):
    ''' Opens the OTPAuth backup file given by 'BACKUP_FILE' for reading and writes QR
    codes for printing into 'OUTPUT_FILE'. Will prompt for password to decrypt the OTPAuth backup file 
    if not provided via commandline.
    '''
    # decode the wrapped archive first.
    # This wrapped archive is AES encrypted for some reason with a fixed password.
    # after this unarchiving has taken place  we can decrypt the actuall contents with the user defindec passwords.
    try:
        r = read_archive(backup_file, key_name="Authenticator")

    except RuntimeError:
        r = read_archive(backup_file, key_name="OTPAuth")

    accounts = otp.backup.decrypt(r, password)
    click.echo(click.style("Success", fg="green") + f": Read OTP auth backup. Storing PDF file to {output_file}")
    otp.document.to_pdf(accounts, output_file)

if __name__ == "__main__":
    main()
