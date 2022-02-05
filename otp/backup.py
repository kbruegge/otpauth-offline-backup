import hashlib
import otp

from Crypto.Cipher import AES



def decrypt(archive, password: str) -> list[otp.OTPAccount]:
    '''Reads the accounts from an OTP backup with the given password.

    Parameters
    ----------
    archive : [type]
        [description]
    password : str
        the password needed to decrypt the file

    Returns
    -------
    list[otp.OTPAccount]
        the entries found in the backup file after succesfull decryption

    Raises
    ------
    ValueError
        If unknown file format is read.
    '''
    if archive['Version'] == 1.0:
        accounts = _decrypt_backup_verison_1_0(archive, password)
    elif archive['Version'] == 1.1:
        accounts = _decrypt_backup_version_1_1(archive, password)
    else:
        print(f'Encountered unknow file version: {archive["Version"]}')
        raise ValueError(f'Encountered unknow file version: {archive["Version"]}')
    return accounts


def _decrypt_backup_verison_1_0(archive, password):
    # Get IV and key for actual archive
    iv = hashlib.sha1(archive['IV'].encode('utf-8')).digest()[:16]
    salt = archive['Salt']
    key = hashlib.sha256((salt + '-' + password).encode('utf-8')).digest()

    # Decrypt actual archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(archive['WrappedData'])
    data = data[:-data[-1]]

    # Decode actual archive
    archive = otp.DangerousUnarchive(data).top_object()

    return [account for folder in archive['Folders'] for account in folder.accounts]


def _decrypt_backup_version_1_1(archive, password):
    # Decrypt using RNCryptor
    data = data = otp.RawRNCryptor().decrypt(archive['WrappedData'], password)

    # Decode archive
    archive = otp.DangerousUnarchive(data).top_object()

    return [account for folder in archive['Folders'] for account in folder.accounts]
