import hashlib
import otp

from Crypto.Cipher import AES


def decrypt_account(archive, password):
    if archive['Version'] == 1.1:
        account = decrypt_account_version_1_1(archive, password)
    elif archive['Version'] == 1.2:
        account = decrypt_account_version_1_2(archive, password)
    else:
        print(f'Encountered unknow file version: {archive["Version"]}')
        raise ValueError(f'Encountered unknow file version: {archive["Version"]}')

    return [account]

def decrypt_account_version_1_1(archive, password):
    # Get IV and key for actual archive
    iv = hashlib.sha1(archive['IV']).digest()[:16]
    salt = archive['Salt']
    key = hashlib.sha256((salt + '-' + password).encode('utf-8')).digest()

    # Decrypt actual archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(archive['Data'])
    data = data[:-data[-1]]

    # Decode actual archive
    archive = otp.DangerousUnarchive(data).top_object()

    # Construct OTPAccount object from returned dictionary
    return otp.OTPAccount.from_dict(archive)


def decrypt_account_version_1_2(archive, password):
    # Decrypt using RNCryptor
    data = data = otp.RawRNCryptor().decrypt(archive['Data'], password)

    # Decode archive
    archive = otp.DangerousUnarchive(data).top_object()

    # Construct OTPAccount object from returned dictionary
    return otp.OTPAccount.from_dict(archive)

