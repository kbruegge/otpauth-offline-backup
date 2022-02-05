"""
This is basically a stripped down copy of the code found in the original repository here: 

    https://github.com/CooperRS/decrypt-otpauth-files


"""

import base64

from enum import Enum
from urllib.parse import quote

from bpylist import archiver
from bpylist.archive_types import uid

from rncryptor import RNCryptor
from rncryptor import bord

# from . import backup, document

# backup = backup
# document = document

class ArchiveType(Enum):
    Unknown = 0
    HOTP = 1
    TOTP = 2

    @property
    def uri_value(self):
        if self.value == 0:
            return 'unknown'
        if self.value == 1:
            return 'hotp'
        if self.value == 2:
            return 'totp'


class Algorithm(Enum):
    Unknown = 0
    SHA1 = 1  # Used in case of Unknown
    SHA256 = 2
    SHA512 = 3
    MD5 = 4

    @property
    def uri_value(self):
        if self.value == 0:
            return 'sha1'
        if self.value == 1:
            return 'sha1'
        if self.value == 2:
            return 'sha256'
        if self.value == 3:
            return 'sha512'
        if self.value == 4:
            return 'md5'


class MutableString:

    def decode_archive(archive):
        return archive.decode('NS.string')


class MutableData:

    def decode_archive(archive):
        return bytes(archive.decode('NS.data'))


class OTPFolder:
    name = None
    accounts = None

    def __init__(self, name, accounts):
        self.name = name
        self.accounts = accounts

    def __repr__(self):
        return f'<OTPFolder: {self.name}>'

    def decode_archive(archive):
        name = archive.decode('name')
        accounts = archive.decode('accounts')
        return OTPFolder(name, accounts)


class OTPAccount:
    def __init__(self, label, issuer, secret, type, algorithm, digits, counter, period, refDate):
        self.label = label
        self.issuer = issuer
        self.secret = secret
        self.type = type
        self.algorithm = algorithm
        self.digits = digits
        self.counter = counter
        self.period = period
        self.refDate = refDate

    def __repr__(self):
        return f'<OTPAccount: {self.issuer} ({self.label})>'

    def decode_archive(archive):
        label = archive.decode("label")
        issuer = archive.decode("issuer")
        secret = bytes(archive.decode("secret"))
        archive_type = ArchiveType(archive.decode("type"))
        algorithm = Algorithm(archive.decode("algorithm"))
        digits = archive.decode("digits")
        counter = archive.decode("counter")
        period = archive.decode("period")
        refDate = archive.decode("refDate")
        return OTPAccount(label, issuer, secret, archive_type, algorithm, digits, counter, period, refDate)

    def from_dict(in_dict):
        label = in_dict.get("label")
        issuer = in_dict.get("issuer")
        secret = bytes(in_dict.get("secret"))
        archive_type = ArchiveType(in_dict.get("type"))
        algorithm = Algorithm(in_dict.get("algorithm"))
        digits = in_dict.get("digits")
        counter = in_dict.get("counter")
        period = in_dict.get("period")
        refDate = in_dict.get("refDate")
        return OTPAccount(label, issuer, secret, archive_type, algorithm, digits, counter, period, refDate)

    def otp_uri(self):
        otp_type = self.type.uri_value
        otp_label = quote(f'{self.issuer}:{self.label}')
        otp_parameters = {
            'secret': base64.b32encode(self.secret).decode("utf-8").rstrip("="),
            'algorithm': self.algorithm.uri_value,
            'period': self.period,
            'digits': self.digits,
            'issuer': self.issuer,
            'counter': self.counter,
        }
        otp_parameters = '&'.join([f'{str(k)}={quote(str(v))}' for (k, v) in otp_parameters.items() if v])
        return f'otpauth://{otp_type}/{otp_label}?{otp_parameters}'


class RawRNCryptor(RNCryptor):

    def post_decrypt_data(self, data):
        """Remove useless symbols which
           appear over padding for AES (PKCS#7)."""
        data = data[:-bord(data[-1])]
        return data


class DangerousUnarchive(archiver.Unarchive):

    def decode_object(self, index):
        if index == 0:
            return None

        obj = self.unpacked_uids.get(index)

        if obj is not None:
            return obj

        raw_obj = self.objects[index]

        # if obj is a (semi-)primitive type (e.g. str)
        if not isinstance(raw_obj, dict):
            return raw_obj

        class_uid = raw_obj.get('$class')
        if not isinstance(class_uid, uid):
            raise archiver.MissingClassUID(raw_obj)

        klass = self.class_for_uid(class_uid)
        obj = klass.decode_archive(archiver.ArchivedObject(raw_obj, self))

        self.unpacked_uids[index] = obj
        return obj
