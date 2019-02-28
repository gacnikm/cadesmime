import email
from datetime import datetime
from email.encoders import encode_base64
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.nonmultipart import MIMENonMultipart

import pytz
from asn1crypto.algos import SignedDigestAlgorithmId, SignedDigestAlgorithm, DigestAlgorithmId, DigestAlgorithm
from asn1crypto.cms import CertificateSet, SignerIdentifier, IssuerAndSerialNumber, \
    CMSAttributes, SignerInfo, SignedData, SignerInfos, Time, ContentInfo, ContentType, CMSAttribute, \
    CMSAttributeType, DigestAlgorithms, EncapsulatedContentInfo
from asn1crypto.core import load, UTCTime, OctetString, ParsableOctetString
from asn1crypto.tsp import SigningCertificateV2, ESSCertIDv2, IssuerSerial
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


class CADESMIMESignature(MIMEMultipart):
    def  __init__(self, _subtype='signed', boundary=None, _subparts=None,micalg="sha-256",
                 *, policy=email.policy.SMTPUTF8,
                 **_params):
        super(CADESMIMESignature, self).__init__(_subtype=_subtype, micalg=micalg, protocol="application/pkcs7-signature",
                                         policy=policy, **_params)

        self._content_mime = MIMEMultipart(policy=email.policy.SMTPUTF8)

    def attach(self, content):
        self._content_mime.attach(content)

    def set_sign_certificate(self, certificate, password):
        certificate_data = certificate.read()

        self._private_key, self._certificate, self._ca = load_key_and_certificates(certificate_data,  password.encode(),backend=default_backend())

        self._cert_serial = self._certificate.serial_number
        self._issuer_name = self._certificate.issuer

    def sign(self):
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(self._content_mime.as_bytes())
        message_digest = h.finalize()

        cs = CertificateSet()
        cs.append(load(self._certificate.public_bytes(Encoding.DER)))

        for ca_cert in self._ca:
            cs.append(load(ca_cert.public_bytes(Encoding.DER)))

        ec = ContentInfo({
            'content_type': ContentType('data'),
        })

        sident = SignerIdentifier({
            'issuer_and_serial_number': IssuerAndSerialNumber({
                'issuer': load(self._issuer_name.public_bytes(default_backend())),
                'serial_number': self._cert_serial,
            })
        })

        certv2 = ESSCertIDv2({
            'hash_algorithm': DigestAlgorithm({'algorithm': DigestAlgorithmId('sha256')}),
            'cert_hash': OctetString(self._certificate.fingerprint(hashes.SHA256())),
            'issuer_serial': IssuerSerial({
                'issuer':  load(self._issuer_name.public_bytes(default_backend())),
                'serial_number': self._cert_serial,
            }),
        })

        now = datetime.now().replace(microsecond=0, tzinfo=pytz.utc)  # .isoformat()

        sattrs = CMSAttributes({
            CMSAttribute({
                'type': CMSAttributeType('content_type'),
                'values': ["data"]
            }),
            CMSAttribute({
                'type': CMSAttributeType('message_digest'),
                'values': [message_digest]
            }),
            CMSAttribute({
                'type': CMSAttributeType('signing_time'),
                'values': (Time({'utc_time': UTCTime(now)}),)
            }),
            CMSAttribute({
                'type': CMSAttributeType('signing_certificate_v2'),
                'values': [SigningCertificateV2({
                    'certs': (certv2,)
                })]
            })
        })

        signature = self._private_key.sign(sattrs.dump(), padding.PKCS1v15(),
                                     hashes.SHA256())  #

        si = SignerInfo({
            'version': 'v1',
            'sid': sident,
            'digest_algorithm': DigestAlgorithm({
                'algorithm': DigestAlgorithmId('sha256')
            }),
            'signed_attrs': sattrs,
            'signature_algorithm': SignedDigestAlgorithm({
                'algorithm': SignedDigestAlgorithmId('rsassa_pkcs1v15')
            }),
            'signature': signature,
        })

        da = DigestAlgorithms((DigestAlgorithm({'algorithm': DigestAlgorithmId('sha256')
                                                }),))
        signed_data = SignedData({
            'version': 'v1',
            'encap_content_info': ec,
            'certificates': cs,
            'digest_algorithms': da,
            'signer_infos': SignerInfos((si,))
        })

        ci = ContentInfo({
            'content_type': ContentType('signed_data'),
            'content': signed_data
        })

        self._signature_mime = MIMEApplication(ci.dump(),_subtype="pkcs7-signature", name="smime.p7s",
                                               policy=email.policy.SMTPUTF8)
        self._signature_mime.add_header('Content-Disposition', 'attachment; filename=smime.p7s')

        super(CADESMIMESignature, self).attach(self._content_mime)
        super(CADESMIMESignature, self).attach(self._signature_mime)


class CADESMIMEmbedded(MIMENonMultipart):
    def __init__(self, _subtype="pkcs7-mime", smime_type="signed-data",name="smime.p7m",
                 *, policy=email.policy.SMTPUTF8,
                 **_params):
        super(CADESMIMEmbedded, self).__init__(_maintype='application',_subtype=_subtype, smime_type=smime_type,name=name,
                                         policy=policy, **_params)
        self.add_header("Content-Disposition","attachment", filename="smime.p7m")

        self._content_mime = MIMEMultipart(policy=email.policy.SMTPUTF8)

    def attach(self, content):
        self._content_mime.attach(content)

    def set_sign_certificate(self, certificate, password):
        certificate_data = certificate.read()

        self._private_key, self._certificate, self._ca = load_key_and_certificates(certificate_data,  password.encode(),backend=default_backend())

        self._cert_serial = self._certificate.serial_number
        self._issuer_name = self._certificate.issuer

    def sign(self):
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(self._content_mime.as_bytes())
        message_digest = h.finalize()

        cs = CertificateSet()
        cs.append(load(self._certificate.public_bytes(Encoding.DER)))

        for ca_cert in self._ca:
            cs.append(load(ca_cert.public_bytes(Encoding.DER)))

        ec = EncapsulatedContentInfo({
            'content_type': ContentType('data'),
            'content': ParsableOctetString(self._content_mime.as_bytes())
        })

        sident = SignerIdentifier({
            'issuer_and_serial_number': IssuerAndSerialNumber({
                'issuer': load(self._issuer_name.public_bytes(default_backend())),
                'serial_number': self._cert_serial,
            })
        })

        certv2 = ESSCertIDv2({
            'hash_algorithm': DigestAlgorithm({'algorithm': DigestAlgorithmId('sha256')}),
            'cert_hash': OctetString(self._certificate.fingerprint(hashes.SHA256())),
            'issuer_serial': IssuerSerial({
                'issuer':  load(self._issuer_name.public_bytes(default_backend())),#[GeneralName({'directory_name': self._issuer_name.public_bytes(default_backend())})],
                'serial_number': self._cert_serial,
            }),
        })

        now = datetime.now().replace(microsecond=0, tzinfo=pytz.utc)

        sattrs = CMSAttributes({
            CMSAttribute({
                'type': CMSAttributeType('content_type'),
                'values': ["data"]
            }),
            CMSAttribute({
                'type': CMSAttributeType('message_digest'),
                'values': [message_digest]
            }),
            CMSAttribute({
                'type': CMSAttributeType('signing_time'),
                'values': (Time({'utc_time': UTCTime(now)}),)
            }),
            # isti k v
            CMSAttribute({
                'type': CMSAttributeType('signing_certificate_v2'),
                'values': [SigningCertificateV2({
                    'certs': (certv2,)
                })]
            })
        })

        signature = self._private_key.sign(sattrs.dump(), padding.PKCS1v15(),
                                     hashes.SHA256())

        si = SignerInfo({
            'version': 'v1',
            'sid': sident,
            'digest_algorithm': DigestAlgorithm({
                'algorithm': DigestAlgorithmId('sha256')
            }),
            'signed_attrs': sattrs,
            'signature_algorithm': SignedDigestAlgorithm({
                'algorithm': SignedDigestAlgorithmId('rsassa_pkcs1v15')
            }),
            'signature': signature,
        })

        da = DigestAlgorithms((DigestAlgorithm({'algorithm': DigestAlgorithmId('sha256')
                                                }),))
        signed_data = SignedData({
            'version': 'v3',
            'encap_content_info': ec,
            'certificates': cs,
            'digest_algorithms': da,
            'signer_infos': SignerInfos((si,))
        })

        ci = ContentInfo({
            'content_type': ContentType('signed_data'),
            'content': signed_data
        })

        self.set_payload(ci.dump())
        encode_base64(self)

