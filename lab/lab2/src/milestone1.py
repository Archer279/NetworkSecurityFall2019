import logging,os,math,random
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet import PacketType, FIELD_NOT_SET
from packets import *
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.exceptions import InvalidKey, InvalidSignature

logger = logging.getLogger("playground.__connector__." + __name__)

class CrapTransport(StackingTransport):
    def __init__(self, transport, protocol):
        super().__init__(transport)
        self.protocol = protocol
        self._mode = self.protocol._mode
 
    def close(self):
        self.lowerTransport().close()

    def write(self, data):
        pkt = DataPacket()
        pkt.data = data
        pkt.signature = b'archer'
        self.lowerTransport().write(pkt.__serialize__())

class CrapProtocol(StackingProtocol):
    def __init__(self):
        super().__init__()
        #handshake
        if self._mode = 'CLIENT'
            self.deserializer = CrapPacketType.Deserializer()
            self._stage = "handshake"
            #gen private and pubilic key
            self.privateKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.publicKey = self.privateKey.public_key()
            self.publicKeyPEM = self.publicKey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            #gen cert and sign
            cert_file = open('clientCertificate.pem', 'rb')
            self.certPEM = cert_file.read()
            cert_file.close()
            self.cert = x509.load_pem_x509_certificate(self.certPEM, default_backend())
            key_file = open('clientPrivateKey.pem', 'rb')
            key_from_file = key_file.read()
            key_file.close()
            #signature using pk and sign
            self.signKey = load_pem_private_key(key_from_file, None, backend=default_backend())
            self.signature = self.signKey.sign(self.publicKeyPEM,padding.PSS( mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            #gen nonce and send packet
            self.nonce = random.randint(0, MAX_UINT32)
            self.shareKey = ''
        else:
            #For server:gen sk
            self.privateKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
            #gen pk
            self.publicKey = self.privateKey.public_key()
            self.publicKeyPEM = self.publicKey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            cert_file = open('serverCertificate.pem', 'rb')
            self.certPEM = cert_file.read()
            self.cert = x509.load_pem_x509_certificate(self.certPEM, default_backend())
            key_file = open('serverPrivateKey.pem', 'rb')

            key_from_file = key_file.read()
            key_file.close()
            #signature using pk and sign
            self.signKey = load_pem_private_key(key_from_file, None, backend=default_backend())
            self.signature = self.signKey.sign(self.publicKeyPEM, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            self.nonce = random.randint(0, MAX_UINT32)
            self.clientCert = ''
            self.shareKey = ''

    def connection_made(self, transport):
        self.transport = transport
        if self.mode == "client":
            self.connect_handshake()
            self.client_send_packetyi()
            print("Done!sending first packet.")

    def client_send_packetyi(self):    
        client_packetyi = HandshakePacket(status=0, nonce=self.nonceA, signature=self.sigA, pk=self.pubA_ser, cert=self.certA)
        self.transport.write(client_packetyi.__serialize__())

    def data_received_server(self, data):
        if packet.nonceSignature:
            self.server_verify_nonce(packet,self.nonceB)
            self._stage = "connected"
        else:
            self.server_verify_handshake(packet)
            self.server_send_packeter()

    def server_send_packeter(self):    
        server_packeter = HandshakePacket(status=1, nonce=self.nonceB, nonceSignature = self.nonceSignatureB, signature=self.sigB, pk=self.pubB_ser, cert=self.certB)
        self.transport.write(server_packeter.__serialize__())

    def data_received_client(self,data):
        self.client_handshake(packet)  
        self.client_send_packetsan()

    def client_handshake(self, packet):
        self.client_verify_sigB(packet)
        self.client_verify_nonce(packet,self.nonceA)
        self.shareB = self.privA.exchange(ec.ECDH(), load_pem_public_key(packet.pk, default_backend())) 
        self.certA, self.sigkA = self.gen_cert()
        self.nonceSignatureA = self.gen_noncesig(packet,self.sigkA)

    def client_send_packetsan(self):
        client_packetsan = HandshakePacket(status=1, nonceSignature = self.nonceSignatureA)
        self.transport.write(client_packetsan.__serialize__())

    def gen_noncesig(self, packet, signk):
        nonceSignature = signk.sign(str(packet.nonce).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return nonceSignature

    def server_sign(self, packet):
        client_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        clientVK= client_cert.public_key()
        try:
            clientVK.verify(packet.signature, packet.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except Exception as e:
            print("Server sign failed")
            packet= HandshakePacket(status=2)
            self.transport.write(packet.__serialize__())
            self.transport.close()

    def server_nonce(self,packet,nonce):
        client_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        clientVK= client_cert.public_key(
        try:
            clientVK.verify(packet.nonceSignature, str(nonceA).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except Exception as e:
            print("Server nonce failed")
            packet = HandshakePacket(status=2)
            self.transport.write(packet.__serialize__())
            self.transport.close()

    def client_sign(self, packet):    
        server_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        serverVK= server_cert.public_key()
        try:
            serverVK.verify(packet.signature, packet.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except Exception as e:
            print("Client sign failed")
            server_packet2_err = HandshakePacket(status=2)
            self.transport.write(packet.__serialize__())
            self.transport.close()

    def client_nonce(self,packet,nonce):
        server_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        serverVK = server_cert.public_key()
        try:
            serverVK.verify(packet.nonceSignature, str(nonceA).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except Exception as e:
            print("Client nonce failed")
            packet= HandshakePacket(status=2)
            self.transport.write(packet.__serialize__())
            self.transport.close()


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client"),
    lambda: CrapProtocol(mode="client")
    )
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server"),
    lambda: CrapProtocol(mode="server")
)
