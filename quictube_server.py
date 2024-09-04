import asyncio
import logging
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

# Basic Logging Setup
logging.basicConfig(level=logging.INFO)

# Constants
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 4433
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

# WebRTC Configuration
RTC_CONFIG = RTCConfiguration(iceServers=[RTCIceServer(urls=['stun:stun.l.google.com:19302'])])


def generate_self_signed_cert(cert_file: str, key_file: str):
    """
    Generate a self-signed certificate and private key.
    """
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write the private key to a file
    with open(key_file, "wb") as key_file_out:
        key_file_out.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Create a self-signed certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QUICTube"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Write the certificate to a file
    with open(cert_file, "wb") as cert_file_out:
        cert_file_out.write(certificate.public_bytes(serialization.Encoding.PEM))


class WebTransportQuicConnectionProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)

    def quic_event_received(self, event):
        """
        Handle QUIC events.
        """
        super().quic_event_received(event)

        if isinstance(event, HandshakeCompleted):
            # HTTP/3 setup
            self.http.send_settings()

        # Handle HTTP/3 Events
        if isinstance(event, HeadersReceived):
            headers = event.headers
            logging.info(f"Headers received: {headers}")

            # Check for WebTransport handshake
            if (b":method", b"CONNECT") in headers and (b":protocol", b"webtransport") in headers:
                logging.info("WebTransport connection established!")
                stream_id = event.stream_id
                self.http.send_headers(stream_id, [(b":status", b"200")])

        elif isinstance(event, DataReceived):
            logging.info(f"Data received on stream {event.stream_id}: {event.data}")
            # Handle incoming data streams

    async def handle_webrtc_offer(self, offer_sdp):
        """
        Handle incoming WebRTC offer.
        """
        peer_connection = RTCPeerConnection(configuration=RTC_CONFIG)

        # Add WebRTC handlers (tracks, data channels, etc.)
        @peer_connection.on("track")
        def on_track(track):
            logging.info(f"New media track received: {track.kind}")
            # TODO: Handle track (add to stream, forward to viewers, etc.)

        # Set remote description and create answer
        await peer_connection.setRemoteDescription(RTCSessionDescription(sdp=offer_sdp, type='offer'))
        answer = await peer_connection.createAnswer()
        await peer_connection.setLocalDescription(answer)

        return answer


async def run_server():
    # Generate self-signed certificates if they do not exist
    try:
        generate_self_signed_cert(CERT_FILE, KEY_FILE)
    except Exception as e:
        logging.error(f"Failed to generate certificates: {e}")
        return

    # QUIC Configuration
    quic_config = QuicConfiguration(is_client=False)
    quic_config.alpn_protocols = H3_ALPN
    quic_config.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # Start HTTP/3 server with custom WebTransport protocol handler
    server = await serve(
        SERVER_HOST,
        SERVER_PORT,
        configuration=quic_config,
        create_protocol=WebTransportQuicConnectionProtocol
    )

    logging.info(f"QUICTube server running at https://{SERVER_HOST}:{SERVER_PORT}")

    # Keep the server running indefinitely
    try:
        logging.info("TEST")
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(run_server())
