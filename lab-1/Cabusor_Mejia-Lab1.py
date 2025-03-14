import socket
import struct
import json
import pickle
import threading

# Physical Layer
class PhysicalLayer:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_bits(self, data, host, port):
        self.socket.connect((host, port))
        self.socket.sendall(data)
        self.socket.close()

    def receive_bits(self, port):
        self.socket.bind(('localhost', port))
        self.socket.listen(1)
        conn, addr = self.socket.accept()
        data = conn.recv(1024)
        conn.close()
        return data

# Data Link Layer
class DataLinkLayer:
    def __init__(self):
        self.mac_address = "00:1A:2B:3C:4D:5E"

    def create_frame(self, data):
        frame = {
            'source_mac': self.mac_address,
            'destination_mac': "00:1A:2B:3C:4D:5F",
            'data': data
        }
        return pickle.dumps(frame)

    def extract_frame(self, frame):
        frame_dict = pickle.loads(frame)
        return frame_dict['data']  # Return only the data field (bytes)

# Network Layer
class NetworkLayer:
    def __init__(self):
        self.ip_address = "192.168.1.1"

    def create_packet(self, data):
        packet = {
            'source_ip': self.ip_address,
            'destination_ip': "192.168.1.2",
            'data': data
        }
        return pickle.dumps(packet)

    def extract_packet(self, packet):
        packet_dict = pickle.loads(packet)
        return packet_dict['data']  # Return only the data field (bytes)

# Transport Layer
class TransportLayer:
    def __init__(self):
        self.sequence_number = 0

    def create_segment(self, data):
        segment = {
            'sequence_number': self.sequence_number,
            'data': data
        }
        self.sequence_number += 1
        return pickle.dumps(segment)

    def extract_segment(self, segment):
        segment_dict = pickle.loads(segment)
        return segment_dict['data']  # Return only the data field (bytes)

# Session Layer
class SessionLayer:
    def __init__(self):
        self.session_id = 1

    def create_session(self, data):
        session = {
            'session_id': self.session_id,
            'data': data
        }
        self.session_id += 1
        return pickle.dumps(session)

    def extract_session(self, session):
        session_dict = pickle.loads(session)
        return session_dict['data']  # Return only the data field (bytes)

# Presentation Layer
class PresentationLayer:
    def encode_data(self, data):
        return json.dumps(data).encode('utf-8')

    def decode_data(self, data):
        return json.loads(data.decode('utf-8'))

# Application Layer
class ApplicationLayer:
    def __init__(self):
        self.http_request = {
            'method': 'GET',
            'uri': '/index.html',
            'version': 'HTTP/1.1'
        }

    def create_http_request(self, data):
        self.http_request['data'] = data
        return self.http_request

    def extract_http_request(self, http_request):
        return http_request['data']

# Server Function
def server():
    # Create instances of each layer
    physical = PhysicalLayer()
    data_link = DataLinkLayer()
    network = NetworkLayer()
    transport = TransportLayer()
    session = SessionLayer()
    presentation = PresentationLayer()
    application = ApplicationLayer()

    # Receiving end
    received_bits = physical.receive_bits(12345)
    received_frame = data_link.extract_frame(received_bits)
    received_packet = network.extract_packet(received_frame)
    received_segment = transport.extract_segment(received_packet)
    received_session = session.extract_session(received_segment)
    decoded_data = presentation.decode_data(received_session)
    received_http_request = application.extract_http_request(decoded_data)

    print("Received Data:", received_http_request)

# Client Function
def client():
    # Create instances of each layer
    physical = PhysicalLayer()
    data_link = DataLinkLayer()
    network = NetworkLayer()
    transport = TransportLayer()
    session = SessionLayer()
    presentation = PresentationLayer()
    application = ApplicationLayer()

    # Data to be sent
    data = "Hello, OSI Model. Yay!"

    # Application Layer
    http_request = application.create_http_request(data)
    encoded_data = presentation.encode_data(http_request)

    # Session Layer
    session_data = session.create_session(encoded_data)

    # Transport Layer
    segment = transport.create_segment(session_data)

    # Network Layer
    packet = network.create_packet(segment)

    # Data Link Layer
    frame = data_link.create_frame(packet)

    # Physical Layer
    physical.send_bits(frame, 'localhost', 12345)

# Simulating the OSI Model
def simulate_osi_model():
    # Start the server in a separate thread
    server_thread = threading.Thread(target=server)
    server_thread.start()

    # Wait for the server to start listening
    import time
    time.sleep(2)

    # Start the client
    client()

    # Wait for the server thread to finish
    server_thread.join()

if __name__ == "__main__":
    simulate_osi_model()