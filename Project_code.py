import numpy as np
import time
import ipaddress
import os
import csv
from sklearn.neighbors import NearestNeighbors
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    load_pem_public_key,  # Import the load_pem_public_key function
)
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import (
    load_pem_x509_certificate,
)  # Import for loading certificate
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric import padding

# Constants
NUM_NODES = 100
GRID_SIZE = 1000  # in meters
MAX_NEIGHBORS = 5
COMMUNICATION_RANGE = 200  # in meters
MAX_SPEED = 15  # m/s
MIN_SPEED = 10  # m/s
MAX_ID = NUM_NODES
HEARTBEAT_INTERVAL = 5  # seconds
UPDATE_INTERVAL = 1  # seconds for updating positions
SIMULATION_DURATION = 2  # seconds for the entire simulation
AES_KEY_LENGTH = 32  # AES key length in bytes (256 bits)
# Group structure
groups = {group_id: {"members": set(), "leader": None} for group_id in range(NUM_NODES)}


# Function to generate unique IPv6 addresses for each node (only known to the leader)
def generate_ipv6_addresses(num_nodes):
    base_ipv6 = "2001:db8::"
    return [
        str(ipaddress.ip_address(base_ipv6) + node_id) for node_id in range(num_nodes)
    ]


# Function to generate a random AES key (256 bits)
def generate_aes_key():
    return os.urandom(AES_KEY_LENGTH)  # 256-bit key for AES


def generate_certificate(pseudonym, issuer_private_key, issuer_name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "{}".format(pseudonym))]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(issuer_name)]),
            critical=False,
        )
        .sign(issuer_private_key, hashes.SHA256())
    )
    return certificate, private_key


# Function to pad the IP address with random bits to make it 256 bits
def pad_ip_address(ip_address):
    padded_ip = ip_address.encode()
    padding_length = 32 - len(padded_ip)  # AES-256 operates on 32 bytes
    padding = os.urandom(padding_length)
    return padded_ip + padding


# Function to encrypt data using AES-256
def aes_256_encrypt(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# Multi-stage encryption using AES-256
def multi_stage_aes_256_encrypt(ip_address, keys):
    padded_ip = pad_ip_address(ip_address)
    encrypted_data = aes_256_encrypt(padded_ip, keys[0])
    return aes_256_encrypt(encrypted_data, keys[1])


# Function to save pseudonyms to a file
def save_pseudonyms_to_csv(node_id, timestamp, pseudonym):
    filename = "/Users/fatimasohail/Documents/Network Security/pseudonyms.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([node_id, timestamp, pseudonym])
        print(f"Saved pseudonym for Node {node_id} at {timestamp}: {pseudonym}")


# Initialize node properties
np.random.seed(0)
positions = np.random.randint(0, GRID_SIZE, size=(NUM_NODES, 2))
node_ids = np.arange(NUM_NODES)
node_properties = {
    node_id: {
        "position": position,
        "neighbors": [],
        "last_heartbeat": time.time(),
        "pseudonym": None,
        "aes_keys": [generate_aes_key() for _ in range(2)],
        "leader_id": None,  # Initialize leader_id
        "group_id": None,  # Initialize group_id
    }
    for node_id, position in zip(node_ids, positions)
}


# Function to update positions
def update_positions(positions, max_speed, min_speed, grid_size):
    speeds = np.random.uniform(min_speed, max_speed, size=(NUM_NODES, 2))
    directions = np.random.choice([-1, 1], size=(NUM_NODES, 2))
    movement = speeds * directions
    new_positions = positions + movement
    new_positions = np.clip(new_positions, 0, grid_size)
    return new_positions


# Function to find neighbors using KNN
def find_neighbors(positions):
    knn = NearestNeighbors(n_neighbors=MAX_NEIGHBORS, radius=COMMUNICATION_RANGE)
    knn.fit(positions)
    indices = knn.radius_neighbors(return_distance=False)
    neighbors_dict = {node: list(neighbors) for node, neighbors in enumerate(indices)}
    return neighbors_dict


def assign_groups():
    for group_id, group_info in groups.items():
        group_info["members"] = set()
    for node_id, node_info in node_properties.items():
        for neighbor_id in node_info["neighbors"]:
            groups[neighbor_id]["members"].add(node_id)
            # Update group_id for each node based on current neighbors
            node_properties[node_id]["group_id"] = neighbor_id
    for group_id, group_info in groups.items():
        print(f"Group {group_id} members: {group_info['members']}")


def initial_leader_election(timestamp):
    for group_id, group_info in groups.items():
        if group_info["members"]:
            group_info["leader"] = max(group_info["members"])
            leader_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            leader_public_key = leader_private_key.public_key()
            leader_public_key_pem = leader_public_key.public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo,
            )

            for member_id in group_info["members"]:
                # Update leader_id for each member in the group
                node_properties[member_id]["leader_id"] = group_info["leader"]
                node_properties[member_id][
                    "group_id"
                ] = group_id  # Also update group_id here

                ipv6 = ipv6_addresses[member_id]
                keys = node_properties[group_info["leader"]]["aes_keys"]
                pseudonym = multi_stage_aes_256_encrypt(ipv6, keys).hex()
                pseudonym_hash = hashlib.sha256(pseudonym.encode()).hexdigest()
                certificate, _ = generate_certificate(
                    pseudonym, leader_private_key, "LeaderNode{}".format(group_id)
                )
                certificate_pem = certificate.public_bytes(Encoding.PEM)

                # Store additional information
                node_properties[member_id]["pseudonym"] = pseudonym
                node_properties[member_id]["pseudonym_hash"] = pseudonym_hash
                node_properties[member_id]["certificate"] = certificate_pem
                node_properties[member_id]["leader_public_key"] = leader_public_key_pem

                save_pseudonyms_to_csv(member_id, timestamp, pseudonym)
                print(
                    f"Pseudonym: {pseudonym}, Hash: {pseudonym_hash}, Certificate: {certificate_pem}"
                )


def send_heartbeat(node_id):
    if node_properties[node_id]["is_leader"]:
        for neighbor_id in node_properties[node_id]["neighbors"]:
            receive_heartbeat(neighbor_id, node_id)


def receive_heartbeat(node_id, leader_id):
    node_properties[node_id]["leader_id"] = leader_id
    node_properties[node_id]["last_heartbeat"] = time.time()


def check_heartbeat(node_id):
    time_since_last_heartbeat = time.time() - node_properties[node_id]["last_heartbeat"]
    if time_since_last_heartbeat > 2 * HEARTBEAT_INTERVAL:
        current_timestamp = int(time.time())
        initial_leader_election(
            node_id,
            node_properties[node_id]["neighbors"],
            ipv6_addresses,
            current_timestamp,
        )


def check_current_leader(node_id):
    current_leader = node_properties[node_id]["leader_id"]
    if current_leader not in node_properties[node_id]["neighbors"]:
        # Get the current timestamp
        current_timestamp = int(time.time())
        # Call initial_leader_election with the current timestamp
        initial_leader_election(
            node_id,
            node_properties[node_id]["neighbors"],
            ipv6_addresses,
            current_timestamp,
        )


def verify_pseudonym_integrity(node_id):
    pseudonym = node_properties[node_id].get("pseudonym")
    stored_hash = node_properties[node_id].get("pseudonym_hash")
    if pseudonym and stored_hash:
        recomputed_hash = hashlib.sha256(pseudonym.encode()).hexdigest()
        if recomputed_hash == stored_hash:
            print(f"Integrity verified for Node {node_id}")
        else:
            print(f"Integrity check failed for Node {node_id}")


def verify_certificate(certificate_pem, issuer_public_key_pem):
    try:
        certificate = load_pem_x509_certificate(certificate_pem)
        issuer_public_key = load_pem_public_key(issuer_public_key_pem)
        # Specify the padding and the hash algorithm used for the signature in the certificate
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        # Check the validity period of the certificate
        return (
            certificate.not_valid_before
            <= datetime.utcnow()
            <= certificate.not_valid_after
        )
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Certificate verification error: {e}")
        return False


# Function to save node information to a CSV file
def save_node_info_to_file(
    node_id, time, position, speed, pseudonym, leader_id, group_id, first_call=False
):
    filename = "/Users/fatimasohail/Documents/Network Security/node_info.csv"
    mode = "w" if first_call else "a"
    with open(filename, mode, newline="") as file:
        writer = csv.writer(file)
        if first_call:
            writer.writerow(
                [
                    "Node ID",
                    "Time",
                    "Position",
                    "Speed",
                    "Pseudonym",
                    "Leader ID",
                    "Group ID",
                ]
            )
        writer.writerow(
            [node_id, time, position, speed, pseudonym, leader_id, group_id]
        )
        print(
            f"Time {time}: Saved info for Node {node_id} - Position {position}, Speed {speed}, Pseudonym {pseudonym}, Leader {leader_id}, Group {group_id}"
        )


ipv6_addresses = generate_ipv6_addresses(NUM_NODES)
start_time = time.time()
num_updates = int(SIMULATION_DURATION / UPDATE_INTERVAL)
first_data_entry = True

for update in range(num_updates):
    simulation_time = update * UPDATE_INTERVAL
    positions = update_positions(positions, MAX_SPEED, MIN_SPEED, GRID_SIZE)

    for node_id, position in zip(node_ids, positions):
        node_properties[node_id]["position"] = position

    neighbors_dict = find_neighbors(positions)
    for node_id, neighbors in neighbors_dict.items():
        node_properties[node_id]["neighbors"] = neighbors

    assign_groups()
    initial_leader_election(int(start_time + simulation_time))

    for node_id in node_ids:
        position = node_properties[node_id]["position"]
        speed = np.linalg.norm(
            update_positions(np.array([position]), MAX_SPEED, MIN_SPEED, GRID_SIZE)
            - np.array([position])
        )
        pseudonym = node_properties[node_id]["pseudonym"]
        leader_id = node_properties[node_id]["leader_id"]
        group_id = node_properties[node_id]["group_id"]
        save_node_info_to_file(
            node_id,
            simulation_time,
            position,
            speed,
            pseudonym,
            leader_id,
            group_id,
            first_call=first_data_entry,
        )
    first_data_entry = False

    for node_id in node_ids:
        verify_pseudonym_integrity(node_id)
        certificate_pem = node_properties[node_id].get("certificate")
        leader_public_key_pem = node_properties[node_id].get("leader_public_key")
        if certificate_pem and leader_public_key_pem:
            is_valid = verify_certificate(certificate_pem, leader_public_key_pem)
            if is_valid:
                print(f"Node {node_id}: Certificate is valid.")
            else:
                print(f"Node {node_id}: Certificate verification failed.")

    while time.time() < start_time + simulation_time + UPDATE_INTERVAL:
        pass

print("Simulation ended.")
