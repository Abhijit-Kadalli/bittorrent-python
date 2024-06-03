import json
import sys
import bencodepy
import os
import hashlib
import requests
import socket
import math

bc = bencodepy.Bencode(encoding='utf-8')


def decode_bencode(bencoded_value):
    return bencodepy.Bencode(encoding="utf-8", encoding_fallback="all").decode(
        bencoded_value
    )

def get_info(metainfo_file):
    try:
        os.path.exists(metainfo_file)
        metainfo_file = os.path.abspath(metainfo_file)
    except:
        raise NotImplementedError("File not found")
    with open(metainfo_file, "rb") as f:
        metadata = bencodepy.decode(f.read())
    tracker_url = metadata.get(b"announce").decode("utf-8")
    info_hash = hashlib.sha1(bencodepy.encode(metadata[b"info"]))
    piece_length = metadata.get(b"info", {}).get(b"piece length")
    piece_hash = ""
    for i in range(0, len(metadata.get(b"info", {}).get(b"pieces")), 20):
        piece_hash += metadata[b'info'][b'pieces'][i:i+20].hex()
    length = metadata.get(b"info", {}).get(b"length")
    return (tracker_url, length, info_hash, piece_length, piece_hash)

def get_peers(metadata_file):
    tracker_url, length, info_hash, piece_length, piece_hash = get_info(metadata_file)

    query = {
        "info_hash": info_hash.digest(),
        "peer_id": "69420694206942069420",
        "port": "6881",
        "uploaded": "0",
        "downloaded": "0",
        "left": length,
        "compact": "1",
    }
    response = decode_bencode(requests.get(tracker_url, query).content)
    peers = response["peers"]
    peers_list = []
    for i in range(0, len(peers), 6):
        ip = ".".join(str(peers[i+j]) for j in range(4))
        port = int.from_bytes(peers[i+4:i+6], "big")
        peers_list.append(f'{ip}:{port}')
    
    return peers_list

def handshake(ip, port, metainfo_file):
    tracker_url, length, info_hash, piece_length, piece_hash = get_info(metainfo_file)
        
    handshake = b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00' + info_hash.digest() + b'PC0001-7694471987235'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip, int(port)))
            s.send(handshake)
            #print(f"Peer ID: {s.recv(68)[48:].hex()}")
        
            return s.recv(68)[48:].hex()
        finally:
            s.close()

def download_piece(output_file):
    piece_index = int(sys.argv[5])
    torrent_file = sys.argv[4]

    with open(torrent_file, "rb") as f:
        torrent_data = f.read()

    decoded_torrent = decode_bencode(torrent_data)
    _, _, info_hash = get_info(torrent_file)

    peers = get_peers(torrent_file)
    peer_ip, peer_port = peers[0].split(":")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, int(peer_port)))
        handshake = b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00' + info_hash.digest() + b'PC0001-7694471987235'
        s.sendall(handshake)
        response_handshake = s.recv(len(handshake))
        length, msg_type = s.recv(4), s.recv(1)
        if msg_type != b'\x05':
            raise RuntimeError("Handshake failed")
        s.recv(int.from_bytes(length, byteorder="big") - 1)
        s.sendall(b"\x00\x00\x00\x01\x02")
        length, msg_type = s.recv(4), s.recv(1)
        while msg_type != b"\x01":
            length, msg_type = s.recv(4), s.recv(1)
        piece_length = decoded_torrent["info"]["piece length"]
        chuck_size = 16 * 1024
        if piece_index == (len(decoded_torrent["info"]["pieces"]) // 20) - 1:
            piece_length = decoded_torrent["info"]["length"] % piece_length
        piece = b""
        for i in range(math.ceil(piece_length / chuck_size)):
            msg_id = b"\x06"
            chunk_index = piece_index.to_bytes(4, byteorder="big")
            chunk_begin = (i * chuck_size).to_bytes(4, byteorder="big")
            if (
                i == math.ceil(piece_length / chuck_size) - 1
                and piece_length % chuck_size != 0
            ):
                chunk_length = (piece_length % chuck_size).to_bytes(4, byteorder="big")
            else:
                chunk_length = chuck_size.to_bytes(4, byteorder="big")
            message_length = (
                1 + len(chunk_index) + len(chunk_begin) + len(chunk_length)
            ).to_bytes(4, byteorder="big")
            request_message = (
                message_length + msg_id + chunk_index + chunk_begin + chunk_length
            )
            s.sendall(request_message)
            print(
                f"Requesting piece: {int.from_bytes(chunk_index, 'big')}, begin: {int.from_bytes(chunk_begin, 'big')}, length: {int.from_bytes(chunk_length, 'big')}"
            )
            msg = msg_id + chunk_index + chunk_begin + chunk_length
            msg = len(msg).to_bytes(4) + msg
            length, msg_type = int.from_bytes(s.recv(4)), s.recv(1)
            resp_index = int.from_bytes(s.recv(4))
            resp_begin = int.from_bytes(s.recv(4))
            block = b""
            to_get = int.from_bytes(chunk_length)
            while len(block) < to_get:
                block += s.recv(to_get - len(block))
            piece += block
        og_hash = decoded_torrent["info"]["pieces"][
            piece_index * 20 : piece_index * 20 + 20
        ]
        assert hashlib.sha1(piece).digest() == og_hash
        with open(output_file, "wb") as f:
            f.write(piece)


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        metainfo_file = sys.argv[2]
        tracker_url, length, info_hash, piece_length, piece_hash = get_info(metainfo_file)
        print("Tracker URL:", tracker_url, "\nLength:", length, "\nInfo Hash:", info_hash.hexdigest(), "\nPiece Length:", piece_length, "\nPiece Hash:", piece_hash)

    elif command == "peers":
        metainfo_file = sys.argv[2]
        peers_list = get_peers(metainfo_file)
        print("\n".join(peers_list))

    elif command == "handshake":
        metainfo_file = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        print(handshake(ip, port, metainfo_file))

    elif command == "download_piece":
        output_file = sys.argv[3]
        try:
            piece_index = download_piece(output_file)
            print(f"Piece {piece_index} downloaded to {output_file}.")
        except:
            raise RuntimeError("Failed to download piece")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
