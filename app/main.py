import json
import sys
import bencodepy
import os
import hashlib
import requests
import socket

bc = bencodepy.Bencode(encoding='utf-8')


def decode_bencode(bencoded_value):
    return bencodepy.Bencode(encoding="utf-8", encoding_fallback="all").decode(
        bencoded_value
    )

def get_info():
    metainfo_file = sys.argv[2]
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
        tracker_url, length, info_hash, piece_length, piece_hash = get_info()
        print("Tracker URL:", tracker_url, "\nLength:", length, "\nInfo Hash:", info_hash.hexdigest(), "\nPiece Length:", piece_length, "\nPiece Hash:", piece_hash)

    elif command == "peers":
        tracker_url, length, info_hash, piece_length, piece_hash = get_info()

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
        for i in range(0, len(peers), 6):
            ip = ".".join(str(peers[i+j]) for j in range(4))
            port = int.from_bytes(peers[i+4:i+6], "big")
            print(f'{ip}:{port}')
    elif command == "handshake":
        (ip, port) = sys.argv[3].split(":")
        tracker_url, length, info_hash, piece_length, piece_hash = get_info()
        
        handshake = b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00' + info_hash.digest() + b'69420694206942069420'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, int(port)))
            s.send(handshake)
            print(f"Peer ID: {s.recv(68)[48:].hex()}")

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
