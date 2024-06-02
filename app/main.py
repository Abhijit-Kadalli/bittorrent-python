import json
import sys
import bencodepy
import os
import hashlib
import requests

bc = bencodepy.Bencode(encoding='utf-8')


def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)

def get_info(metainfo_file):
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
        metainfo_file = sys.argv[2]
        try:
            os.path.exists(metainfo_file)
            metainfo_file = os.path.abspath(metainfo_file)
        except:
            raise NotImplementedError("File not found")
        tracker_url, length, info_hash, piece_length, piece_hash = get_info(metainfo_file)
        print("Tracker URL:", tracker_url, "\nLength:", length, "\nInfo Hash:", info_hash.hexdigest(), "\nPiece Length:", piece_length, "\nPiece Hash:", piece_hash)

    elif command == "peers":
        metainfo_file = sys.argv[2]
        try:
            os.path.exists(metainfo_file)
            metainfo_file = os.path.abspath(metainfo_file)
        except:
            raise NotImplementedError("File not found")
        tracker_url, length, info_hash, piece_length, piece_hash = get_info(metainfo_file)

        query = {
            "info_hash": info_hash.digest(),
            "peer_id": "69420694206942069420",
            "port": "6881",
            "uploaded": "0",
            "downloaded": "0",
            "left": length,
            "compact": "1",
        }
        response = requests.get(tracker_url, params=query)

        response_dict = bc.decode(response.content)
        peers = response_dict.get(b"peers", b"")
        for i in range(0, len(peers), 6):
            ip = ".".join(str(peers[i+j]) for j in range(4))
            port = int.from_bytes(peers[i+4:i+6], "big")
            print(ip + ':' + port)



    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
