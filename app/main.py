import json
import sys
import bencodepy
import os


bc = bencodepy.Bencode(encoding='utf-8')


def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)

def get_info(metainfo_file):
    bc = bencodepy.Bencode(encoding="utf-8")
    with open(metainfo_file, "rb") as f:
        metadata = bencodepy.decode(f.read())
    tracker_url = metadata.get(b"announce").decode("utf-8")
    length = metadata.get(b"info", {}).get(b"length")
    return (tracker_url, length)
        
def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
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
        tracker_url, length = get_info(metainfo_file)
        print("Tracker URL:", tracker_url, "\nLength:", length)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
