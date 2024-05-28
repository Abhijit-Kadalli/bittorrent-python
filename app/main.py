import json
import sys
import bencodepy


bc = bencodepy.Bencode(encoding='utf-8')


def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)
        
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
        with open(sys.argv[2], "rb") as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get("announce", "").decode()
        file_length = torrent_info.get("info", {}).get("length", 0)
        print(f"Tracker URL: {tracker_url}")
        print(f"Length: {file_length}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
