import json
import sys
import bencodepy


bc = bencodepy.Bencode(encoding='utf-8')


def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)

def info_torrent(location):
    with open(location, 'rb') as f:
        data = f.read()
    decoded = bc.decode(data)
    tracker_url = decoded[b'announce']
    size_file = decoded[b'info'][b'length']
    return tracker_url, size_file
        
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
        location = sys.argv[2]

        tracker_url, size_file = info_torrent(location)
        print(f"Tracker URL: {tracker_url.decode()}")
        print(f"Size of file: {size_file}")

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
