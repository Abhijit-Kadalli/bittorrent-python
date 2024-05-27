import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        length = int(bencoded_value[:bencoded_value.index(b":")])
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        return bencoded_value[first_colon_index+1:length+first_colon_index+1], length+first_colon_index+1
    elif chr(bencoded_value[0]) == "i" and bencoded_value.find(b"e") != -1:
        end_index = bencoded_value.find(b"e")
        return int(bencoded_value[1:end_index]), end_index + 1
    elif chr(bencoded_value[0]) == "l" and chr(bencoded_value[-1]) == "e":
        bencoded_value = bencoded_value[1:-1]
        result = []
        while bencoded_value:
            value, len = decode_bencode(bencoded_value)
            result.append(value)
            bencoded_value = bencoded_value[len:]    
        return result
    else:
        raise NotImplementedError("Only strings, integers and lists are supported at the moment")
        


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
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
