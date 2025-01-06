import argparse


def extract_dd_field(hex_line):
    if not hex_line.startswith(":") or len(hex_line) < 11:
        return None
    hex_line = hex_line[1:]
    nn = int(hex_line[0:2], 16)
    dd_start_index = 8
    dd_end_index = 8 + nn * 2
    return hex_line[dd_start_index:dd_end_index]


def extract_starting_address(hex_line):
    if not hex_line.startswith(":") or len(hex_line) < 11:
        return None
    return int(hex_line[3:7], 16)


def split_into_chunks(data, chunk_size):
    if data is None:
        return None
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def swap_bytes(chunks):
    swapped_chunks = []
    for chunk in chunks:
        swapped_chunk = chunk[2:4] + chunk[0:2]
        swapped_chunks.append(swapped_chunk)
    return swapped_chunks


def combine_chunks_starting_with_94(chunks):
    combined_chunks = []
    i = 0
    while i < len(chunks):
        if chunks[i].startswith("94") and chunks[i] != "94F8" and i + 1 < len(chunks):
            combined_chunks.append(chunks[i] + chunks[i + 1])
            i += 2
        else:
            combined_chunks.append(chunks[i])
            i += 1
    return combined_chunks


def process_k_for_branching(k_binary):
    if k_binary[0] == "1":
        k_inverted = "".join("1" if bit == "0" else "0" for bit in k_binary)
        k_adjusted = int(k_inverted, 2) + 1
        k_adjusted <<= 1
        return -k_adjusted
    else:
        k_adjusted = int(k_binary, 2) << 1
        return k_adjusted


def preprocess_binary(stroka, name):
    if name == "subi":
        stroka = stroka[:-2] + "0" + stroka[-2:]
    else:
        stroka = stroka.zfill(16)
    return stroka


def match_command(stroka, mask, name):
    parameters = {"k": None, "P": None, "b": None, "d": None, "r": None}
    for i in range(len(mask)):
        if mask[i] not in ["k", "P", "b", "d", "r"] and stroka[i] != mask[i]:
            return None, parameters
    if "k" in mask:
        if name in ["ldi", "subi"]:
            k = "".join(stroka[i] for i in range(len(mask)) if mask[i] == "k")
        else:
            k = "".join(stroka[i] for i in range(len(mask)) if mask[i] == "k") + "0"
        parameters["k"] = hex(int(k, 2))[2:]
    if "P" in mask:
        P = "".join(stroka[i] for i in range(len(mask)) if mask[i] == "P")
        parameters["P"] = hex(int(P, 2))[2:]
    if "b" in mask:
        b = "".join(stroka[i] for i in range(len(mask)) if mask[i] == "b")
        parameters["b"] = hex(int(b, 2))[2:]
    if "d" in mask:
        d = "".join(stroka[i] for i in range(len(mask)) if mask[i] == "d")
        if name in ["ldi", "subi", "sbci"]:
            parameters["d"] = int(d, 2) + 16
        else:
            parameters["d"] = int(d, 2)
    if "r" in mask:
        r = "".join(stroka[i] for i in range(len(mask)) if mask[i] == "r")
        parameters["r"] = hex(int(r, 2))[2:]
    return name, parameters


COMMANDS = [
    {
        "name": "jmp",
        "mask": "1001 010k kkkk 110k kkkk kkkk kkkk kkkk".replace(" ", ""),
        "size": 4,
    },
    {
        "name": "call",
        "mask": "1001 010k kkkk 111k kkkk kkkk kkkk kkkk".replace(" ", ""),
        "size": 4,
    },
    {"name": "eor", "mask": "0010 01rd dddd rrrr".replace(" ", ""), "size": 2},
    {"name": "sbi", "mask": "1001 1010 PPPP Pbbb".replace(" ", ""), "size": 2},
    {"name": "cbi", "mask": "1001 1000 PPPP Pbbb".replace(" ", ""), "size": 2},
    {"name": "ldi", "mask": "1110 kkkk dddd kkkk".replace(" ", ""), "size": 2},
    {"name": "rjmp", "mask": "1100 kkkk kkkk kkkk".replace(" ", ""), "size": 2},
    {"name": "breq", "mask": "1111 00kk kkkk k001".replace(" ", ""), "size": 2},
    {"name": "out", "mask": "1011 1PPr rrrr PPPP".replace(" ", ""), "size": 2},
    {"name": "ldi", "mask": "1110 kkkk dddd kkkk".replace(" ", ""), "size": 2},
    {"name": "subi", "mask": "1010 kkkk dddd kkkk".replace(" ", ""), "size": 2},
    {"name": "cli", "mask": "1001 0100 1111 1000".replace(" ", ""), "size": 2},
    {"name": "brne", "mask": "1111 01kk kkkk k001".replace(" ", ""), "size": 2},
    {"name": "sbci", "mask": "0100 kkkk dddd kkkk".replace(" ", ""), "size": 2},
]


def process_hex_string(hex_line):
    starting_address = extract_starting_address(hex_line)
    dd_field = extract_dd_field(hex_line)
    chunks = split_into_chunks(dd_field, 4)
    combined_chunks = combine_chunks_starting_with_94(swap_bytes(chunks))
    binary_chunks = [bin(int(chunk, 16))[2:].zfill(8) for chunk in combined_chunks]
    current_address = starting_address
    for binary_string in binary_chunks:
        matched_command = None
        parameters = None
        command_size = 2
        for command in COMMANDS:
            preprocessed_binary = preprocess_binary(binary_string, command["name"])
            result, params = match_command(
                preprocessed_binary, command["mask"], command["name"]
            )
            if result:
                matched_command = result
                parameters = params
                command_size = command["size"]
                break
        if matched_command:
            if matched_command in ["jmp", "call"]:
                target_address = int(parameters["k"], 16)
                params_output = f"0x{target_address:x}"
            elif matched_command in ["rjmp", "breq", "brne"]:
                k_binary = "".join(
                    binary_string[i]
                    for i in range(len(command["mask"]))
                    if command["mask"][i] == "k"
                )
                offset = process_k_for_branching(k_binary)
                params_output = (
                    f".{offset} ; 0x{current_address + command_size + offset:x}"
                )
            elif matched_command in ["sbi", "cbi"]:
                params_output = f"0x{parameters['P']}, {int(parameters['b'], 16)}"
            elif matched_command == "out":
                params_output = f"0x{parameters['P']}, r{int(parameters['r'], 16)}"
            elif matched_command in ["ldi", "subi"]:
                params_output = f"r{parameters['d']}, 0x{parameters['k']}"
            elif matched_command == "sbci":
                params_output = f"r{parameters['d']}, 0x{parameters['k']}"
            elif matched_command == "eor":
                rd = parameters["d"]
                rr = int(parameters["r"], 16)
                params_output = f"r{rd}, r{rr}"
            else:
                params_output = ""
            print(f"0x{current_address:x}: {matched_command} {params_output}")
        else:
            print(f"0x{current_address:x}: unknown")
        current_address += command_size


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a hex string and decode it.")
    parser.add_argument("hex_string", help="A string in HEX format to be decoded")
    args = parser.parse_args()
    process_hex_string("args.hex_string")
