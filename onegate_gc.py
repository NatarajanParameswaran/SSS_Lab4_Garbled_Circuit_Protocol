#!/usr/bin/env python
################################################################################
# Req'd Imports
################################################################################
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
################################################################################



################################################################################
# Logic Gates
################################################################################
def AND_gate(a, b): return a & b
def XOR_gate(a, b): return a ^ b
def OR_gate(a, b):  return a | b
################################################################################



################################################################################
# Garbler
################################################################################
# Generate Labels for wires
def generate_labels():
    return [get_random_bytes(16), get_random_bytes(16)]

# Perform AES Double Encryption
def double_encrypt(data, key1, key2):
    cipher1 = AES.new(key1, AES.MODE_ECB)
    cipher2 = AES.new(key2, AES.MODE_ECB)
    return cipher2.encrypt(cipher1.encrypt(data))

# Generate Garble Gate table
def garble_gate(gate_func, input1_labels, input2_labels):
    output_labels = generate_labels()
    garbled_table = []

    for i in [0, 1]:
        for j in [0, 1]:
            output_value = gate_func(i, j)
            encrypted_data = double_encrypt(output_labels[output_value],
                                            input1_labels[i],
                                            input2_labels[j])
            garbled_table.append(encrypted_data)

    return output_labels, garbled_table
################################################################################



################################################################################
# Evaluator
################################################################################
# Perform AES Double Decryption
def double_decrypt(encrypted_data, key1, key2):
    cipher1 = AES.new(key1, AES.MODE_ECB)
    cipher2 = AES.new(key2, AES.MODE_ECB)
    return cipher1.decrypt(cipher2.decrypt(encrypted_data))

# Evaluate the Garble Gate
def evaluate_garbled_gate(garbled_table, encoded_input1, encoded_input2,
                          output_labels):
    for entry in garbled_table:
        output_label = double_decrypt(entry, encoded_input1, encoded_input2)
        if output_label in output_labels:
            break
    return output_label
################################################################################



################################################################################
# Main Function
################################################################################
def main(argv):
    gates = {
                'AND': AND_gate,
                'XOR': XOR_gate,
                'OR' : OR_gate,
            }

    # Check for the inputs
    if not ((len(argv) == 3) and (argv[0] in gates.keys()) and \
       (argv[1] in ['0', '1']) and (argv[2] in ['0', '1'])):
        print(f'Kindly check your arguments, {argv}')
        exit(-1)

    # Generate Input labels and Garbled table
    A_labels, B_labels = generate_labels(), generate_labels()
    O_labels, Garbled_table = garble_gate(gates[argv[0]], A_labels, B_labels)
     print(f'Output Labels: {O_labels}')
     print(f'Garbled Table:')
     for entry in Garbled_table:
         print(f'\t\t{len(entry)}bytes - {entry}')

    # Evaluation starts here
    A, B = int(argv[1]), int(argv[2])
    encoded_A = A_labels[A]
    encoded_B = B_labels[B]
     print(f'Encoded A ({len(encoded_A)}bytes): {encoded_A}')
     print(f'Encoded B ({len(encoded_B)}bytes): {encoded_B}')

    # Call the Evaluator
    encoded_O = evaluate_garbled_gate(Garbled_table, encoded_A,
                                      encoded_B, O_labels)
    # print(f'Encoded O ({len(encoded_O)}bytes): {encoded_O}')
    O = O_labels.index(encoded_O)
    print(f'Output is {O}')

if __name__ == '__main__':
    main(sys.argv[1:])
################################################################################
