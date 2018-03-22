from unittest import TestCase
from binascii import unhexlify, hexlify
from bitcoin_tools import PrivateKey, blockchain_explorer_helper as BlockExplorer, UTXO, Tx, TxIn, TxOut, blockchain_explorer_helper, satoshi_to_bitcoin, generate_p2pkh_pub_key, generate_reedemScript, sha256_ripemd160, generate_p2sh_address, bitcoin_to_satoshi, SIGHASH_ALL, generate_p2sh_pub_key, Script, encode_base58_checksum, decode_base58
from io import BytesIO
import json
import sys

class Main:
    def __init__(self, secret=None, UTXOs=None):
        if secret is None:
            self.keys = PrivateKey()
        else:
            self.keys = PrivateKey.import_private_key(secret)

        self.sec = self.keys.public_key.get_sec(compressed=True)

        # Retrieve all existing UTXO's for this wallet (if any)
        # print("Get UTXOs called")
        if UTXOs is None:
            self.get_UTXOs()

        self.balance = self.get_balance()

    def get_private_key(self):
        return self.keys.get_WIF(mainnet=False)

    def is_public_key_valid(self):
        return self.keys.is_on_curve()

    def get_address(self, mainnet=False):
        return self.keys.public_key.get_address(self.sec, mainnet)

    def get_balance(self, mainnet=False):
        response = blockchain_explorer_helper.request_balance(self.get_address())

        json_response = response.json()

        return json_response["balance"]


    def get_UTXOs(self, mainnet=False):
        response = blockchain_explorer_helper.request_UTXOs(self.get_address())
        json_response = response[0].json()
        print("JSON Response object: {}".format(response[0].json()))
        print("JSON Response schema: {}".format(response[1]))

        UTXOs = []
        if response[1] == 'block_cypher' and 'txrefs' in json_response:
                # print("Has tx refs")
                tx_refs = json_response.get('txrefs')
                # print("TX Refs: {}".format(tx_refs))

                if len(tx_refs) > 0:
                    filtered = list(filter(lambda x: 'spent' in x and x.get('spent') is False, tx_refs))
                    # print("Filtered: {}".format(filtered))
                    UTXOs = list(map(lambda x: UTXO.parse(x), filtered))
                    # print("UTXOs: {}".format(UTXOs))

        # Do I need this?
        if response[1] == 'block_trail' and 'data' in json_response:
            data = json_response.get('data')
            UTXOs = list(map(lambda x: UTXO.parse(x), data))

        self.UTXOs = UTXOs

        # Sor the UTXO's according to value
        self.UTXOs.sort(key=lambda x: x.value, reverse=False)

        # print("\nUTXOs: {} | Address: {}".format(self.UTXOs, self.get_address()))
        return self.UTXOs

    @classmethod
    def import_private_key(cls, secret):
        return cls(secret)

    def calculate_inputs(self, target_amount):
        # Current Time Complexity: O (n log n)
        # Self.UTXOs was sorted on init
        low_pos = 0
        high_pos = len(self.UTXOs) - 1

        target_amount = bitcoin_to_satoshi(target_amount)
        
        lowest_difference_to_target = sys.maxsize
        current_lowest_input = sys.maxsize

        inputs = []
        while low_pos <= high_pos:
            # Values at each index position
            low_val = self.UTXOs[low_pos].value
            high_val = self.UTXOs[high_pos].value

            # low_val is the lowest valued item in a sorted list, if it's greater than the target amount, we don't need to include anymore inputs
            if low_val > target_amount:
                inputs = []
                inputs.append((self.UTXOs[low_pos].tx_hash, self.UTXOs[low_pos].tx_index))
                break

            # Add low_pos and high_pos value to see if we need to use 2 inputs
            input_amount = low_val + high_val

            # input_amount is greater than or equal to target_amount and lower than the current_lowest_input
            if target_amount <= input_amount < current_lowest_input:
                inputs = []

                # Check if the high_pos value is sufficient as input
                if high_val >= target_amount:
                    inputs.append((self.UTXOs[high_pos].tx_hash, self.UTXOs[high_pos].tx_index))
                    input_amount = high_val    
                else:
                    # Use the combination of 2 inputs
                    inputs.append((self.UTXOs[low_pos].tx_hash, self.UTXOs[low_pos].tx_index))
                    inputs.append(((self.UTXOs[high_pos].tx_hash, self.UTXOs[high_pos].tx_index)))

                lowest_difference_to_target = input_amount - target_amount
                current_lowest_input = input_amount

            # input_amount is less than the target_amount, but can we add the next element to equal or be greater than the target and still be the lowest inputs
            if target_amount > input_amount:
                three_inputs = low_val + self.UTXOs[low_pos + 1].value + high_val
                difference_between_inputs = three_inputs - target_amount

                if target_amount <= three_inputs < current_lowest_input and difference_between_inputs < lowest_difference_to_target:
                    inputs = []
                    current_lowest_input = three_inputs
                    inputs.append((self.UTXOs[low_pos].tx_hash, self.UTXOs[low_pos].tx_index))
                    inputs.append((self.UTXOs[low_pos + 1].tx_hash, self.UTXOs[low_pos + 1].tx_index))
                    inputs.append(((self.UTXOs[high_pos].tx_hash, self.UTXOs[high_pos].tx_index)))

            # If input amount equals the target break
            if input_amount == target_amount:
                break

            # if input_amount is greater than target amount, decrement high_pos else increment low_pos
            if input_amount > target_amount:
                high_pos -= 1
            else:
                low_pos += 1

        return inputs
    
    #  def send_transaction(self, prev_tx, prev_index, target_addr, amount, change_amount, redeem_script=None, p2sh=False):
    def send_transaction(self,target_addr, amount, redeem_script=None, p2sh=False):
        # Initialize Inputs
        inputs_to_consume = self.calculate_inputs(amount)

        tx_inputs = []

        for inputs in inputs_to_consume:
            print("TX Hash: {}".format(inputs[0].encode()))
            prev_tx = unhexlify(inputs[0].encode())
            prev_index = inputs[1]

            # Create a tx input for transaction
            tx_inputs.append(TxIn
                            (prev_hash=prev_tx,
                            prev_index=prev_index,
                            script_sig=b'',
                            sequence=0xffffffff
                            ))

        # Initialize Outputs for transaction
        tx_outputs = []

        # decode the hash160 from the target address, to be used in the p2pkh (LOCKING SCRIPT) on this output
        # Use the target_addr_h160 in create the p2pkh (LOCKING SCRIPT) on this output
        print("Target Address: {}".format(target_addr))

        # if p2sh:
            # print("Creating p2sh pubkey:")
            # target_output_script_pub_key = generate_p2sh_pub_key(target_addr)
            # print("P2SH CREATED: {}".format(target_output_script_pub_key))
        # else:    
        target_output_script_pub_key = generate_p2pkh_pub_key(target_addr)

        print("Target Output: {}".format(hexlify(target_output_script_pub_key)))

        # Convert the target output amount to satoshis
        output_amount_in_satoshis = bitcoin_to_satoshi(amount)

        # Create the TX OUTPUT, pass in the amount and the LOCKING SCRIPT
        tx_outputs.append(TxOut
                          (amount=output_amount_in_satoshis,
                           script_pub_key=target_output_script_pub_key
                           ))

        # decode the hash160 for the change address (Sending coins back to sender)
        # Create the p2pkh (LOCKING SCRIPT) for the change output (sending back to sender)

        #TODO: CHECK CHANGE ADDRESS TYPE TO GENERATE THE CORRECT SCRIPT PUB KEY
        change_output_p2pkh = generate_p2pkh_pub_key(self.get_address(mainnet=False))

        # Temp solution for calculating change amount
        print("Balance: {}\n".format(self.balance))
        print("Output Amount: {}\n".format(output_amount_in_satoshis))
        difference_in_satoshis = int((self.balance - output_amount_in_satoshis) * 0.1)
        change_amount_in_satoshis = (self.balance - output_amount_in_satoshis) - difference_in_satoshis
        print("Change Amount: {}\n".format(change_amount_in_satoshis))

        # Convert the change amount output to satoshis
        # change_amount_in_satoshis = bitcoin_to_satoshi(change_amount)

        # Create a tx output for the change transaction
        tx_outputs.append(TxOut
            (
            amount=change_amount_in_satoshis,
            script_pub_key=change_output_p2pkh
        ))

        # sign with tx object with SIGHASH_ALL, sender is signing all the inputs and outputs
        sig_hash = SIGHASH_ALL

        # Create the Tx object with all the inputs and outputs created above
        transaction = Tx(version=1,
                         tx_ins=tx_inputs,
                         tx_outs=tx_outputs,
                         locktime=0,
                         testnet=True)

        balance_in_btc = satoshi_to_bitcoin(self.balance)
        target_in_btc = satoshi_to_bitcoin(output_amount_in_satoshis)
        change_amount_in_btc = satoshi_to_bitcoin(change_amount_in_satoshis)
        print("Balance: {} | Target: {} | Change Amount: {}".format(balance_in_btc, target_in_btc, change_amount_in_btc))


        print("")
        # print("Transaction: {}".format(transaction))

        # Hash of the message to sign
        # if p2sh:
            # z = transaction.sig_hash(0, sig_hash, redeem_script)
        # else:
        z = transaction.sig_hash(0, sig_hash)

        # Sign z with the private key
        der = self.keys.sign(z).der()

        # Add the sighash to the der signature
        sig = der + bytes([sig_hash])

        # Input a new Script sig to unlock the input
        sec = unhexlify(self.keys.public_key.get_sec(compressed=True))

        # Creating the p2pkh script sig to UNLOCK the input at index 0
        unlocking_script = Script([sig, sec])
        transaction.tx_ins[0].script_sig = unlocking_script

        # Create a block explorer instance and serialize transaction
        raw_tx = hexlify(transaction.serialize()).decode('ascii')
        print(raw_tx)

        # print("RAW TX: {}".format(raw_tx))
        return BlockExplorer.send_tx(raw_tx)


