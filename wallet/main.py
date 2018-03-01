from unittest import TestCase
from binascii import unhexlify, hexlify
from bitcoin_tools import PrivateKey, blockchain_explorer_helper, UTXO, Tx, TxIn, TxOut, blockchain_explorer_helper, satoshi_to_bitcoin, generate_p2pkh_pub_key, generate_reedemScript, sha256_ripemd160, generate_p2sh_address, bitcoin_to_satoshi, SIGHASH_ALL, generate_p2sh_pub_key
from io import BytesIO
import json

class Main:
    def __init__(self, secret=None):
        if secret is None:
            self.keys = PrivateKey()
        else:
            self.keys = PrivateKey.import_private_key(secret)

        self.sec = self.keys.public_key.get_sec(compressed=True)

        # Retrieve all existing UTXO's for this wallet (if any)
        self.get_UTXOs()

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

        UTXOs = []
        if response[1] == 'block_cypher':
            if 'txrefs' in json_response:
                print("TX_REFS: {}".format(json_response.get('txrefs')))
                tx_refs = json_response.get('txrefs')

                if len(tx_refs) > 0:
                    filtered = list(filter(lambda x: 'spent' in x and x.get('spent') is False, tx_refs))
                    UTXOs = list(map(lambda x: UTXO.parse(x), filtered))


        self.UTXOs = UTXOs
        return self.UTXOs

    @classmethod
    def import_private_key(cls, secret):
        return cls(secret)
 
    def send_transaction(self, prev_tx, prev_index, target_addr, amount, change_amount, redeem_script=None, p2sh=False):
        # Initialize Inputs
        tx_inputs = []

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

        # Convert the change amount output to satoshis
        change_amount_in_satoshis = bitcoin_to_satoshi(change_amount)

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


