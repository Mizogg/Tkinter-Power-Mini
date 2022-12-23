#!/usr/bin/env python3   OFFLINE VERSION ETH Vanity
# -*- coding: utf-8 -*-
#Created by @Mizogg 23.12.2022 https://t.me/CryptoCrackersUK
import hmac, struct, codecs, sys, os, binascii, hashlib, re, webbrowser, random, string
from tkinter import * 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext as tkst
from tkinter.ttk import *
import secp256k1 as ice
try:
    import base58
    import ecdsa
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import numpy as np
    import trotter

except ImportError:
    import subprocess
    subprocess.check_call(["python", '-m', 'pip', 'install', 'base58'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'ecdsa'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'simplebloomfilter'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bitarray==1.9.2'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bit'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'numpy'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'trotter'])
    import base58
    import ecdsa
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    import requests
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import numpy as np
    import trotter

with open('btc.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)

with open('eth.bf', "rb") as fp:
    bloom_filtereth = BloomFilter.load(fp)
    
def countadd():
    addr_count = len(bloom_filterbtc) + len(bloom_filtereth)
    addr_count_print = (f'BTC Addresses {len(bloom_filterbtc)} ETH Addresses {len(bloom_filtereth)} Total Loaded and Checking : {addr_count}')
    return addr_count_print

lines = '=' * 54
# For Menu
def donothing():
   x = 0

def openweb():
   x = webbrowser.open("https://mizogg.co.uk")
   
def opentelegram():
   x = webbrowser.open("https://t.me/CryptoCrackersUK")

def bin2dec(value):
    return int(value, 2)

def bin2hex(value):
    return hex(int(value, 2))
    
def bin2bit(value):
    length = len(bin(int(value, 2)))
    length -=2
    return length
    
def bit2dec(value):
    return 2**(int(value))

def bit2hex(value):
    value = 2**(int(value))
    return hex(value)
    
def bit2bin(value):
    value = 2**(int(value))
    return bin(value)

def dec2bin(value):
    return bin(int(value))

def dec2hex(value):
    return hex(int(value))
    
def dec2bit(value):
    length = len(bin(int(value)))
    length -=2
    return length

def hex2bin(value):
    return bin(int(value, 16))

def hex2dec(value):
    return int(value, 16)
    
def hex2bit(value):
    length = len(bin(int(value, 16)))
    length -=2
    return length

def addr2int(value):
    dataadd= (f'''{lines}
Bitcoin Address : {value} : 
{lines}
''')
    return dataadd

def int2addr(self, value):
    dec=int(value)
    HEX = "%064x" % dec
    caddr = ice.privatekey_to_address(0, True, dec) #Compressed
    uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
    p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
    bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
    ethaddr = ice.privatekey_to_ETH_address(dec)[2:] # [2:]
    if caddr in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n {caddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
        with open("foundcaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if p2sh in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n {p2sh}\nDecimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX} \n'
        with open("foundp2sh.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n {bech32}\n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX} \n'
        with open("foundbech32.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if ethaddr in bloom_filtereth:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n 0x{ethaddr}\n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX} \n'
        with open("foundeth.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    dataadd= (f'''{lines}
Bitcoin Address : {caddr} : 
Bitcoin Address : {uaddr} : 
Bitcoin Address : {p2sh} : 
Bitcoin Address : {bech32} : 
Ethereum Address : 0x{ethaddr} : 
{lines}
''')
    return dataadd
# BrainWallet
class BrainWallet:
    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = str(hashlib.sha256(
            passphrase.encode('utf-8')).hexdigest())
        address =  BrainWallet.generate_address_from_private_key(private_key)
        return private_key, address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        sha256_bdec = hashlib.sha256(public_key_bytes)
        sha256_bdec_digest = sha256_bdec.digest()
        ripemd160_bdec = hashlib.new('ripemd160')
        ripemd160_bdec.update(sha256_bdec_digest)
        ripemd160_bdec_digest = ripemd160_bdec.digest()
        ripemd160_bdec_hex = codecs.encode(ripemd160_bdec_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bdec_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        sha256_nbdec = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbdec_digest = sha256_nbdec.digest()
        sha256_2_nbdec = hashlib.sha256(sha256_nbdec_digest)
        sha256_2_nbdec_digest = sha256_2_nbdec.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbdec_digest, 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        wallet = BrainWallet.base58(address_hex)
        return wallet

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        address_int = int(address_hex, 16)
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string
        
def create_valid_mnemonics(strength):

    rbytes = os.urandom(strength // 8)
    h = hashlib.sha256(rbytes).hexdigest()
    
    b = ( bin(int.from_bytes(rbytes, byteorder="big"))[2:].zfill(len(rbytes) * 8) \
         + bin(int(h, 16))[2:].zfill(256)[: len(rbytes) * 8 // 32] )
    
    result = []
    for i in range(len(b) // 11):
        idx = int(b[i * 11 : (i + 1) * 11], 2)
        result.append(wordlist[idx])

    return " ".join(result)
# WORD Wallet
order	= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
with open('files/english.txt') as f:
    wordlist = f.read().split('\n')
def mnem_to_seed(words):
    salt = 'mnemonic'
    seed = hashlib.pbkdf2_hmac("sha512",words.encode("utf-8"), salt.encode("utf-8"), 2048)
    return seed

def bip39seed_to_bip32masternode(seed):
    h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code

def parse_derivation_path(str_derivation_path="m/44'/0'/0'/0/0"):
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def parse_derivation_path2(str_derivation_path="m/49'/0'/0'/0/0"):
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/49'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def derive_bip32childkey(parent_key, parent_chain_code, i):
    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & 0x80000000) != 0:
        key = b'\x00' + parent_key
    else:
        key = bit.Key.from_bytes(parent_key).public_key
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % order
        if a < order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code
    
def bip39seed_to_private_key(bip39seed, n=1):
    const = "m/44'/0'/0'/0/"
    str_derivation_path = "m/44'/0'/0'/0/0"
    derivation_path = parse_derivation_path(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key
    
def bip39seed_to_private_key2(bip39seed, n=1):
    const = "m/49'/0'/0'/0/"
    str_derivation_path = "m/49'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key3(bip39seed, n=1):
    const = "m/84'/0'/0'/0/"
    str_derivation_path = "m/84'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key4(bip39seed, n=1):
    const = "m/44'/60'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/44'/60'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key
    
derivation_total_path_to_check = 1


def rwoffline(self, mnem):
    startadd = self._txt_inputvanword.get()
    startadd1 = self._txt_inputvanword1.get()
    startadd2 = self._txt_inputvanword2.get()
    startadd3 = self._txt_inputvanword3.get()
    startadd4 = self._txt_inputvanword4.get()
    seed = mnem_to_seed(mnem)
    pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
    pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
    pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
    pvk4 = bip39seed_to_private_key4(seed, derivation_total_path_to_check)
    dec = (int.from_bytes(pvk, "big"))
    HEX = "%064x" % dec
    dec2 = (int.from_bytes(pvk2, "big"))
    HEX2 = "%064x" % dec2
    dec3 = (int.from_bytes(pvk3, "big"))
    HEX3 = "%064x" % dec3
    dec4 = (int.from_bytes(pvk4, "big"))
    HEX4 = "%064x" % dec4
    cpath = "m/44'/0'/0'/0/0"
    ppath = "m/49'/0'/0'/0/0"
    bpath = "m/84'/0'/0'/0/0"
    epath = "m/44'/60'/0'/0/"
    caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
    p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
    bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
    ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))[2:]
    wordvartext = (f' Bitcoin {cpath} :  {caddr} \n Bitcoin {cpath} : Hexadecimal Private Key \n {HEX}  \n \n Bitcoin {ppath} :  {p2sh} \n Bitcoin {ppath} :  Hexadecimal Private Key \n {HEX2} \n\n  Bitcoin {bpath} : {bech32}\n Bitcoin {bpath} : Hexadecimal Private Key \n {HEX3} \n \n  ETH {epath} : 0x{ethaddr}\n ETH {epath} : Hexadecimal Private Key \n {HEX4} ')
    if caddr in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {cpath} :  {caddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
        with open("foundcaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if p2sh in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {ppath} :  {p2sh}\nDecimal Private Key \n {dec2} \n Hexadecimal Private Key \n {HEX2} \n'
        with open("foundp2sh.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {bpath} : {bech32}\n Decimal Private Key \n {dec3} \n Hexadecimal Private Key \n {HEX3} \n'
        with open("foundbech32.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if ethaddr in bloom_filtereth:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n ETH {epath} : 0x{ethaddr}\n Decimal Private Key \n {dec4} \n Hexadecimal Private Key \n {HEX4} \n'
        with open("foundeth.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if caddr.startswith(startadd) or caddr.startswith(startadd1) or caddr.startswith(startadd2) or caddr.startswith(startadd3) or caddr.startswith(startadd4):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {cpath} :  {caddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
        with open("foundcaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if p2sh.startswith(startadd) or p2sh.startswith(startadd1) or p2sh.startswith(startadd2) or p2sh.startswith(startadd3) or p2sh.startswith(startadd4):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {ppath} :  {p2sh} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
        with open("foundp2sh.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if bech32.startswith(startadd) or bech32.startswith(startadd1) or bech32.startswith(startadd2) or bech32.startswith(startadd3) or bech32.startswith(startadd4):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Bitcoin {bpath} :  {bech32} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
        with open("foundbech32.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if ethaddr.startswith(startadd[2:]) or ethaddr.startswith(startadd1[2:]) or ethaddr.startswith(startadd2[2:]) or ethaddr.startswith(startadd3[2:]) or ethaddr.startswith(startadd4[2:]):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = f'\n Mnemonic: {mnem} \n Ethereum {epath} :  0x{ethaddr} \n Decimal Private Key \n {dec} \n Hexadecimal Private Key \n {HEX}  \n'
        with open("foundeth.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    return wordvartext
    
def brute_crypto(self, dec):
    startadd = self._txt_inputvancrypto.get()
    startadd1 = self._txt_inputvancrypto1.get()
    startadd2 = self._txt_inputvancrypto2.get()
    startadd3 = self._txt_inputvancrypto3.get()
    startadd4 = self._txt_inputvancrypto4.get()
    caddr = ice.privatekey_to_address(0, True, dec)
    uaddr = ice.privatekey_to_address(0, False, dec)
    HEX = "%064x" % dec
    wifc = ice.btc_pvk_to_wif(HEX)
    wifu = ice.btc_pvk_to_wif(HEX, False)
    p2sh = ice.privatekey_to_address(1, True, dec)
    bech32 = ice.privatekey_to_address(2, True, dec)
    ethaddr = ice.privatekey_to_ETH_address(dec)[2:] # [2:]
    length = len(bin(dec))
    length -=2
    if caddr in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundcaddr.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}")
        self.popwinner()
    if uaddr in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('founduaddr.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}")
        self.popwinner()
    if p2sh in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundp2sh.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh} \n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh}")
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundbech32.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address bech32: {bech32}")
        self.popwinner()
    if ethaddr in bloom_filtereth:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nETH Address : {ethaddr}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundeth.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nETH Address : 0x{ethaddr}')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nETH Address : 0x{ethaddr}")
        self.popwinner()
    if caddr.startswith(startadd) or caddr.startswith(startadd1) or caddr.startswith(startadd2) or caddr.startswith(startadd3) or caddr.startswith(startadd4):
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundcaddr.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Compressed: {caddr} \nWIF Compressed: {wifc}")
        self.popwinner()
    if uaddr.startswith(startadd) or uaddr.startswith(startadd1) or uaddr.startswith(startadd2) or uaddr.startswith(startadd3) or uaddr.startswith(startadd4):
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('founduaddr.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}\n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address Uncompressed: {uaddr} \nWIF Uncompressed: {wifu}")
        self.popwinner()
    if p2sh.startswith(startadd) or p2sh.startswith(startadd1) or p2sh.startswith(startadd2) or p2sh.startswith(startadd3) or p2sh.startswith(startadd4):
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundp2sh.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address p2sh: {p2sh} \n')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address p2sh: {p2sh}")
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundbech32.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nBTC Address bech32: {bech32}')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nBTC Address bech32: {bech32}")
        self.popwinner()
    if ethaddr.startswith(startadd[2:]) or ethaddr.startswith(startadd1[2:]) or ethaddr.startswith(startadd2[2:]) or ethaddr.startswith(startadd3[2:]) or ethaddr.startswith(startadd4[2:]):
        self.bfr.config(text = f' WINNER WINNER Check found.txt \n Instance: Bruteforce \n DEC Key: {dec} Bits {length} \n HEX Key: {HEX} \nETH Address : {ethaddr}')
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        with open('foundeth.txt', 'a') as result:
            result.write(f'\n Instance: Bruteforce \n DEC Key: {dec}\n Bits {length} \n HEX Key: {HEX} \nETH Address : 0x{ethaddr}')
        self.WINTEXT = (f"DEC Key: {dec}\nHEX Key: {HEX} \nETH Address : 0x{ethaddr}")
        self.popwinner()
    scantext = f'''
            *** DEC Key ***
 {dec}
        Bits {length}
        *** HEY Key ***
    {HEX}
 BTC Address Compressed: {caddr}
        WIF Compressed: {wifc}
 BTC Address Uncompressed: {uaddr}
        WIF Compressed: {wifu}
 BTC Address p2sh: {p2sh}
 BTC Address bech32: {bech32}
 Ethereum Address : 0x{ethaddr}
{lines}'''

    return scantext

def get_page(self, page):
    #max = 904625697166532776746648320380374280100293470930272690489102837043110636675
    num = page
    startPrivKey = (page - 1) * 128 + 1
    startadd = self._txt_inputvanpage.get()
    startadd1 = self._txt_inputvanpage1.get()
    startadd2 = self._txt_inputvanpage2.get()
    startadd3 = self._txt_inputvanpage3.get()
    startadd4 = self._txt_inputvanpage4.get()
    for i in range(0, 128):
        dec = int(startPrivKey)
        starting_key_hex = hex(startPrivKey)[2:].zfill(64)
        if startPrivKey == 115792089237316195423570985008687907852837564279074904382605163141518161494336:
            break
        caddr = ice.privatekey_to_address(0, True, dec)
        uaddr = ice.privatekey_to_address(0, False, dec)
        p2sh = ice.privatekey_to_address(1, True, dec)
        bech32 = ice.privatekey_to_address(2, True, dec)
        ethaddr = ice.privatekey_to_ETH_address(dec)[2:] # [2:]
        length = len(bin(dec))
        length -=2
        if caddr in bloom_filterbtc:
            output = f'''\n
  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Compressed : {caddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundcaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()

        if uaddr in bloom_filterbtc:
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Uncompressed : {uaddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('founduaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
        if p2sh in bloom_filterbtc:
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Segwit : {p2sh}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundp2sh.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()

        if bech32 in bloom_filterbtc:
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Bc1 : {bech32}
{lines}
'''

            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundbech32.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
        if ethaddr in bloom_filtereth:
            output = f'''\n
  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : ETH Address : 0x{ethaddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundeth.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
            
        if caddr.startswith(startadd) or caddr.startswith(startadd1) or caddr.startswith(startadd2) or caddr.startswith(startadd3) or caddr.startswith(startadd4):
            output = f'''\n
  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Compressed : {caddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundcaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()

        if uaddr.startswith(startadd) or uaddr.startswith(startadd1) or uaddr.startswith(startadd2) or uaddr.startswith(startadd3) or uaddr.startswith(startadd4):
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Uncompressed : {uaddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('founduaddr.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
        if p2sh.startswith(startadd) or p2sh.startswith(startadd1) or p2sh.startswith(startadd2) or p2sh.startswith(startadd3) or p2sh.startswith(startadd4):
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Segwit : {p2sh}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundp2sh.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()

        if bech32.startswith(startadd) or bech32.startswith(startadd1) or bech32.startswith(startadd2) or bech32.startswith(startadd3) or bech32.startswith(startadd4):
            output = f'''\n

  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : BTC Address Bc1 : {bech32}
{lines}
'''

            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundbech32.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
        if ethaddr.startswith(startadd[2:]) or ethaddr.startswith(startadd1[2:]) or ethaddr.startswith(startadd2[2:]) or ethaddr.startswith(startadd3[2:]) or ethaddr.startswith(startadd4[2:]):
            output = f'''\n
  : Private Key Page : {num}
{lines}
  : Private Key DEC : {startPrivKey} Bits : {length}
{lines}
  : Private Key HEX : {starting_key_hex}
{lines}
  : ETH Address : 0x{ethaddr}
{lines}
'''
            self.page_brute.config(text = output)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            with open('foundeth.txt', 'a', encoding='utf-8') as f:
                f.write(output)
            self.WINTEXT = output
            self.popwinner()
            
        startPrivKey += 1
    scantext = f'''
  : Private Key Page : 
  {num}
  : Private Key DEC :
  {startPrivKey} 
  Bits : {length}
  : Private Key HEX : 
  {starting_key_hex}
{lines}
 BTC Address Compressed: {caddr}
 BTC Address Uncompressed: {uaddr}
 BTC Address p2sh: {p2sh}
 BTC Address bech32: {bech32}
 Ethereum Address : 0x{ethaddr}
{lines}'''
    return scantext
    
def rboffline(self, passphrase):
    startadd = self._txt_inputvanbrain.get()
    startadd1 = self._txt_inputvanbrain1.get()
    startadd2 = self._txt_inputvanbrain2.get()
    startadd3 = self._txt_inputvanbrain3.get()
    startadd4 = self._txt_inputvanbrain4.get()
    wallet = BrainWallet()
    private_key, uaddr = wallet.generate_address_from_passphrase(passphrase)
    dec = int(private_key, 16)
    caddr = ice.privatekey_to_address(0, True, dec)
    p2sh = ice.privatekey_to_address(1, True, dec)
    bech32 = ice.privatekey_to_address(2, True, dec)
    ethaddr = ice.privatekey_to_ETH_address(dec)[2:] # [2:]
    brainvartext = (f'\n Private Key In HEX : \n\n {private_key} \n Bitcoin Adress Compressed : {caddr} \n Bitcoin Adress Uncompressed : {uaddr} \n Bitcoin Adress p2sh : {p2sh} \n Bitcoin Adress bech32 : {bech32} \n Ethereum Adress  : 0x{ethaddr} ')
    if caddr in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress Compressed: {caddr}')
        with open("foundcaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if uaddr in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress Uncompressed : {uaddr}')
        with open("founduaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if p2sh in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress p2sh : {p2sh}')
        with open("foundp2sh.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if bech32 in bloom_filterbtc:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress Bc1 : {bech32}')
        with open("foundbech32.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if ethaddr in bloom_filtereth:
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Ethereum Adress : {ethaddr}')
        with open("foundeth.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if caddr.startswith(startadd) or caddr.startswith(startadd1) or caddr.startswith(startadd2) or caddr.startswith(startadd3) or caddr.startswith(startadd4):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress Compressed: {caddr}')
        with open("foundcaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if uaddr.startswith(startadd) or uaddr.startswith(startadd1) or uaddr.startswith(startadd2) or uaddr.startswith(startadd3) or uaddr.startswith(startadd4):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress Uncompressed : {uaddr}')
        with open("founduaddr.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if p2sh.startswith(startadd) or p2sh.startswith(startadd1) or p2sh.startswith(startadd2) or p2sh.startswith(startadd3) or p2sh.startswith(startadd4):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress p2sh : {p2sh}')
        with open("foundp2sh.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if bech32.startswith(startadd) or bech32.startswith(startadd1) or bech32.startswith(startadd2) or bech32.startswith(startadd3) or bech32.startswith(startadd4):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Bitcoin Adress Bc1 : {bech32}')
        with open("foundbech32.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    if ethaddr.startswith(startadd[2:]) or ethaddr.startswith(startadd1[2:]) or ethaddr.startswith(startadd2[2:]) or ethaddr.startswith(startadd3[2:]) or ethaddr.startswith(startadd4[2:]):
        self.found+=1
        self.foundcrypto.config(text = f'{self.found}')
        self.WINTEXT = (f'\n BrainWallet: {passphrase} \n Private Key In HEX : {private_key} \n Ethereum Adress : {ethaddr}')
        with open("foundeth.txt", "a") as f:
            f.write(self.WINTEXT)
        self.popwinner()
    return brainvartext

def hexhunter(self, dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18):
    dec= int(dec)
    dec0= int(dec0)
    dec1= int(dec1)
    dec2= int(dec2)
    dec3= int(dec3)
    dec4= int(dec4)
    dec5= int(dec5)
    dec6= int(dec6)
    dec7= int(dec7)
    dec8= int(dec8)
    dec9= int(dec9)
    dec10= int(dec10)
    dec11= int(dec11)
    dec12= int(dec12)
    dec13= int(dec13)
    dec14= int(dec14)
    dec15= int(dec15)
    dec16= int(dec16)
    dec17= int(dec17)
    dec18= int(dec18)
    for r in range(0, 128):
        ether = ice.privatekey_to_ETH_address(dec)[2:]
        ether0 = ice.privatekey_to_ETH_address(dec0)[2:]
        ether1 = ice.privatekey_to_ETH_address(dec1)[2:]
        ether2 = ice.privatekey_to_ETH_address(dec2)[2:]
        ether3 = ice.privatekey_to_ETH_address(dec3)[2:]
        ether4 = ice.privatekey_to_ETH_address(dec4)[2:]
        ether5 = ice.privatekey_to_ETH_address(dec5)[2:]
        ether6 = ice.privatekey_to_ETH_address(dec6)[2:]
        ether7 = ice.privatekey_to_ETH_address(dec7)[2:]
        ether8 = ice.privatekey_to_ETH_address(dec8)[2:]
        ether9 = ice.privatekey_to_ETH_address(dec9)[2:]
        ether10 = ice.privatekey_to_ETH_address(dec10)[2:]
        ether11 = ice.privatekey_to_ETH_address(dec11)[2:]
        ether12 = ice.privatekey_to_ETH_address(dec12)[2:]
        ether13 = ice.privatekey_to_ETH_address(dec13)[2:]
        ether14 = ice.privatekey_to_ETH_address(dec14)[2:]
        ether15 = ice.privatekey_to_ETH_address(dec15)[2:]
        ether16 = ice.privatekey_to_ETH_address(dec16)[2:]
        ether17 = ice.privatekey_to_ETH_address(dec17)[2:]
        ether18 = ice.privatekey_to_ETH_address(dec18)[2:]
        btcC = ice.privatekey_to_address(0, True, dec)
        btcC0 = ice.privatekey_to_address(0, True, dec0)
        btcC1 = ice.privatekey_to_address(0, True, dec1)
        btcC2 = ice.privatekey_to_address(0, True, dec2)
        btcC3 = ice.privatekey_to_address(0, True, dec3)
        btcC4 = ice.privatekey_to_address(0, True, dec4)
        btcC5 = ice.privatekey_to_address(0, True, dec5)
        btcC6 = ice.privatekey_to_address(0, True, dec6)
        btcC7 = ice.privatekey_to_address(0, True, dec7)
        btcC8 = ice.privatekey_to_address(0, True, dec8)
        btcC9 = ice.privatekey_to_address(0, True, dec9)
        btcC10 = ice.privatekey_to_address(0, True, dec10)
        btcC11 = ice.privatekey_to_address(0, True, dec11)
        btcC12 = ice.privatekey_to_address(0, True, dec12)
        btcC13 = ice.privatekey_to_address(0, True, dec13)
        btcC14 = ice.privatekey_to_address(0, True, dec14)
        btcC15 = ice.privatekey_to_address(0, True, dec15)
        btcC16 = ice.privatekey_to_address(0, True, dec16)
        btcC17 = ice.privatekey_to_address(0, True, dec17)
        btcC18 = ice.privatekey_to_address(0, True, dec18)
        btcU = ice.privatekey_to_address(0, False, dec)
        btcU0 = ice.privatekey_to_address(0, False, dec0)
        btcU1 = ice.privatekey_to_address(0, False, dec1)
        btcU2 = ice.privatekey_to_address(0, False, dec2)
        btcU3 = ice.privatekey_to_address(0, False, dec3)
        btcU4 = ice.privatekey_to_address(0, False, dec4)
        btcU5 = ice.privatekey_to_address(0, False, dec5)
        btcU6 = ice.privatekey_to_address(0, False, dec6)
        btcU7 = ice.privatekey_to_address(0, False, dec7)
        btcU8 = ice.privatekey_to_address(0, False, dec8)
        btcU9 = ice.privatekey_to_address(0, False, dec9)
        btcU10 = ice.privatekey_to_address(0, False, dec10)
        btcU11 = ice.privatekey_to_address(0, False, dec11)
        btcU12 = ice.privatekey_to_address(0, False, dec12)
        btcU13 = ice.privatekey_to_address(0, False, dec13)
        btcU14 = ice.privatekey_to_address(0, False, dec14)
        btcU15 = ice.privatekey_to_address(0, False, dec15)
        btcU16 = ice.privatekey_to_address(0, False, dec16)
        btcU17 = ice.privatekey_to_address(0, False, dec17)
        btcU18 = ice.privatekey_to_address(0, False, dec18)
        btcP = ice.privatekey_to_address(1, True, dec)
        btcP0 = ice.privatekey_to_address(1, True, dec0)
        btcP1 = ice.privatekey_to_address(1, True, dec1)
        btcP2 = ice.privatekey_to_address(1, True, dec2)
        btcP3 = ice.privatekey_to_address(1, True, dec3)
        btcP4 = ice.privatekey_to_address(1, True, dec4)
        btcP5 = ice.privatekey_to_address(1, True, dec5)
        btcP6 = ice.privatekey_to_address(1, True, dec6)
        btcP7 = ice.privatekey_to_address(1, True, dec7)
        btcP8 = ice.privatekey_to_address(1, True, dec8)
        btcP9 = ice.privatekey_to_address(1, True, dec9)
        btcP10 = ice.privatekey_to_address(1, True, dec10)
        btcP11 = ice.privatekey_to_address(1, True, dec11)
        btcP12 = ice.privatekey_to_address(1, True, dec12)
        btcP13 = ice.privatekey_to_address(1, True, dec13)
        btcP14 = ice.privatekey_to_address(1, True, dec14)
        btcP15 = ice.privatekey_to_address(1, True, dec15)
        btcP16 = ice.privatekey_to_address(1, True, dec16)
        btcP17 = ice.privatekey_to_address(1, True, dec17)
        btcP18 = ice.privatekey_to_address(1, True, dec18)
        btcB = ice.privatekey_to_address(2, True, dec)
        btcB0 = ice.privatekey_to_address(2, True, dec0)
        btcB1 = ice.privatekey_to_address(2, True, dec1)
        btcB2 = ice.privatekey_to_address(2, True, dec2)
        btcB3 = ice.privatekey_to_address(2, True, dec3)
        btcB4 = ice.privatekey_to_address(2, True, dec4)
        btcB5 = ice.privatekey_to_address(2, True, dec5)
        btcB6 = ice.privatekey_to_address(2, True, dec6)
        btcB7 = ice.privatekey_to_address(2, True, dec7)
        btcB8 = ice.privatekey_to_address(2, True, dec8)
        btcB9 = ice.privatekey_to_address(2, True, dec9)
        btcB10 = ice.privatekey_to_address(2, True, dec10)
        btcB11 = ice.privatekey_to_address(2, True, dec11)
        btcB12 = ice.privatekey_to_address(2, True, dec12)
        btcB13 = ice.privatekey_to_address(2, True, dec13)
        btcB14 = ice.privatekey_to_address(2, True, dec14)
        btcB15 = ice.privatekey_to_address(2, True, dec15)
        btcB16 = ice.privatekey_to_address(2, True, dec16)
        btcB17 = ice.privatekey_to_address(2, True, dec17)
        btcB18 = ice.privatekey_to_address(2, True, dec18)
        scantext =f'''
        
{hex(dec)[2:].zfill(64)}    |   {hex(dec9)[2:].zfill(64)}
{hex(dec0)[2:].zfill(64)}    |   {hex(dec10)[2:].zfill(64)}
{hex(dec1)[2:].zfill(64)}    |   {hex(dec11)[2:].zfill(64)}
{hex(dec2)[2:].zfill(64)}    |   {hex(dec12)[2:].zfill(64)}
{hex(dec3)[2:].zfill(64)}    |   {hex(dec13)[2:].zfill(64)}
{hex(dec4)[2:].zfill(64)}    |   {hex(dec14)[2:].zfill(64)}
{hex(dec5)[2:].zfill(64)}    |   {hex(dec15)[2:].zfill(64)}
{hex(dec6)[2:].zfill(64)}    |   {hex(dec16)[2:].zfill(64)}
{hex(dec7)[2:].zfill(64)}    |   {hex(dec17)[2:].zfill(64)}
{hex(dec8)[2:].zfill(64)}    |   {hex(dec18)[2:].zfill(64)}
'''
        if  btcC in bloom_filterbtc or btcU in bloom_filterbtc or btcP in bloom_filterbtc or btcB in bloom_filterbtc or ether in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex):  {hex(dec)[2:].zfill(64)}
Decimal     (dec): {dec}
BTCc        : {btcC}
BTCu        : {btcU}
BTC p2sh    : {btcP}
BTC BC1     : {btcB}
Ethereum    : 0x{ether}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC0 in bloom_filterbtc or btcU0 in bloom_filterbtc or btcP0 in bloom_filterbtc or btcB0 in bloom_filterbtc or ether0 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec0)[2:].zfill(64)}
Decimal     (dec): {dec0}
BTCc        : {btcC0}
BTCu        : {btcU0}
BTC p2sh    : {btcP0}
BTC BC1     : {btcB0}
Ethereum    : 0x{ether0}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC1 in bloom_filterbtc or btcU1 in bloom_filterbtc or btcP1 in bloom_filterbtc or btcB1 in bloom_filterbtc or ether1 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec1)[2:].zfill(64)}
Decimal     (dec): {dec1}
BTCc        : {btcC1}
BTCu        : {btcU1}
BTC p2sh    : {btcP1}
BTC BC1     : {btcB1}
Ethereum    : 0x{ether1}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC2 in bloom_filterbtc or btcU2 in bloom_filterbtc or btcP2 in bloom_filterbtc or btcB2 in bloom_filterbtc or ether2 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec2)[2:].zfill(64)}
Decimal     (dec): {dec2}
BTCc        : {btcC2}
BTCu        : {btcU2}
BTC p2sh    : {btcP2}
BTC BC1     : {btcB2}
Ethereum    : 0x{ether2}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC3 in bloom_filterbtc or btcU3 in bloom_filterbtc or btcP3 in bloom_filterbtc or btcB3 in bloom_filterbtc or ether3 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec3)[2:].zfill(64)}
Decimal     (dec): {dec3}
BTCc        : {btcC3}
BTCu        : {btcU3}
BTC p2sh    : {btcP3}
BTC BC1     : {btcB3}
Ethereum    : 0x{ether3}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC4 in bloom_filterbtc or btcU4 in bloom_filterbtc or btcP4 in bloom_filterbtc or btcB4 in bloom_filterbtc or ether4 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec4)[2:].zfill(64)}
Decimal     (dec): {dec4}
BTCc        : {btcC4}
BTCu        : {btcU4}
BTC p2sh    : {btcP4}
BTC BC1     : {btcB4}
Ethereum    : 0x{ether4}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC5 in bloom_filterbtc or btcU5 in bloom_filterbtc or btcP5 in bloom_filterbtc or btcB5 in bloom_filterbtc or ether5 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec5)[2:].zfill(64)}
Decimal     (dec): {dec5}
BTCc        : {btcC5}
BTCu        : {btcU5}
BTC p2sh    : {btcP5}
BTC BC1     : {btcB5}
Ethereum    : 0x{ether5}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC6 in bloom_filterbtc or btcU6 in bloom_filterbtc or btcP6 in bloom_filterbtc or btcB6 in bloom_filterbtc or ether6 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec6)[2:].zfill(64)}
Decimal     (dec): {dec6}
BTCc        : {btcC6}
BTCu        : {btcU6}
BTC p2sh    : {btcP6}
BTC BC1     : {btcB6}
Ethereum    : 0x{ether6}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC7 in bloom_filterbtc or btcU7 in bloom_filterbtc or btcP7 in bloom_filterbtc or btcB7 in bloom_filterbtc or ether7 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec7)[2:].zfill(64)}
Decimal     (dec): {dec7}
BTCc        : {btcC7}
BTCu        : {btcU7}
BTC p2sh    : {btcP7}
BTC BC1     : {btcB7}
Ethereum    : 0x{ether7}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC8 in bloom_filterbtc or btcU8 in bloom_filterbtc or btcP8 in bloom_filterbtc or btcB8 in bloom_filterbtc or ether8 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec8)[2:].zfill(64)}
Decimal     (dec): {dec8}
BTCc        : {btcC8}
BTCu        : {btcU8}
BTC p2sh    : {btcP8}
BTC BC1     : {btcB8}
Ethereum    : 0x{ether8}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC9 in bloom_filterbtc or btcU9 in bloom_filterbtc or btcP9 in bloom_filterbtc or btcB9 in bloom_filterbtc or ether9 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec9)[2:].zfill(64)}
Decimal     (dec): {dec9}
BTCc        : {btcC9}
BTCu        : {btcU9}
BTC p2sh    : {btcP9}
BTC BC1     : {btcB9}
Ethereum    : 0x{ether9}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC10 in bloom_filterbtc or btcU10 in bloom_filterbtc or btcP10 in bloom_filterbtc or btcB10 in bloom_filterbtc or ether10 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec10)[2:].zfill(64)}
Decimal     (dec): {dec10}
BTCc        : {btcC10}
BTCu        : {btcU10}
BTC p2sh    : {btcP10}
BTC BC1     : {btcB10}
Ethereum    : 0x{ether10}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC11 in bloom_filterbtc or btcU11 in bloom_filterbtc or btcP11 in bloom_filterbtc or btcB11 in bloom_filterbtc or ether11 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec11)[2:].zfill(64)}
Decimal     (dec): {dec11}
BTCc        : {btcC11}
BTCu        : {btcU11}
BTC p2sh    : {btcP11}
BTC BC1     : {btcB11}
Ethereum    : 0x{ether11}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC12 in bloom_filterbtc or btcU12 in bloom_filterbtc or btcP12 in bloom_filterbtc or btcB12 in bloom_filterbtc or ether12 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec12)[2:].zfill(64)}
Decimal     (dec): {dec12}
BTCc        : {btcC12}
BTCu        : {btcU12}
BTC p2sh    : {btcP12}
BTC BC1     : {btcB12}
Ethereum    : 0x{ether12}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC13 in bloom_filterbtc or btcU13 in bloom_filterbtc or btcP13 in bloom_filterbtc or btcB13 in bloom_filterbtc or ether13 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec13)[2:].zfill(64)}
Decimal     (dec): {dec13}
BTCc        : {btcC13}
BTCu        : {btcU13}
BTC p2sh    : {btcP13}
BTC BC1     : {btcB13}
Ethereum    : 0x{ether13}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC14 in bloom_filterbtc or btcU14 in bloom_filterbtc or btcP14 in bloom_filterbtc or btcB14 in bloom_filterbtc or ether14 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec14)[2:].zfill(64)}
Decimal     (dec): {dec14}
BTCc        : {btcC14}
BTCu        : {btcU14}
BTC p2sh    : {btcP14}
BTC BC1     : {btcB14}
Ethereum    : 0x{ether14}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC15 in bloom_filterbtc or btcU15 in bloom_filterbtc or btcP15 in bloom_filterbtc or btcB15 in bloom_filterbtc or ether15 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec15)[2:].zfill(64)}
Decimal     (dec): {dec15}
BTCc        : {btcC15}
BTCu        : {btcU15}
BTC p2sh    : {btcP15}
BTC BC1     : {btcB15}
Ethereum    : 0x{ether15}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC16 in bloom_filterbtc or btcU16 in bloom_filterbtc or btcP16 in bloom_filterbtc or btcB16 in bloom_filterbtc or ether16 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec16)[2:].zfill(64)}
Decimal     (dec): {dec16}
BTCc        : {btcC16}
BTCu        : {btcU16}
BTC p2sh    : {btcP16}
BTC BC1     : {btcB16}
Ethereum    : 0x{ether16}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC17 in bloom_filterbtc or btcU17 in bloom_filterbtc or btcP17 in bloom_filterbtc or btcB17 in bloom_filterbtc or ether17 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec17)[2:].zfill(64)}
Decimal     (dec): {dec17}
BTCc        : {btcC17}
BTCu        : {btcU17}
BTC p2sh    : {btcP17}
BTC BC1     : {btcB17}
Ethereum    : 0x{ether17}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if btcC18 in bloom_filterbtc or btcU18 in bloom_filterbtc or btcP18 in bloom_filterbtc or btcB18 in bloom_filterbtc or ether18 in bloom_filtereth:
            wintext = f'''
PrivateKey  (hex): {hex(dec18)[2:].zfill(64)}
Decimal     (dec): {dec18}
BTCc        : {btcC18}
BTCu        : {btcU18}
BTC p2sh    : {btcP18}
BTC BC1     : {btcB18}
Ethereum    : 0x{ether18}
=================================
'''
            f=open('found.txt','a')
            f.write(wintext)
            self.rotation_brute.config(text = wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        dec+=r 
        dec0+=r
        dec1+=r
        dec2+=r
        dec3+=r
        dec4+=r
        dec5+=r
        dec6+=r
        dec7+=r
        dec8+=r
        dec9+=r
        dec10+=r
        dec11+=r
        dec12+=r
        dec13+=r
        dec14+=r
        dec15+=r
        dec16+=r
        dec17+=r
        dec18+=r
        return scantext

# Recovery Program
def complete_key(rec_IN_string, missing_letters):
    for letter in missing_letters:
        rec_IN_string = rec_IN_string.replace('*', letter, 1)
    return rec_IN_string

def btc_address_from_private_key(my_secret, secret_type):
    assert secret_type in ['WIF', 'HEX', 'DEC', 'mnemonic']
    match secret_type:
        case 'WIF':
            if my_secret.startswith('5H') or my_secret.startswith('5J') or my_secret.startswith('5K') or my_secret.startswith('K') or my_secret.startswith('L'):
                if my_secret.startswith('5H') or my_secret.startswith('5J') or my_secret.startswith('5K'):
                    first_encode = base58.b58decode(my_secret)
                    private_key_full = binascii.hexlify(first_encode)
                    private_key = private_key_full[2:-8]
                    private_key_hex = private_key.decode("utf-8")
                    dec = int(private_key_hex,16)
                elif my_secret.startswith('K') or my_secret.startswith('L'):
                    first_encode = base58.b58decode(my_secret)
                    private_key_full = binascii.hexlify(first_encode)
                    private_key = private_key_full[2:-8]
                    private_key_hex = private_key.decode("utf-8")
                    dec = int(private_key_hex[0:64],16)
        case 'HEX':
            dec = int(my_secret[0:64],16)
        case 'mnemonic':
            raise "Mnemonic secrets not implemented"
        case 'DEC':
            dec = int(my_secret)
        case _:
            raise "I don't know how to handle this type."

    return dec

def recovery_main(self, scan_IN, rec_IN, mode):
    missing_length = rec_IN.count('*')
    key_length = len(rec_IN)
    recoverytext = f'Looking for {missing_length} characters in {rec_IN}'
    self.labelWIF1.config(text = recoverytext)
    self.labelWIF1.update()
    match scan_IN:
        case 'WIF':
            secret_type = 'WIF'
            allowed_characters = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        case 'HEX':
            secret_type = 'HEX'
            allowed_characters = '0123456789abcdef'
        case 'DEC':
            secret_type = 'DEC'
            allowed_characters = '0123456789'
        case _:
            # Unknown Length
            secret_type = 'unhandled'
            allowed_characters = string.ascii_uppercase + string.ascii_lowercase + string.digits

    missing_letters_master_list = trotter.Amalgams(missing_length, allowed_characters)
    try:
        self.labelWIF2.config(text = missing_letters_master_list)
        self.labelWIF2.update()
        max_loop_length = len(missing_letters_master_list)
    except OverflowError:
        max_loop_length = sys.maxsize
        if mode == 'sequential':
            print(f"Warning: Some letters will not be processed in sequential mode because "
                  f"the possible space is too large. Try random mode.")
    remaining = max_loop_length
    for i in range(max_loop_length):
        if mode == 'sequential':
            potential_key = complete_key(rec_IN, missing_letters_master_list[i])
        elif mode == 'random':
            potential_key = complete_key(rec_IN, missing_letters_master_list.random())
        dec = btc_address_from_private_key(potential_key, secret_type=secret_type)
        uaddr = ice.privatekey_to_address(0, False, dec)
        caddr = ice.privatekey_to_address(0, True, dec)
        p2sh = ice.privatekey_to_address(1, True, dec)
        bech32 = ice.privatekey_to_address(2, True, dec)
        ethaddr = ice.privatekey_to_ETH_address(dec)[2:] # [2:]
        self.labelWIF3.config(text = potential_key)
        self.labelWIF3.update()
        remaining -= 1
        self.labelWIF4.config(text = remaining)
        self.labelWIF4.update()
        if caddr in bloom_filterbtc:
            wintext = f"\n key: {potential_key} address: {caddr}"
            f=open('foundcaddr.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if uaddr in bloom_filterbtc:
            wintext = f"\n key: {potential_key} address: {uaddr}"
            f=open('founduaddr.txt','a')
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if p2sh in bloom_filterbtc:
            wintext = f"\n key: {potential_key} address: {p2sh}"
            f=open('foundp2sh.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if bech32 in bloom_filterbtc:
            wintext = f"\n key: {potential_key} address: {bech32}"
            f=open('foundbech32.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
        if ethaddr in bloom_filtereth:
            wintext = f"\n key: {potential_key} address: 0x{ethaddr}"
            f=open('foundbech32.txt','a')
            f.write(wintext)
            self.found+=1
            self.foundcrypto.config(text = f'{self.found}')
            self.WINTEXT = wintext
            self.popwinner()
            
def RandomInteger(minN, maxN):
    return random.randrange(minN, maxN)

########### Database Load and Files ###########
mylist = []
 
with open('files/words.txt', newline='', encoding='utf-8') as f:
    for line in f:
        mylist.append(line.strip())
startdec = 1
stopdec = 115792089237316195423570985008687907852837564279074904382605163141518161494336
totaladd = total = found =0
run = run1=  run2 = run3 = True
########### THE MAIN PROGRAM BITCOIN HUNTER ###########
class MainWindow():
    def __init__(self):
        self.found = found
        self.run = run
        self.fact = 1
        def start1():
           global run1
           run1= True
        def stop1():
           global run1
           run1= False
        def start2():
           global run2
           run2= True
        def stop2():
           global run2
           run2= False
        def start3():
           global run3
           run3= True
        def stop3():
           global run3
           run3= False
        ###########  Main Window Program Menu Bar ###########
        self._window = tkinter.Tk()
        self._window.title("MiniHunterCrypto.py @ Mizogg.co.uk")
        # self._window.iconbitmap('images/ico')
        self._window.config(bg="black")
        self._window.geometry("660x580")
        self._window.resizable(False, False)
        self._window.menubar = Menu(self._window)
        self._window.filemenu = Menu(self._window.menubar, tearoff=0)
        self._window.filemenu.add_separator()
        self._window.filemenu.add_command(label="Exit", command=self._window.quit)
        self._window.menubar.add_cascade(label="File", menu=self._window.filemenu)
        self._window.helpmenu = Menu(self._window.menubar, tearoff=0)
        self._window.helpmenu.add_command(label="Help Telegram Group", command=opentelegram)
        self._window.helpmenu.add_command(label="Mizogg Website", command=openweb)
        self._window.helpmenu.add_command(label="About MiniHunterCrypto", command=self.startpop)
        self._window.menubar.add_cascade(label="Help", menu=self._window.helpmenu)
        self._window.config(menu=self._window.menubar)
        self.my_notebook = ttk.Notebook(self._window)
        self.my_notebook.pack(pady=5)
        self.main_frame = Frame(self.my_notebook, width=640, height=560)
        self.crypto_frame = Frame(self.my_notebook, width=640, height=560)
        self.page_frame = Frame(self.my_notebook, width=640, height=560)
        self.hex_frame = Frame(self.my_notebook, width=640, height=560)
        self.brain_frame = Frame(self.my_notebook, width=640, height=560)
        self.word_frame = Frame(self.my_notebook, width=640, height=560)
        self.recovery_frame = Frame(self.my_notebook, width=640, height=560)
        self.main_frame.pack(fill="both", expand=1)
        self.crypto_frame.pack(fill="both", expand=1)
        self.page_frame.pack(fill="both", expand=1)
        self.hex_frame.pack(fill="both", expand=1)
        self.brain_frame.pack(fill="both", expand=1)
        self.word_frame.pack(fill="both", expand=1)
        self.recovery_frame.pack(fill="both", expand=1)
        ########### TAB ORDER ###########
        self.my_notebook.add(self.crypto_frame, text="Crytpo Hunting")
        self.my_notebook.add(self.page_frame, text="Hunting by Pages")
        self.my_notebook.add(self.hex_frame, text="Rotation5Bit")
        self.my_notebook.add(self.brain_frame, text="Brain Hunting")
        self.my_notebook.add(self.word_frame, text="Mnemonic Hunting")
        self.my_notebook.add(self.recovery_frame, text="Recovery Tools")
        self.my_notebook.add(self.main_frame, text="Conversion Tools ")
        ###########  Main Tab ###########
        self.labeltype = tkinter.Label(self.main_frame, text=" Type \n Data \n Here ", font=("Consolas", 10)).place(x=5,y=70)
        self._txt_input = tkinter.Entry(self.main_frame, width=60, font=("Consolas", 10))
        self._txt_input.insert(0, '10101')
        self._txt_input.place(x=80,y=100)
        self._txt_input.focus()
        self._btc_bin = tkinter.Button(self.main_frame, text="Bin", font=("Consolas", 10), command=self.evt_btc_bin).place(x=300,y=150)
        self._btc_dec = tkinter.Button(self.main_frame, text="Dec", font=("Consolas", 10), command=self.evt_btc_dec).place(x=360,y=150)
        self._btc_bit = tkinter.Button(self.main_frame, text="Bits", font=("Consolas", 10), command=self.evt_btc_bit).place(x=480,y=150)
        self._btc_hex = tkinter.Button(self.main_frame, text="Hex", font=("Consolas", 10), command=self.evt_btc_hex).place(x=420,y=150)
        self._rd_dec = tkinter.Button(self.main_frame, text="Random", font=("Consolas", 10), command=self.evt_rd_dec).place(x=15,y=150)
        self._jump_input = tkinter.Entry(self.main_frame, width=4, font=("Consolas", 10), fg='red')
        self._jump_input.insert(0, '1')
        self._jump_input.place(x=170,y=150)
        self._jump_input.focus()
        self._jump1_dec = tkinter.Button(self.main_frame, text=" + ", font=("Consolas", 10), command=self.evt_jump1_dec, fg='green').place(x=230,y=150)
        self._jump_dec = tkinter.Button(self.main_frame, text=" - ", font=("Consolas", 10), command=self.evt_jump_rm1_dec, fg='red').place(x=110,y=150)
        self.labelbin = tkinter.Label(self.main_frame, text="  Binary ", font=("Consolas", 10)).place(x=5,y=200)
        self._stringvar_bin = tkinter.StringVar()
        self.txt_outputbin = tkinter.Entry(self.main_frame, textvariable=self._stringvar_bin, width=64, font=("Consolas", 10))
        self.txt_outputbin.place(x=90,y=200)
        self.labelbits = tkinter.Label(self.main_frame, text="  Bits ", font=("Consolas", 10)).place(x=550,y=240)
        self._stringvar_bit = tkinter.StringVar()
        self.txt_outputbit = tkinter.Entry(self.main_frame, textvariable=self._stringvar_bit, width=5, font=("Consolas", 10))
        self.txt_outputbit.place(x=565,y=280)
        self.labeldec = tkinter.Label(self.main_frame, text=" Decimal ", font=("Consolas", 10)).place(x=5,y=240)
        self._stringvar_dec = tkinter.StringVar()
        self.txt_outputdec = tkinter.Entry(self.main_frame, textvariable=self._stringvar_dec, width=64, font=("Consolas", 10))
        self.txt_outputdec.place(x=90,y=240)
        self.labelhex = tkinter.Label(self.main_frame, text="Hexadecimal ", font=("Consolas", 10)).place(x=2,y=280)
        self._stringvar_hex = tkinter.StringVar()
        self.txt_outputhex = tkinter.Entry(self.main_frame, textvariable=self._stringvar_hex, width=64, font=("Consolas", 10))
        self.txt_outputhex.place(x=90,y=280)
        self.labelbtca = tkinter.Label(self.main_frame, text=" BTC Address ", font=("Consolas", 10)).place(x=300,y=310)
        self._stringvar_addr = tkinter.StringVar()
        self.txt_outputaddr = tkinter.Label(self.main_frame, textvariable=self._stringvar_addr, font=("Arial", 10))
        self.txt_outputaddr.place(x=90,y=330)
        ###########  Widgets ###########
        self.widget = tkinter.Label(self._window, compound='top')
        self.widget.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widget['text'] = "© MIZOGG 2018 - 2022"
        self.widget['image'] = self.widget.miz_image_png
        self.widget.place(x=10,y=30)
        self.tpk = tkinter.Label(self._window, text="Total Private Keys : ",font=("Arial",10),bg="#F0F0F0",fg="Black").place(x=200,y=30)
        self.totalC = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",10),text="")
        self.totalC.place(x=320,y=30)
        self.totaladd = tkinter.Label(self._window, text="Total Addresses   : ",font=("Arial",10),bg="#F0F0F0",fg="Black").place(x=200,y=50)
        self.totalA = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",10),text="")
        self.totalA.place(x=320,y=50)
        self.addcount = tkinter.Label(self._window, text=countadd(),font=("Arial",11),bg="#F0F0F0",fg="purple").place(x=10,y=80)
        self.totalbtc = tkinter.Label(self._window, text="Total Found ",font=("Arial",12),bg="#F0F0F0",fg="purple").place(x=430,y=30)
        self.foundcrypto = tkinter.Label(self._window, bg="#F0F0F0",font=("Arial",14),text="0")
        self.foundcrypto.place(x=460,y=50)
        ########### brain_frame ###########
        self.brain_update = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",9),text="", width=80, fg="Red")
        self.brain_update.place(x=20,y=220)
        self.brain_update1 = tkinter.Label(self.brain_frame, bg="#F0F0F0",font=("Arial",10),text="")
        self.brain_update1.place(x=30,y=240)
        self.start1= tkinter.Button(self.brain_frame, text= "Start",font=("Arial",8),bg="#F0F0F0", command= self.start, fg='green').place(x=450,y=120)
        self.stop1= tkinter.Button(self.brain_frame, text= "Stop",font=("Arial",8),bg="#F0F0F0", command= self.stop, fg='red').place(x=410,y=120)
        self.labelbrain = tkinter.Label(self.brain_frame, text="Brain \nWords ", font=("Arial",10)).place(x=5,y=75)
        self._txt_inputbrain = tkinter.Entry(self.brain_frame, width=70, font=("Consolas", 11))
        self._txt_inputbrain.insert(0, 'how much wood could a woodchuck chuck if a woodchuck could chuck wood')
        self._txt_inputbrain.place(x=60,y=80)
        self._txt_inputbrain.focus()
        self._txt_brain_ammount = tkinter.Entry(self.brain_frame, width=4, font=("Consolas", 10), fg="red")
        self._txt_brain_ammount.insert(0, '1')
        self._txt_brain_ammount.place(x=110,y=130)
        self._txt_brain_ammount.focus()
        self._txt_brain_total = tkinter.Entry(self.brain_frame, width=4, font=("Consolas", 10), fg="red")
        self._txt_brain_total.insert(0, '12')
        self._txt_brain_total.place(x=110,y=160)
        self._txt_brain_total.focus()
        self.titleb = tkinter.Label(self.brain_frame, text="Brain Wallet Results ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=190,y=180)
        self.titlemax = tkinter.Label(self.brain_frame, text="!!! MAX 25 -26 !!!",font=("Arial",10),bg="#F0F0F0",fg="red").place(x=25,y=190)
        self.title1 = tkinter.Label(self.brain_frame, text="Brain Wallet \n Random Generator \n Pick Ammount \n to Generate",font=("Arial",7),bg="#F0F0F0",fg="Black").place(x=10,y=130)
        self.my_button = tkinter.Button(self.brain_frame, text= "1 Word List ",font=("Arial",8),bg="#ee6b6e", command= self.Random_brain_offline1).place(x=160,y=120)
        self.my_button = tkinter.Button(self.brain_frame, text= "Brain Words ",font=("Arial",8),bg="#A3E4A7", command= self.Random_brain_offline).place(x=235,y=120)
        self.my_button = tkinter.Button(self.brain_frame, text= "Brain String ",font=("Arial",8),bg="#F3E4C8", command= self.Random_brain_offline2).place(x=315,y=120)
        self._btc_bin = tkinter.Button(self.brain_frame, text="Enter", font=("Consolas", 10), command=self.Random_brain_single).place(x=545,y=110)
        self.labelvanbrain = tkinter.Label(self.brain_frame, text=" Vanity Address \n Starting With ", font=("Arial",9), fg="red").place(x=5,y=490)
        self._txt_inputvanbrain = tkinter.Entry(self.brain_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanbrain.insert(0, '1FeexV6bAH')
        self._txt_inputvanbrain.place(x=100,y=500)
        self._txt_inputvanbrain.focus()
        self._txt_inputvanbrain1 = tkinter.Entry(self.brain_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanbrain1.insert(0, '1Mizogg')
        self._txt_inputvanbrain1.place(x=200,y=500)
        self._txt_inputvanbrain1.focus()
        self._txt_inputvanbrain2 = tkinter.Entry(self.brain_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanbrain2.insert(0, '3Merry')
        self._txt_inputvanbrain2.place(x=300,y=500)
        self._txt_inputvanbrain2.focus()
        self._txt_inputvanbrain3 = tkinter.Entry(self.brain_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanbrain3.insert(0, '0x1Happy')
        self._txt_inputvanbrain3.place(x=400,y=500)
        self._txt_inputvanbrain3.focus()
        self._txt_inputvanbrain4 = tkinter.Entry(self.brain_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanbrain4.insert(0, 'bc1xmas')
        self._txt_inputvanbrain4.place(x=500,y=500)
        self._txt_inputvanbrain4.focus()
        self.labelvanbrain = tkinter.Label(self.brain_frame, text=" Optional Look for addresses starting with this prefix ", font=("Arial",7), fg="red").place(x=195,y=482)
        ########### crypto_frame ###########
        self.bwg = tkinter.Label(self.crypto_frame, text="Crypto Wallet Generator ",font=("Arial",11),bg="#F0F0F0",fg="Black").place(x=60,y=75)
        self.bfr = tkinter.Label(self.crypto_frame, bg="#F0F0F0",font=("Arial",10),text="")
        self.bfr.place(x=20,y=200)
        self.labelstart = tkinter.Label(self.crypto_frame, text="Start Dec ", font=("Arial",10)).place(x=5,y=95)
        self._txt_inputstart = tkinter.Entry(self.crypto_frame, width=56, font=("Consolas", 11))
        self._txt_inputstart.insert(0, '1')
        self._txt_inputstart.place(x=75,y=100)
        self._txt_inputstart.focus()
        self.labelstop = tkinter.Label(self.crypto_frame, text="Stop Dec ", font=("Arial",10)).place(x=5,y= 120)
        self._txt_inputstop = tkinter.Entry(self.crypto_frame, width=56, font=("Consolas", 11))
        self._txt_inputstop.insert(0, stopdec)
        self._txt_inputstop.place(x=75,y=125)
        self._txt_inputstop.focus()
        self.labelmag = tkinter.Label(self.crypto_frame, text="Jump \ Mag ", font=("Arial",10)).place(x=550,y= 90)
        self._txt_inputmag = tkinter.Entry(self.crypto_frame, width=4, font=("Consolas", 11))
        self._txt_inputmag.insert(0, '1')
        self._txt_inputmag.place(x=550,y=125)
        self._txt_inputmag.focus()
        self.r1 = tkinter.Button(self.crypto_frame, text=" Random Start-Stop",font=("Arial",8),bg="#A3E4D7",command=self.Random_Bruteforce_Speed).place(x=13,y=160)
        self.s1 = tkinter.Button(self.crypto_frame, text=" Sequential Start-Stop",font=("Arial",8),bg="#B3B4D7",command=self.Sequential_Bruteforce_speed).place(x=120,y=160)
        self.sb1 = tkinter.Button(self.crypto_frame, text=" Backward Stop-Start ",font=("Arial",8),bg="#C3C4D7",command=self.Sequential_Bruteforce_speed_back).place(x=240,y=160)
        self.start= tkinter.Button(self.crypto_frame, text= "Start",font=("Arial",8),bg="#F0F0F0", command= self.start, fg='green').place(x=460,y=160)
        self.stop= tkinter.Button(self.crypto_frame, text= "Stop",font=("Arial",8),bg="#F0F0F0", command= self.stop, fg='red').place(x=420,y=160)
        self.labelvancrypto = tkinter.Label(self.crypto_frame, text=" Vanity Address \n Starting With ", font=("Arial",9), fg="red").place(x=5,y=490)
        self._txt_inputvancrypto = tkinter.Entry(self.crypto_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvancrypto.insert(0, '1FeexV6bAH')
        self._txt_inputvancrypto.place(x=100,y=500)
        self._txt_inputvancrypto.focus()
        self._txt_inputvancrypto1 = tkinter.Entry(self.crypto_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvancrypto1.insert(0, '1Mizogg')
        self._txt_inputvancrypto1.place(x=200,y=500)
        self._txt_inputvancrypto1.focus()
        self._txt_inputvancrypto2 = tkinter.Entry(self.crypto_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvancrypto2.insert(0, '3Merry')
        self._txt_inputvancrypto2.place(x=300,y=500)
        self._txt_inputvancrypto2.focus()
        self._txt_inputvancrypto3 = tkinter.Entry(self.crypto_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvancrypto3.insert(0, '0x1Happy')
        self._txt_inputvancrypto3.place(x=400,y=500)
        self._txt_inputvancrypto3.focus()
        self._txt_inputvancrypto4 = tkinter.Entry(self.crypto_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvancrypto4.insert(0, 'bc1xmas')
        self._txt_inputvancrypto4.place(x=500,y=500)
        self._txt_inputvancrypto4.focus()
        self.labelvancrypto = tkinter.Label(self.crypto_frame, text=" Optional Look for addresses starting with this prefix ", font=("Arial",7), fg="red").place(x=195,y=482)
        ########### page_frame ###########
        self.bwgpage = tkinter.Label(self.page_frame, text="Crypto Wallet Generator Based on Keys.lol 128 Private Keys per page",font=("Arial",11),bg="#F0F0F0",fg="Black").place(x=10,y=75)
        self.page_brute = tkinter.Label(self.page_frame, bg="#F0F0F0",font=("Arial",10),text="")
        self.page_brute.place(x=20,y=200)
        self.labelstart = tkinter.Label(self.page_frame, text="Start Page ", font=("Arial",10)).place(x=5,y=95)
        self._txt_inputstartpage = tkinter.Entry(self.page_frame, width=56, font=("Consolas", 11))
        self._txt_inputstartpage.insert(0, '1')
        self._txt_inputstartpage.place(x=75,y=100)
        self._txt_inputstartpage.focus()
        self.labelstoppage = tkinter.Label(self.page_frame, text="Stop Page ", font=("Arial",10)).place(x=5,y= 120)
        self._txt_inputstoppage = tkinter.Entry(self.page_frame, width=56, font=("Consolas", 11))
        self._txt_inputstoppage.insert(0, '904625697166532776746648320380374280100293470930272690489102837043110636675')
        self._txt_inputstoppage.place(x=75,y=125)
        self._txt_inputstoppage.focus()
        self.labelmagpage = tkinter.Label(self.page_frame, text="Jump \ Mag ", font=("Arial",10)).place(x=550,y= 95)
        self._txt_inputmagpage = tkinter.Entry(self.page_frame, width=4, font=("Consolas", 11))
        self._txt_inputmagpage.insert(0, '1')
        self._txt_inputmagpage.place(x=550,y=125)
        self._txt_inputmagpage.focus()
        self.r1page = tkinter.Button(self.page_frame, text=" Random Start-Stop",font=("Arial",8),bg="#A3E4D7",command=self.Random_Bruteforce_Speed_page).place(x=13,y=160)
        self.s1page = tkinter.Button(self.page_frame, text=" Sequential Start-Stop",font=("Arial",8),bg="#B3B4D7",command=self.Sequential_Bruteforce_speed_page).place(x=120,y=160)
        self.sb1page = tkinter.Button(self.page_frame, text=" Backward Stop-Start ",font=("Arial",8),bg="#C3C4D7",command=self.Sequential_Bruteforce_speed_back_page).place(x=240,y=160)
        self.startpage= tkinter.Button(self.page_frame, text= "Start",font=("Arial",8),bg="#F0F0F0", command= start1, fg='green').place(x=460,y=160)
        self.stoppage= tkinter.Button(self.page_frame, text= "Stop",font=("Arial",8),bg="#F0F0F0", command= stop1, fg='red').place(x=420,y=160)
        self.labelvanpage = tkinter.Label(self.page_frame, text=" Vanity Address \n Starting With ", font=("Arial",9), fg="red").place(x=5,y=490)
        self._txt_inputvanpage = tkinter.Entry(self.page_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanpage.insert(0, '1FeexV6bAH')
        self._txt_inputvanpage.place(x=100,y=500)
        self._txt_inputvanpage.focus()
        self._txt_inputvanpage1 = tkinter.Entry(self.page_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanpage1.insert(0, '1Mizogg')
        self._txt_inputvanpage1.place(x=200,y=500)
        self._txt_inputvanpage1.focus()
        self._txt_inputvanpage2 = tkinter.Entry(self.page_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanpage2.insert(0, '3Merry')
        self._txt_inputvanpage2.place(x=300,y=500)
        self._txt_inputvanpage2.focus()
        self._txt_inputvanpage3 = tkinter.Entry(self.page_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanpage3.insert(0, '0x1Happy')
        self._txt_inputvanpage3.place(x=400,y=500)
        self._txt_inputvanpage3.focus()
        self._txt_inputvanpage4 = tkinter.Entry(self.page_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanpage4.insert(0, 'bc1xmas')
        self._txt_inputvanpage4.place(x=500,y=500)
        self._txt_inputvanpage4.focus()
        self.labelvanpage = tkinter.Label(self.page_frame, text=" Optional Look for addresses starting with this prefix ", font=("Arial",7), fg="red").place(x=195,y=482)
        ########### word_frame ###########
        self.word_update = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",9),text="", width=72,fg="Red")
        self.word_update.place(x=10,y=190)
        self.word_update1 = tkinter.Label(self.word_frame, bg="#F0F0F0",font=("Arial",8),text="")
        self.word_update1.place(x=40,y=210)
        self.start2= tkinter.Button(self.word_frame, text= "Start",font=("Arial",8),bg="#F0F0F0", command= start2, fg='green').place(x=580,y=120)
        self.stop2= tkinter.Button(self.word_frame, text= "Stop",font=("Arial",8),bg="#F0F0F0", command= stop2, fg='red').place(x=540,y=120)
        self.titlem = tkinter.Label(self.word_frame, text="Mnemonic Words ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=180,y=160)
        self.titlem2 = tkinter.Label(self.word_frame, text="Random Mnemonic Wallet Generator Pick Ammount of Words to Generate",font=("Arial",11),bg="#F0F0F0",fg="Black").place(x=30,y=90)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "1 Word ",font=("Arial",8),bg="#A3E4A7", command= self.Random_word_offline).place(x=10,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "3 Words ",font=("Arial",8),bg="#A3E4B7", command= self.Random_word_offline1).place(x=60,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "6 Words ",font=("Arial",8),bg="#A3E4C7", command= self.Random_word_offline2).place(x=115,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "9 Words ",font=("Arial",8),bg="#A3E4D7", command= self.Random_word_offline3).place(x=170,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "12 Words ",font=("Arial",8),bg="#A3E4E7", command= self.Random_word_offline4).place(x=225,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "15 Words ",font=("Arial",8),bg="#A3E4F7", command= self.Random_word_offline5).place(x=287,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "18 Words ",font=("Arial",8),bg="#F3E4A8", command= self.Random_word_offline6).place(x=350,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "21 Words ",font=("Arial",8),bg="#F3E4B8", command= self.Random_word_offline7).place(x=412,y=120)
        self.my_buttonword = tkinter.Button(self.word_frame, text= "24 Words ",font=("Arial",8),bg="#F3E4C8", command= self.Random_word_offline8).place(x=474,y=120)
        self.labelvanword = tkinter.Label(self.word_frame, text=" Vanity Address \n Starting With ", font=("Arial",9), fg="red").place(x=5,y=490)
        self._txt_inputvanword = tkinter.Entry(self.word_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanword.insert(0, '1FeexV6bAH')
        self._txt_inputvanword.place(x=100,y=500)
        self._txt_inputvanword.focus()
        self._txt_inputvanword1 = tkinter.Entry(self.word_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanword1.insert(0, '1Mizogg')
        self._txt_inputvanword1.place(x=200,y=500)
        self._txt_inputvanword1.focus()
        self._txt_inputvanword2 = tkinter.Entry(self.word_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanword2.insert(0, '3Merry')
        self._txt_inputvanword2.place(x=300,y=500)
        self._txt_inputvanword2.focus()
        self._txt_inputvanword3 = tkinter.Entry(self.word_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanword3.insert(0, '0x1Happy')
        self._txt_inputvanword3.place(x=400,y=500)
        self._txt_inputvanword3.focus()
        self._txt_inputvanword4 = tkinter.Entry(self.word_frame, width=11, font=("Consolas", 11),fg="blue")
        self._txt_inputvanword4.insert(0, 'bc1xmas')
        self._txt_inputvanword4.place(x=500,y=500)
        self._txt_inputvanword4.focus()
        self.labelvanword = tkinter.Label(self.word_frame, text=" Optional Look for addresses starting with this prefix ", font=("Arial",7), fg="red").place(x=195,y=482)
        ########### hex_frame ###########
        self.hext = tkinter.Label(self.hex_frame, text="Rotation5 Bitcoin&Eth 20 Scans 128 private keys per scan 12,800 Addresses  ",font=("Arial",11),bg="#F0F0F0",fg="Black").place(x=10,y=75)
        self.hexl1 = tkinter.Label(self.hex_frame, text="Private Keys 1 - 10  ",font=("Arial",10),bg="#F0F0F0",fg="purple").place(x=60,y=270)
        self.hexl2 = tkinter.Label(self.hex_frame, text=" | ",font=("Arial",12),bg="#F0F0F0",fg="purple").place(x=270,y=270)
        self.hexl3 = tkinter.Label(self.hex_frame, text="Private Keys 11 - 20  ",font=("Arial",10),bg="#F0F0F0",fg="purple").place(x=350,y=270)
        self.rotation_brute = tkinter.Label(self.hex_frame, bg="#F0F0F0",font=("Consolas",6),text="")
        self.rotation_brute.place(x=5,y=290)
        self.labelstarthexnum = tkinter.Label(self.hex_frame, text="1", font=("Arial",12), fg='red').place(x=60,y=100)
        self.labelstarthex = tkinter.Label(self.hex_frame, text="Start \nBIT ", font=("Arial",10), fg='green').place(x=5,y=115)
        self._txt_inputstarthex = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex.insert(0, '65')
        self._txt_inputstarthex.place(x=55,y=125)
        self._txt_inputstarthex.focus()
        self.labelstophex = tkinter.Label(self.hex_frame, text="Stop \nBIT ", font=("Arial",10), fg='orange').place(x=5,y= 150)
        self._txt_inputstophex = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex.insert(0, '67')
        self._txt_inputstophex.place(x=55,y=155)
        self._txt_inputstophex.focus()
        self.labelstarthexnum0 = tkinter.Label(self.hex_frame, text="2", font=("Arial",12), fg='red').place(x=110,y=100)
        self._txt_inputstarthex0 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex0.insert(0, '65')
        self._txt_inputstarthex0.place(x=100,y=125)
        self._txt_inputstarthex0.focus()
        self._txt_inputstophex0 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex0.insert(0, '70')
        self._txt_inputstophex0.place(x=100,y=155)
        self._txt_inputstophex0.focus()
        self.labelstarthexnum1 = tkinter.Label(self.hex_frame, text="3", font=("Arial",12), fg='red').place(x=155,y=100)
        self._txt_inputstarthex1 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex1.insert(0, '65')
        self._txt_inputstarthex1.place(x=145,y=125)
        self._txt_inputstarthex1.focus()
        self._txt_inputstophex1 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex1.insert(0, '80')
        self._txt_inputstophex1.place(x=145,y=155)
        self._txt_inputstophex1.focus()
        self.labelstarthexnum2 = tkinter.Label(self.hex_frame, text="4", font=("Arial",12), fg='red').place(x=200,y=100)
        self._txt_inputstarthex2 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex2.insert(0, '65')
        self._txt_inputstarthex2.place(x=190,y=125)
        self._txt_inputstarthex2.focus()
        self._txt_inputstophex2 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex2.insert(0, '90')
        self._txt_inputstophex2.place(x=190,y=155)
        self._txt_inputstophex2.focus()
        self.labelstarthexnum3 = tkinter.Label(self.hex_frame, text="5", font=("Arial",12), fg='red').place(x=245,y=100)
        self._txt_inputstarthex3 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex3.insert(0, '65')
        self._txt_inputstarthex3.place(x=235,y=125)
        self._txt_inputstarthex3.focus()
        self._txt_inputstophex3 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex3.insert(0, '100')
        self._txt_inputstophex3.place(x=235,y=155)
        self._txt_inputstophex3.focus()
        self.labelstarthexnum4 = tkinter.Label(self.hex_frame, text="6", font=("Arial",12), fg='red').place(x=290,y=100)
        self._txt_inputstarthex4 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex4.insert(0, '65')
        self._txt_inputstarthex4.place(x=280,y=125)
        self._txt_inputstarthex4.focus()
        self._txt_inputstophex4 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex4.insert(0, '110')
        self._txt_inputstophex4.place(x=280,y=155)
        self._txt_inputstophex4.focus()
        self.labelstarthexnum5 = tkinter.Label(self.hex_frame, text="7", font=("Arial",12), fg='red').place(x=335,y=100)
        self._txt_inputstarthex5 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex5.insert(0, '65')
        self._txt_inputstarthex5.place(x=325,y=125)
        self._txt_inputstarthex5.focus()
        self._txt_inputstophex5 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex5.insert(0, '120')
        self._txt_inputstophex5.place(x=325,y=155)
        self._txt_inputstophex5.focus()
        self.labelstarthexnum6 = tkinter.Label(self.hex_frame, text="8", font=("Arial",12), fg='red').place(x=380,y=100)
        self._txt_inputstarthex6 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex6.insert(0, '65')
        self._txt_inputstarthex6.place(x=370,y=125)
        self._txt_inputstarthex6.focus()
        self._txt_inputstophex6 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex6.insert(0, '130')
        self._txt_inputstophex6.place(x=370,y=155)
        self._txt_inputstophex6.focus()
        self.labelstarthexnum7 = tkinter.Label(self.hex_frame, text="9", font=("Arial",12), fg='red').place(x=425,y=100)
        self._txt_inputstarthex7 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex7.insert(0, '65')
        self._txt_inputstarthex7.place(x=415,y=125)
        self._txt_inputstarthex7.focus()
        self._txt_inputstophex7 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex7.insert(0, '140')
        self._txt_inputstophex7.place(x=415,y=155)
        self._txt_inputstophex7.focus()
        self.labelstarthexnum8 = tkinter.Label(self.hex_frame, text="10", font=("Arial",12), fg='red').place(x=460,y=100)
        self._txt_inputstarthex8 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex8.insert(0, '65')
        self._txt_inputstarthex8.place(x=460,y=125)
        self._txt_inputstarthex8.focus()
        self._txt_inputstophex8 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex8.insert(0, '150')
        self._txt_inputstophex8.place(x=460,y=155)
        self._txt_inputstophex8.focus()
        self.labelstarthexnum9 = tkinter.Label(self.hex_frame, text="11", font=("Arial",12), fg='red').place(x=55,y=180)
        self.labelstarthex2 = tkinter.Label(self.hex_frame, text="Start \nBIT ", font=("Arial",10), fg='green').place(x=5,y=195)
        self._txt_inputstarthex9 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex9.insert(0, '65')
        self._txt_inputstarthex9.place(x=55,y=205)
        self._txt_inputstarthex9.focus()
        self.labelstophex2 = tkinter.Label(self.hex_frame, text="Stop \nBIT ", font=("Arial",10), fg='orange').place(x=5,y= 230)
        self._txt_inputstophex9 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex9.insert(0, '160')
        self._txt_inputstophex9.place(x=55,y=235)
        self._txt_inputstophex9.focus()
        self.labelstarthexnum10 = tkinter.Label(self.hex_frame, text="12", font=("Arial",12), fg='red').place(x=100,y=180)
        self._txt_inputstarthex10 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex10.insert(0, '65')
        self._txt_inputstarthex10.place(x=100,y=205)
        self._txt_inputstarthex10.focus()
        self._txt_inputstophex10 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex10.insert(0, '170')
        self._txt_inputstophex10.place(x=100,y=235)
        self._txt_inputstophex10.focus()
        self.labelstarthexnum11 = tkinter.Label(self.hex_frame, text="13", font=("Arial",12), fg='red').place(x=145,y=180)
        self._txt_inputstarthex11 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex11.insert(0, '65')
        self._txt_inputstarthex11.place(x=145,y=205)
        self._txt_inputstarthex11.focus()
        self._txt_inputstophex11 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex11.insert(0, '180')
        self._txt_inputstophex11.place(x=145,y=235)
        self._txt_inputstophex11.focus()
        self.labelstarthexnum12 = tkinter.Label(self.hex_frame, text="14", font=("Arial",12), fg='red').place(x=190,y=180)
        self._txt_inputstarthex12 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex12.insert(0, '65')
        self._txt_inputstarthex12.place(x=190,y=205)
        self._txt_inputstarthex12.focus()
        self._txt_inputstophex12 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex12.insert(0, '190')
        self._txt_inputstophex12.place(x=190,y=235)
        self._txt_inputstophex12.focus()
        self.labelstarthexnum13 = tkinter.Label(self.hex_frame, text="15", font=("Arial",12), fg='red').place(x=235,y=180)
        self._txt_inputstarthex13 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex13.insert(0, '65')
        self._txt_inputstarthex13.place(x=235,y=205)
        self._txt_inputstarthex13.focus()
        self._txt_inputstophex13 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex13.insert(0, '200')
        self._txt_inputstophex13.place(x=235,y=235)
        self._txt_inputstophex13.focus()
        self.labelstarthexnum14 = tkinter.Label(self.hex_frame, text="16", font=("Arial",12), fg='red').place(x=280,y=180)
        self._txt_inputstarthex14 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstarthex14.insert(0, '65')
        self._txt_inputstarthex14.place(x=280,y=205)
        self._txt_inputstarthex14.focus()
        self._txt_inputstophex14 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex14.insert(0, '210')
        self._txt_inputstophex14.place(x=280,y=235)
        self._txt_inputstophex14.focus()
        self.labelstarthexnum15 = tkinter.Label(self.hex_frame, text="17", font=("Arial",12), fg='red').place(x=325,y=180)
        self._txt_inputstarthex15 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex15.insert(0, '65')
        self._txt_inputstarthex15.place(x=325,y=205)
        self._txt_inputstarthex15.focus()
        self._txt_inputstophex15 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex15.insert(0, '220')
        self._txt_inputstophex15.place(x=325,y=235)
        self._txt_inputstophex15.focus()
        self.labelstarthexnum16 = tkinter.Label(self.hex_frame, text="18", font=("Arial",12), fg='red').place(x=370,y=180)
        self._txt_inputstarthex16 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex16.insert(0, '65')
        self._txt_inputstarthex16.place(x=370,y=205)
        self._txt_inputstarthex16.focus()
        self._txt_inputstophex16 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex16.insert(0, '230')
        self._txt_inputstophex16.place(x=370,y=235)
        self._txt_inputstophex16.focus()
        self.labelstarthexnum17 = tkinter.Label(self.hex_frame, text="19", font=("Arial",12), fg='red').place(x=415,y=180)
        self._txt_inputstarthex17 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex17.insert(0, '65')
        self._txt_inputstarthex17.place(x=415,y=205)
        self._txt_inputstarthex17.focus()
        self._txt_inputstophex17 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 13))
        self._txt_inputstophex17.insert(0, '240')
        self._txt_inputstophex17.place(x=415,y=235)
        self._txt_inputstophex17.focus()
        self.labelstarthexnum18 = tkinter.Label(self.hex_frame, text="20", font=("Arial",12), fg='red').place(x=460,y=180)
        self._txt_inputstarthex18 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstarthex18.insert(0, '65')
        self._txt_inputstarthex18.place(x=460,y=205)
        self._txt_inputstarthex18.focus()
        self._txt_inputstophex18 = tkinter.Entry(self.hex_frame, width=4, font=("Consolas", 11))
        self._txt_inputstophex18.insert(0, '256')
        self._txt_inputstophex18.place(x=460,y=235)
        self._txt_inputstophex18.focus()
        self.hex1 = tkinter.Button(self.hex_frame, text=" Rotation \n 5 Generator ",font=("Arial",11),bg="#A3E4D7",command=self.rotation_five).place(x=510,y=190)
        self.start3= tkinter.Button(self.hex_frame, text= "Start",font=("Arial",10),bg="#F0F0F0", command= start3, fg='green').place(x=510,y=140)
        self.stop3= tkinter.Button(self.hex_frame, text= "Stop",font=("Arial",10),bg="#F0F0F0", command= stop3, fg='red').place(x=560,y=140)
        ########### recovery_frame ###########
        self.recovery_title = tkinter.Label(self.recovery_frame, text=" WIF HEX DEC Recovery Tools ",font=("Arial",12),bg="#F0F0F0",fg="Black").place(x=100,y=80)
        self.labeladd_WIF = tkinter.Label(self.recovery_frame, text="WIF HERE (WIF Recovery Tool ****  MAX 10 MISSING  ****)  ", font=("Arial",10),fg="#FF6700").place(x=20,y=100)
        self._txt_inputadd_WIF = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 10))
        self._txt_inputadd_WIF.insert(0, 'KwDiBf89Qg*bjEhKnhXJuH7LrciVrZi3qYjgd*M7rFU*4sHUHy8*')
        self._txt_inputadd_WIF.place(x=10,y=120)
        self._txt_inputadd_WIF.focus()
        self.labeladd_HEX = tkinter.Label(self.recovery_frame, text="HEX HERE (HEX Recovery Tool ****  MAX 10 MISSING  ****)  ", font=("Arial",10),fg="#FF6700").place(x=20,y=145)
        self._txt_inputadd_HEX = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 10))
        self._txt_inputadd_HEX.insert(0, '0**000000000000000000000000000000000000000000000000000000000000*')
        self._txt_inputadd_HEX.place(x=10,y=165)
        self._txt_inputadd_HEX.focus()
        self.labeladd_DEC = tkinter.Label(self.recovery_frame, text="DEC HERE (DEC Recovery Tool ****  MAX 18 MISSING  ****)  ", font=("Arial",10),fg="#FF6700").place(x=20,y=190)
        self._txt_inputadd_DEC = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 10))
        self._txt_inputadd_DEC.insert(0, '***1')
        self._txt_inputadd_DEC.place(x=10,y=210)
        self._txt_inputadd_DEC.focus()
        self.labeladd_WORD = tkinter.Label(self.recovery_frame, text="Mnemonic HERE (Mnm Recovery Tool ****  MAX 5 MISSING  ****)  ", font=("Arial",10),fg="#FF6700").place(x=20,y=235)
        self._txt_inputadd_WORD = tkinter.Entry(self.recovery_frame, width=64, font=("Consolas", 10))
        self._txt_inputadd_WORD.insert(0, 'COMING SOON !!!!!!!')
        self._txt_inputadd_WORD.place(x=10,y=255)
        self._txt_inputadd_WORD.focus()
        self.labelWIF1 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",8),text="")
        self.labelWIF1.place(x=10,y=280)
        self.labelWIF2 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",9),text="",fg="green")
        self.labelWIF2.place(x=10,y=305)
        self.labelWIF3 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",11),text="",fg="red")
        self.labelWIF3.place(x=10,y=330)
        self.labelREC = tkinter.Label(self.recovery_frame, text="Remaining ", font=("Arial",12),fg="purple").place(x=10,y=350)
        self.labelWIF4 = tkinter.Label(self.recovery_frame, bg="#F0F0F0",font=("Arial",12),text="",fg="red")
        self.labelWIF4.place(x=100,y=350)
        self.sqWIF= tkinter.Button(self.recovery_frame, text= "WIF SEQ",font=("Arial",8),bg="#B3F4F8", command= self.start_recovery_wif_S, fg='black').place(x=385,y=93)
        self.sqHEX= tkinter.Button(self.recovery_frame, text= "HEX SEQ",font=("Arial",8),bg="#B3F4F8", command= self.start_recovery_HEX_S, fg='black').place(x=385,y=140)
        self.sqDEC= tkinter.Button(self.recovery_frame, text= "DEC SEQ",font=("Arial",8),bg="#B3F4F8", command= self.start_recovery_DEC_S, fg='black').place(x=385,y=185)
        self.ranWIF= tkinter.Button(self.recovery_frame, text= "WIF Random",font=("Arial",8),bg="#F3E4C8", command= self.start_recovery_wif_R, fg='black').place(x=450,y=93)
        self.ranHEX= tkinter.Button(self.recovery_frame, text= "HEX Random",font=("Arial",8),bg="#F3E4C8", command= self.start_recovery_HEX_R, fg='black').place(x=450,y=140)
        self.ranDEC= tkinter.Button(self.recovery_frame, text= "DEC Random",font=("Arial",8),bg="#F3E4C8", command= self.start_recovery_DEC_R, fg='black').place(x=450,y=185)

    ########### Recovery Tools  ###########
    def start_recovery_wif_S(self):
        scan_IN = 'WIF'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_WIF.get()
        recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_HEX_S(self):
        scan_IN = 'HEX'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_HEX.get()
        recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_DEC_S(self):
        scan_IN = 'DEC'
        mode = 'sequential'
        rec_IN = self._txt_inputadd_DEC.get()
        recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_wif_R(self):
        scan_IN = 'WIF'
        mode = 'random'
        rec_IN = self._txt_inputadd_WIF.get()
        recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_HEX_R(self):
        scan_IN = 'HEX'
        mode = 'random'
        rec_IN = self._txt_inputadd_HEX.get()
        recovery_main(self, scan_IN, rec_IN, mode)
        
    def start_recovery_DEC_R(self):
        scan_IN = 'DEC'
        mode = 'random'
        rec_IN = self._txt_inputadd_DEC.get()
        recovery_main(self, scan_IN, rec_IN, mode)
        
    def start(self):
        self.run= True

    def stop(self):
        self.run= False
    ###########  Brute PAGE Program Main ###########
    def brute_results_page(self, page):
        global total, totaladd
        scantext = get_page(self, page)
        self.page_brute.config(text = scantext)
        self.page_brute.update()
        total+=128
        totaladd+=640
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
    
    def Random_Bruteforce_Speed_page(self):
        startpage = self._txt_inputstartpage.get().strip().replace(" ", "")
        stoppage = self._txt_inputstoppage.get().strip().replace(" ", "")
        while run1:
            page =int(RandomInteger(int(startpage), int(stoppage)))
            self.brute_results_page(page)
    
    def Sequential_Bruteforce_speed_page(self):
        startpage = self._txt_inputstartpage.get().strip().replace(" ", "")
        stoppage = self._txt_inputstoppage.get().strip().replace(" ", "")
        mag = self._txt_inputmagpage.get().strip().replace(" ", "")
        while run1:
            dec = int(startpage)
            if dec == int(stoppage):
                self.stop1()
            else:
                self.brute_results_page(dec)
                startpage = int(startpage) + int(mag)
    
    def Sequential_Bruteforce_speed_back_page(self):
        startpage = self._txt_inputstartpage.get().strip().replace(" ", "")
        stoppage = self._txt_inputstoppage.get().strip().replace(" ", "")
        mag = self._txt_inputmagpage.get().strip().replace(" ", "")
        while run1:
            dec = int(stoppage)
            if dec == int(startpage):
                self.stop1()
            else:
                self.brute_results_page(dec)
                stoppage = int(stoppage) - int(mag)
    ###########  Brute Program Main ###########
    def brute_results(self, dec):
        global total, totaladd
        scantext = brute_crypto(self, dec)
        self.bfr.config(text = scantext)
        self.bfr.update()
        total+=1
        totaladd+=5
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def Random_Bruteforce_Speed(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        while self.run:
            dec =int(RandomInteger(int(startdec), int(stopdec)))
            self.brute_results(dec)

    def Sequential_Bruteforce_speed(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        mag = self._txt_inputmag.get().strip().replace(" ", "")
        while self.run:
            dec = int(startdec)
            if dec == int(stopdec):
                self.stop()
            else:
                self.brute_results(dec)
                startdec = int(startdec) + int(mag)
    
    def Sequential_Bruteforce_speed_back(self):
        startdec = self._txt_inputstart.get().strip().replace(" ", "")
        stopdec = self._txt_inputstop.get().strip().replace(" ", "")
        mag = self._txt_inputmag.get().strip().replace(" ", "")
        while self.run:
            dec = int(stopdec)
            if dec == int(startdec):
                self.stop()
            else:
                self.brute_results(dec)
                stopdec = int(stopdec) - int(mag)
    ###########  Rotation 4 Program Main ###########
    def rotation_results(self, dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18):
        global total, totaladd
        scantext = hexhunter(self, dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18)
        self.rotation_brute.config(text = scantext)
        self.rotation_brute.update()
        total+=20   # 2560
        totaladd+= 100  #  10240
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def rotation_five(self):
        startbit = self._txt_inputstarthex.get().strip().replace(" ", "")
        stopbit = self._txt_inputstophex.get().strip().replace(" ", "")
        startbit0 = self._txt_inputstarthex0.get().strip().replace(" ", "")
        stopbit0 = self._txt_inputstophex0.get().strip().replace(" ", "")
        startbit1 = self._txt_inputstarthex1.get().strip().replace(" ", "")
        stopbit1 = self._txt_inputstophex1.get().strip().replace(" ", "")
        startbit2 = self._txt_inputstarthex2.get().strip().replace(" ", "")
        stopbit2 = self._txt_inputstophex2.get().strip().replace(" ", "")
        startbit3 = self._txt_inputstarthex3.get().strip().replace(" ", "")
        stopbit3 = self._txt_inputstophex3.get().strip().replace(" ", "")
        startbit4 = self._txt_inputstarthex4.get().strip().replace(" ", "")
        stopbit4 = self._txt_inputstophex4.get().strip().replace(" ", "")
        startbit5 = self._txt_inputstarthex5.get().strip().replace(" ", "")
        stopbit5 = self._txt_inputstophex5.get().strip().replace(" ", "")
        startbit6 = self._txt_inputstarthex6.get().strip().replace(" ", "")
        stopbit6 = self._txt_inputstophex6.get().strip().replace(" ", "")
        startbit7 = self._txt_inputstarthex7.get().strip().replace(" ", "")
        stopbit7 = self._txt_inputstophex7.get().strip().replace(" ", "")
        startbit8 = self._txt_inputstarthex8.get().strip().replace(" ", "")
        stopbit8 = self._txt_inputstophex8.get().strip().replace(" ", "")
        startbit9 = self._txt_inputstarthex9.get().strip().replace(" ", "")
        stopbit9 = self._txt_inputstophex9.get().strip().replace(" ", "")
        startbit10 = self._txt_inputstarthex10.get().strip().replace(" ", "")
        stopbit10 = self._txt_inputstophex10.get().strip().replace(" ", "")
        startbit11 = self._txt_inputstarthex11.get().strip().replace(" ", "")
        stopbit11 = self._txt_inputstophex11.get().strip().replace(" ", "")
        startbit12 = self._txt_inputstarthex12.get().strip().replace(" ", "")
        stopbit12 = self._txt_inputstophex12.get().strip().replace(" ", "")
        startbit13 = self._txt_inputstarthex13.get().strip().replace(" ", "")
        stopbit13 = self._txt_inputstophex13.get().strip().replace(" ", "")
        startbit14 = self._txt_inputstarthex14.get().strip().replace(" ", "")
        stopbit14 = self._txt_inputstophex14.get().strip().replace(" ", "")
        startbit15 = self._txt_inputstarthex15.get().strip().replace(" ", "")
        stopbit15 = self._txt_inputstophex15.get().strip().replace(" ", "")
        startbit16 = self._txt_inputstarthex16.get().strip().replace(" ", "")
        stopbit16 = self._txt_inputstophex16.get().strip().replace(" ", "")
        startbit17 = self._txt_inputstarthex17.get().strip().replace(" ", "")
        stopbit17 = self._txt_inputstophex17.get().strip().replace(" ", "")
        startbit18 = self._txt_inputstarthex18.get().strip().replace(" ", "")
        stopbit18 = self._txt_inputstophex18.get().strip().replace(" ", "")
        while run3:
            dec =int(RandomInteger(2**(int(startbit)), 2**(int(stopbit))))
            dec0 =int(RandomInteger(2**(int(startbit0)), 2**(int(stopbit0))))
            dec1 =int(RandomInteger(2**(int(startbit1)), 2**(int(stopbit1))))
            dec2 =int(RandomInteger(2**(int(startbit2)), 2**(int(stopbit2))))
            dec3 =int(RandomInteger(2**(int(startbit3)), 2**(int(stopbit3))))
            dec4 =int(RandomInteger(2**(int(startbit4)), 2**(int(stopbit4))))
            dec5 =int(RandomInteger(2**(int(startbit5)), 2**(int(stopbit5))))
            dec6 =int(RandomInteger(2**(int(startbit6)), 2**(int(stopbit6))))
            dec7 =int(RandomInteger(2**(int(startbit7)), 2**(int(stopbit7))))
            dec8 =int(RandomInteger(2**(int(startbit8)), 2**(int(stopbit8))))
            dec9 =int(RandomInteger(2**(int(startbit9)), 2**(int(stopbit9))))
            dec10 =int(RandomInteger(2**(int(startbit10)), 2**(int(stopbit10))))
            dec11 =int(RandomInteger(2**(int(startbit11)), 2**(int(stopbit11))))
            dec12 =int(RandomInteger(2**(int(startbit12)), 2**(int(stopbit12))))
            dec13 =int(RandomInteger(2**(int(startbit13)), 2**(int(stopbit13))))
            dec14 =int(RandomInteger(2**(int(startbit14)), 2**(int(stopbit14))))
            dec15 =int(RandomInteger(2**(int(startbit15)), 2**(int(stopbit15))))
            dec16 =int(RandomInteger(2**(int(startbit16)), 2**(int(stopbit16))))
            dec17 =int(RandomInteger(2**(int(startbit17)), 2**(int(stopbit17))))
            dec18 =int(RandomInteger(2**(int(startbit18)), 2**(int(stopbit18))))
            self.rotation_results(dec, dec0, dec1, dec2, dec3, dec4, dec5, dec6, dec7, dec8, dec9, dec10, dec11, dec12, dec13, dec14, dec15, dec16, dec17, dec18)
    ###########  Brain Program Main ###########
    def Random_brain_single(self):
        passphrase = self._txt_inputbrain.get().strip()
        global total, totaladd
        brainvartext = passphrase
        brainvartext1 = rboffline(self, passphrase)
        self.brain_update.config(text = brainvartext)
        self.brain_update1.config(text = brainvartext1)
        self.brain_update.update()
        self.brain_update1.update()
        total+=1
        totaladd+=5
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')
        
    def brain_results_offline(self, passphrase):
        global total, totaladd
        brainvartext = passphrase
        brainvartext1 = rboffline(self, passphrase)
        self.brain_update.config(text = brainvartext)
        self.brain_update1.config(text = brainvartext1)
        self.brain_update.update()
        self.brain_update1.update()
        total+=1
        totaladd+=5
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def Random_brain_offline(self):
        start_amm = self._txt_brain_ammount.get().strip().replace(" ", "")
        stop_amm = self._txt_brain_total.get().strip().replace(" ", "")
        while self.run:
            passphrase = ' '.join(random.sample(mylist, random.randint(int(start_amm), int(stop_amm))))
            self.brain_results_offline(passphrase)
            
    def Random_brain_offline1(self):
        for i in range(0,len(mylist)):
            passphrase = mylist[i]
            self.brain_results_offline(passphrase)
    
    def Random_brain_offline2(self):
        start_amm = self._txt_brain_ammount.get().strip().replace(" ", "")
        stop_amm = self._txt_brain_total.get().strip().replace(" ", "")
        while self.run:
            words = random.randrange(int(start_amm), int(stop_amm))
            passphrase = ''.join(random.sample(string.ascii_lowercase, words))
            self.brain_results_offline(passphrase)
                
    def popwinner(self):
        self.popwin = Toplevel()
        self.popwin.title("MiniHunter.py")
        #self.popwin.iconbitmap('images/ico')
        self.popwin.geometry("700x250")
        self.widgetwinpop = tkinter.Label(self.popwin, compound='top')
        self.widgetwinpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetwinpop['text'] = "© MIZOGG 2018 - 2022"
        self.widgetwinpop['image'] = self.widgetwinpop.miz_image_png
        self.widgetwinpop.place(x=380,y=180)
        self.widgetwin2pop = tkinter.Label(self.popwin, compound='top')
        self.widgetwin2pop.miz_image_png = tkinter.PhotoImage(file='images/congratulations.gif')
        self.widgetwin2pop['image'] = self.widgetwin2pop.miz_image_png
        self.widgetwin2pop.place(x=10,y=165)
        self.editAreapop = tkst.ScrolledText(master = self.popwin, wrap = tkinter.WORD, width  = 70, height = 6,font=("Arial",12))
        self.editAreapop.pack(padx=10, pady=10)
        self.editAreapop.insert(tkinter.INSERT, self.WINTEXT)
        self.framewinpop = Frame(self.popwin)
        self.framewinpop.pack(padx=10, pady=10)
        self.buttonwinpop = Button(self.framewinpop, text=" Close ", command=self.popwin.destroy)
        self.buttonwinpop.grid(row=0, column=1)
        #self.popwin.after(2000,lambda:self.popwin.destroy())
        ########### START Window POP UP ###########
    def startpop(self):
        self.pop = Toplevel()
        self.pop.title("BitHunter.py")
        #self.pop.iconbitmap('images/ico')
        self.pop.geometry("500x300")
        self.widgetpop = tkinter.Label(self.pop, compound='top')
        self.widgetpop.miz_image_png = tkinter.PhotoImage(file='images/mizogg.png')
        self.widgetpop['text'] = "© MIZOGG 2018 - 2022"
        self.widgetpop['image'] = self.widgetpop.miz_image_png
        self.widgetpop.place(x=140,y=220)
        self.label = tkinter.Label(self.pop, text='Welcome to MiniHunter Multi Crypto...... \n\n Made By Mizogg.co.uk \n\n Version 1.2 23/12/22').pack(pady=10)
        self.label1 = tkinter.Label(self.pop, text= "MiniHunter application use at your own risk.\n There is no promise of warranty.\n\n  Auto Agree 5 secs", font=('Helvetica 8 bold')).pack(pady=10)
        self.framepop = Frame(self.pop)
        self.framepop.pack(pady=10)
        self.buttonpop = Button(self.framepop, text=" Agree ", command=lambda: self.pop.destroy())
        self.buttonpop.grid(row=0, column=1)
        self.buttonpop = Button(self.framepop, text=" Disagree ", command=quit)
        self.buttonpop.grid(row=0, column=2)
        self.pop.after(5000,lambda:self.pop.destroy())
        
    def CLOSEWINDOW(self):
        self.pop.destroy()

        ###########  Mnemonic Program Main ###########
    def word_results_offline(self, rnds):
        global total, totaladd
        mnem = create_valid_mnemonics(strength=int(rnds))
        wordvartext = rwoffline(self, mnem)
        self.word_update.config(text = mnem)
        self.word_update1.config(text = wordvartext)
        self.word_update.update()
        self.word_update1.update()
        total+=1
        totaladd+=4
        self.totalC.config(text = f'{total}')
        self.totalA.config(text = f'{totaladd}')

    def Random_word_offline(self):
        while run2:
            rnds = '16'
            self.word_results_offline(rnds)

    def Random_word_offline1(self):
        while run2:
            rnds = '32'
            self.word_results_offline(rnds)

    def Random_word_offline2(self):
        while run2:
            rnds = '64'
            self.word_results_offline(rnds)

    def Random_word_offline3(self):
        while run2:
            rnds = '96'
            self.word_results_offline(rnds)

    def Random_word_offline4(self):
        while run2:
            rnds = '128'
            self.word_results_offline(rnds)

    def Random_word_offline5(self):
        while run2:
            rnds = '160'
            self.word_results_offline(rnds)

    def Random_word_offline6(self):
        while run2:
            rnds = '192'
            self.word_results_offline(rnds)

    def Random_word_offline7(self):
        while run2:
            rnds = '224'
            self.word_results_offline(rnds)

    def Random_word_offline8(self):
        while run2:
            rnds = '256'
            self.word_results_offline(rnds)
    ########### Conversion Main Program ###########
    def evt_btc_bin(self):
        try:
            bin_value = self._txt_input.get().strip().replace(" ", "")
            dec_value = bin2dec(bin_value)
            hex_value = bin2hex(bin_value)
            bit_value = bin2bit(bin_value)
            btc_value = int2addr(self, dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Binary conversion")
            print(ex, file=sys.stderr)
            
    def evt_btc_bit(self):
        try:
            bit_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = bit2bin(bit_value)
            dec_value = bit2dec(bit_value)
            hex_value = bit2hex(bit_value)
            btc_value = int2addr(self, dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Bits conversion")
            print(ex, file=sys.stderr)
    
    def evt_btc_dec(self):
        try:
            dec_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(self, dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
            
    def evt_rd_dec(self):
        try:
            dec_value = int(RandomInteger(startdec, stopdec))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(self, dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
    
    def evt_jump1_dec(self):
        try:
            dec_value = int(self.txt_outputdec.get().strip().replace(" ", ""))
            dec_value += int(self._jump_input.get().strip().replace(" ", ""))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(self, dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr)
            
    def evt_jump_rm1_dec(self):
        try:
            dec_value = int(self.txt_outputdec.get().strip().replace(" ", ""))
            dec_value -= int(self._jump_input.get().strip().replace(" ", ""))
            bin_value = dec2bin(dec_value)
            hex_value = dec2hex(dec_value)
            bit_value = dec2bit(dec_value)
            btc_value = int2addr(self, dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Decimal conversion")
            print(ex, file=sys.stderr) 
            
    def evt_btc_hex(self):
        try:
            hex_value = self._txt_input.get().strip().replace(" ", "")
            bin_value = hex2bin(hex_value)
            dec_value = hex2dec(hex_value)
            bit_value = hex2bit(hex_value)
            btc_value = int2addr(self, dec_value)
            self._set_values(bin_value, dec_value, hex_value, bit_value, btc_value)
        except Exception as ex:
            tkinter.messagebox.showerror("Error", "Invalid Hexadecimal conversion")
            print(ex, file=sys.stderr)
    
    def _set_values(self, bin_value, dec_value, hex_value, bit_value, btc_value):
        if not bin_value.startswith("0b"):
            bin_value = "0b" + bin_value
        if not hex_value.startswith("0x"):
            hex_value = "0x" + hex_value
        self._stringvar_bin.set(bin_value)
        self._stringvar_bit.set(bit_value)
        self._stringvar_dec.set(dec_value)
        self._stringvar_hex.set(hex_value)
        self._stringvar_addr.set(btc_value)
    ########### START ###########
    def mainloop(self):
        self.main_frame.mainloop()

if __name__ == "__main__":
    win = MainWindow()
    win.mainloop()
