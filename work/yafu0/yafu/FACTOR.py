import ctypes
import urllib.request
import urllib.error
import urllib.parse
import base64
import json
import hashlib
import struct
import random
import os
import sys
import struct
import sympy as sp
import gmpy2 as gmp
from math import floor, ceil
from gmpy2 import mpz,mpq,mpfr,mpc
from gmpy2 import isqrt, sqrt, log2, gcd
from numpy.ctypeslib import ndpointer
from sympy.ntheory import isprime
import subprocess
import random
from random import randrange
from time import time
import multiprocessing
import hashlib
import base58
import sympy as sp
import secrets as st
from random import shuffle
import statistics

#Attibution note: the Bitcoin RPC components here are taken
#                 from publicly available sources and are not
#                 my own original code.

#get sieves
siever = None
siev = None

#Determine stopping point, parametr <= 35.
MAX_SIEVE_LEVEL = 27

BLOCK_SIZE = 50
BLOCK_TIME = [0] * BLOCK_SIZE

def load_levels():
    global siever
    global siev
    global MAX_SIEVE_LEVEL

    #Check if the primorial levels were built
    filenames = [ level_file for level_file 
            in next(os.walk("isieve/"), (None, None, []))[2]
            if "primorial_level_" in level_file ]

    #Order in ascending order
    filenames.sort( key= lambda x: int( x.split("_")[-1].split(".")[0] ) )

    if filenames:
        siever = {}
        START = time()
        for File in filenames:
            level = int( File.split("_")[-1].split(".")[0] )
            if level > MAX_SIEVE_LEVEL:
                break
            start = time()
            f = open(f"isieve/{File}", "r")
            line = f.readlines()[0]
            siever[level] = mpz( int(line,16) )
            print("Level loaded: ",level, "  | ", time() - start, " Seconds.")
        print("Total time: ", time() - START, " Seconds.")

    else:
        siev = mpz( sp.factorial(10000))
    
RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8332")
RPC_USER = os.environ.get("RPC_USER", "replaceme")
RPC_PASS = os.environ.get("RPC_PASS", "replaceme") 

################################################################################
# CTypes and utility functions
################################################################################
class CParams(ctypes.Structure):
    _fields_=[("hashRounds",ctypes.c_uint32 ),
              ("MillerRabinRounds",ctypes.c_uint32 )  
             ]
    
class uint1024(ctypes.Structure):
    _fields_=[("data", ctypes.c_uint64 * 16 )]

class uint256(ctypes.Structure):
    _fields_=[("data", ctypes.c_uint64 * 4 )]
    
def uint256ToInt( m ):
    return sum(a << (idx*64) for idx, a in enumerate(m))

def uint1024ToInt( m ):
    ans = 0    

    if hasattr(m, 'data'):
        for idx in range(16):
            ans += m.data[idx] << (idx*64)
    else:
        for idx,a in enumerate(m):
            ans += a << (idx*64)
    
    return ans

def IntToUint1024( m ):
    ans = [0]*16
    n = int(m)
    MASK = (1<<64)-1
    
    for idx in range(16):
        ans[idx] = (m >> (idx*64)) & MASK
    
    return (ctypes.c_uint64 * 16)(*ans)
    
    
def hashToArray( Hash ):
    if Hash == 0:
        return [0,0,0,0]

    number = int(Hash,16)
    MASK = (1 << 64) - 1
    return [ ( number >> 64*(jj) )&MASK for jj in range(0, 4) ]


################################################################################
# Bitcoin Daemon JSON-HTTP RPC
################################################################################
def rpc(method, params=None):
    """ 
    Make an RPC call to the Bitcoin Daemon JSON-HTTP server.

    Arguments:
        method (string): RPC method
        params: RPC arguments

    Returns:
        object: RPC response result.
    """

    rpc_id = random.getrandbits(32)
    data = json.dumps({"id": rpc_id, "method": method, "params": params}).encode()
    auth = base64.encodebytes(f"{RPC_USER}:{RPC_PASS}".encode()).decode().strip()

    request = urllib.request.Request(RPC_URL, data, {"Authorization": "Basic {:s}".format(auth)})

    with urllib.request.urlopen(request) as f:
        response = json.loads(f.read())

    if response['id'] != rpc_id:
        raise ValueError("Invalid response id: got {}, expected {:u}".format(response['id'], rpc_id))
    elif response['error'] is not None:
        raise ValueError("RPC error: {:s}".format(json.dumps(response['error'])))

    return response['result']

################################################################################
# Bitcoin Daemon RPC Call Wrappers
################################################################################
def rpc_getblocktemplate():
    try:
        return rpc("getblocktemplate", [{"rules": ["segwit"]}])
    except ValueError:
        return {}

def rpc_submitblock(block_submission):
    return rpc("submitblock", [block_submission])

def rpc_getblockcount():
    return rpc( "getblockcount" )

def rpc_getblockhash(height):
    return rpc( "getblockhash", [height] )

def rpc_getblock( Hash ):
    return rpc( "getblock", [Hash, 2] )

def block_who( height ):
    bhash = rpc_getblockhash(height)
    block = rpc_getblock(bhash)
    wallet = block['tx'][0]['vout'][0]['scriptPubKey']['address']
    return block['mediantime']



def get_blocktime( ):
    TOP = rpc_getblockcount()
    data = []
    global BLOCK_SIZE
    for k, height in enumerate(range(TOP - BLOCK_SIZE, TOP )):
        BLOCK_TIME[ k ] = block_who(height)


################################################################################
# Representation Conversion Utility Functions
################################################################################
def int2lehex(value, width):
    """
    Convert an unsigned integer to a little endian ASCII hex string.
    Args:
        value (int): value
        width (int): byte width
    Returns:
        string: ASCII hex string
    """

    return value.to_bytes(width, byteorder='little').hex()

def int2varinthex(value):
    """
    Convert an unsigned integer to little endian varint ASCII hex string.
    Args:
        value (int): value
    Returns:
        string: ASCII hex string
    """

    if value < 0xfd:
        return int2lehex(value, 1)
    elif value <= 0xffff:
        return f"fd{int2lehex(value, 2)}"
    elif value <= 0xffffffff:
        return f"fe{int2lehex(value, 4)}"
    else:
        return f"ff{int2lehex(value, 8)}"

def bitcoinaddress2hash160(addr):
    """
    Convert a Base58 Bitcoin address to its Hash-160 ASCII hex string.
    Args:
        addr (string): Base58 Bitcoin address
    Returns:
        string: Hash-160 ASCII hex string
    """

    table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    addr = addr[::-1]
    hash160 = sum((58 ** i) * table.find(c) for i, c in enumerate(addr))
    # Convert number to 50-byte ASCII Hex string
    hash160 = "{:050x}".format(hash160)

    # Discard 1-byte network byte at beginning and 4-byte checksum at the end
    return hash160[2:50 - 8]

################################################################################
# Transaction Coinbase and Hashing Functions
################################################################################
def tx_encode_coinbase_height(height):
    """
    Encode the coinbase height, as per BIP 34:
    https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
    Arguments:
        height (int): height of the mined block
    Returns:
        string: encoded height as an ASCII hex string
    """

    width = (height.bit_length() + 7 )//8 

    return bytes([width]).hex() + int2lehex(height, width)

def make_P2PKH_from_public_key( publicKey ):
    from hashlib import sha256 as sha256

    address   = sha256( bytes.fromhex( publicKey) ).hexdigest()
    address   = hashlib.new('ripemd160', bytes.fromhex( address ) ).hexdigest()
    address = bytes.fromhex(f"00{address}")
    addressCS = sha256(                address     ).hexdigest()
    addressCS = sha256( bytes.fromhex( addressCS ) ).hexdigest()
    addressCS = addressCS[:8]
    address   = address.hex() + addressCS
    address   = base58.b58encode( bytes.fromhex(address))

    return address
    
def tx_make_coinbase(coinbase_script, pubkey_script, value, height, wit_commitment ):
    """
    Create a coinbase transaction.
    Arguments:
        coinbase_script (string): arbitrary script as an ASCII hex string
        address (string): Base58 Bitcoin address
        value (int): coinbase value
        height (int): mined block height
    Returns:
        string: coinbase transaction as an ASCII hex string
    """
    # See https://en.bitcoin.it/wiki/Transaction
    coinbase_script = tx_encode_coinbase_height(height) + coinbase_script

    tx = "" + "02000000"
    # in-counter
    tx += "01"
    # input[0] prev hash
    tx += "0" * 64
    # input[0] prev seqnum
    tx += "ffffffff"
    # input[0] script len
    tx += int2varinthex(len(coinbase_script) // 2)
    # input[0] script
    tx += coinbase_script
    # input[0] seqnum
    tx += "00000000"
    # out-counter
    #tx += "02" if default_witness_commitment else "01"
    tx += "02"
    # output[0] value
    tx += int2lehex(value, 8)
    # output[0] script len
    tx += int2varinthex(len(pubkey_script) // 2)
    # output[0] script
    tx += pubkey_script
    # witness commitment value
    tx += int2lehex(0, 8)
    # witness commitment script len
    tx += int2varinthex(len(wit_commitment) // 2)
    # witness commitment script
    tx += wit_commitment
    # lock-time
    tx += "00000000"

    return tx

def tx_compute_hash(tx):
    """
    Compute the SHA256 double hash of a transaction.
    Arguments:
        tx (string): transaction data as an ASCII hex string
    Return:
        string: transaction hash as an ASCII hex string
    """

    return hashlib.sha256(hashlib.sha256(bytes.fromhex(tx)).digest()).digest()[::-1].hex()

def tx_compute_merkle_root(tx_hashes):
    """
    Compute the Merkle Root of a list of transaction hashes.
    Arguments:
        tx_hashes (list): list of transaction hashes as ASCII hex strings
    Returns:
        string: merkle root as a big endian ASCII hex string
    """
    
    # Convert list of ASCII hex transaction hashes into bytes
    tx_hashes = [bytes.fromhex(tx_hash)[::-1] for tx_hash in tx_hashes]

    # Iteratively compute the merkle root hash
    while len(tx_hashes) > 1:
        # Duplicate last hash if the list is odd
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])

        tx_hashes_new = []

        for _ in range(len(tx_hashes) // 2):
            # Concatenate the next two
            concat = tx_hashes.pop(0) + tx_hashes.pop(0)
            # Hash them
            concat_hash = hashlib.sha256(hashlib.sha256(concat).digest()).digest()
            # Add them to our working list
            tx_hashes_new.append(concat_hash)

        tx_hashes = tx_hashes_new

    # Format the root in big endian ascii hex
    return tx_hashes[0][::-1].hex()

################################################################################
# Bitcoin Core Wrappers
################################################################################
class CBlock(ctypes.Structure):
    blocktemplate = {}
    _hash = "0"*32
    _fields_ = [("nP1",                 ctypes.c_uint64 * 16),
              ("hashPrevBlock",       ctypes.c_uint64 * 4 ),
              ("hashMerkleRoot",      ctypes.c_uint64 * 4 ),
              ("nNonce",   ctypes.c_uint64),
              ("wOffset",  ctypes.c_int64),
              ("nVersion", ctypes.c_uint32),
              ("nTime",    ctypes.c_uint32),
              ("nBits",    ctypes.c_uint16),
             ]

    def get_next_block_to_work_on(self):
        blocktemplate      = rpc_getblocktemplate()
        self.blocktemplate = blocktemplate 

        prevBlock = blocktemplate["previousblockhash"]
        prevBlock = hashToArray(prevBlock)

        merkleRoot = blocktemplate["merkleroothash"]
        merkleRoot = hashToArray(merkleRoot)

        self.nP1                 = (ctypes.c_uint64 * 16)(*([0]*16))
        self.hashPrevBlock       = (ctypes.c_uint64 * 4)(*prevBlock)
        self.hashMerkleRoot      = (ctypes.c_uint64 * 4)(*merkleRoot )
        self.nNonce   = 0
        self.nTime    = ctypes.c_uint32( blocktemplate["curtime"] )
        self.nVersion = ctypes.c_uint32( blocktemplate["version"] )
        self.nBits    = ctypes.c_uint16( blocktemplate["bits"] )
        self.wOffset  = 0
        
        return self
    
    def serialize_block_header(self):
        #Get the data
        nP1                 = hex(uint1024ToInt(self.nP1)                 )[2:].zfill(256)
        hashPrevBlock       = hex(uint256ToInt( self.hashPrevBlock)       )[2:].zfill(64)
        hashMerkleRoot      = hex(uint256ToInt( self.hashMerkleRoot)      )[2:].zfill(64)
        nNonce              = struct.pack("<Q", self.nNonce)
        wOffset             = struct.pack("<q", self.wOffset)
        nVersion            = struct.pack("<L", self.nVersion)
        nTime               = struct.pack("<L", self.nTime)
        nBits               = struct.pack("<H", self.nBits)
        
        #Reverse bytes of the hashes as little-Endian is needed for bitcoind
        nP1                 = bytes.fromhex(nP1)[::-1]
        hashPrevBlock       = bytes.fromhex(hashPrevBlock)[::-1] 
        hashMerkleRoot      = bytes.fromhex(hashMerkleRoot)[::-1]
                                                
        #Serialize in the right order
        CBlock1 = bytes()
        CBlock1 += nP1
        CBlock1 += hashPrevBlock
        CBlock1 += hashMerkleRoot
        CBlock1 += nNonce
        CBlock1 += wOffset
        CBlock1 += nVersion
        CBlock1 += nTime
        CBlock1 += nBits
        
        return CBlock1
    
    def __str__(self):
        
        #Get the data
        nP1                 = hex(uint1024ToInt(self.nP1)                 )[2:].zfill(256)
        hashPrevBlock       = hex(uint256ToInt( self.hashPrevBlock)       )[2:].zfill(64)
        hashMerkleRoot      = hex(uint256ToInt( self.hashMerkleRoot)      )[2:].zfill(64)
        nNonce              = struct.pack("<Q", self.nNonce).hex()
        wOffset             = struct.pack("<q", self.wOffset).hex()
        nVersion            = struct.pack("<L", self.nVersion).hex()
        nTime               = struct.pack("<L", self.nTime).hex()
        nBits               = struct.pack("<H", self.nBits).hex()

        #Reverse bytes of the hashes as little-Endian is needed for bitcoind
        nP1                 = bytes.fromhex(nP1)[::-1].hex()
        hashPrevBlock       = bytes.fromhex(hashPrevBlock)[::-1].hex()
        hashMerkleRoot      = bytes.fromhex(hashMerkleRoot)[::-1].hex()

        s  = "CBlock class: \n"
        s += f"                    nP1: {str(nP1)}" + "\n"
        s += f"          hashPrevBlock: {str(hashPrevBlock)}" + "\n"
        s += f"         hashMerkleRoot: {str(hashMerkleRoot)}" + "\n"
        s += f"                 nNonce: {str(nNonce)}" + "\n"
        s += f"                wOffset: {str(wOffset)}" + "\n"
        s += f"               nVersion: {str(nVersion)}" + "\n"
        s += f"                  nTime: {str(nTime)}" + "\n"
        s += f"                  nBits: {str(nBits)}" + "\n"

        return s
    
    def int2lehex(self, value, width):
        """
        Convert an unsigned integer to a little endian ASCII hex string.
        Args:
            value (int): value
            width (int): byte width
        Returns:
            string: ASCII hex string
        """

        return value.to_bytes(width, byteorder='little').hex()

    def int2varinthex(self, value):
        """
        Convert an unsigned integer to little endian varint ASCII hex string.
        Args:
            value (int): value
        Returns:
            string: ASCII hex string
        """

        if value < 0xfd:
            return self.int2lehex(value, 1)
        elif value <= 0xffff:
            return f"fd{self.int2lehex(value, 2)}"
        elif value <= 0xffffffff:
            return f"fe{self.int2lehex(value, 4)}"
        else:
            return f"ff{self.int2lehex(value, 8)}"

    def prepare_block_for_submission(self):
        #Get block header
        submission = self.serialize_block_header().hex()
        
        # Number of transactions as a varint
        submission += self.int2varinthex(len(self.blocktemplate['transactions']))
        
        # Concatenated transactions data
        for tx in self.blocktemplate['transactions']:
            submission += tx['data']
            
        return submission
    
    def rpc_submitblock(self):
        submission = self.prepare_block_for_submission()
        print( "Submission: ", submission)

        return rpc_submitblock(submission), submission
    
    def compute_raw_hash(self):
        """
        Compute the raw SHA256 double hash of a block header.
        Arguments:
            header (bytes): block header
        Returns:
            bytes: block hash
        """

        return hashlib.sha256(hashlib.sha256(self.serialize_block_header()).digest()).digest()[::-1]

##############################################################################################
##                                   Mining                                                 ##
##############################################################################################
    def mine(self, coinbase_message = "", scriptPubKey = None, hthreads = 1, cpu_thread_offset = 0):
        #Get parameters and candidate block
        block = None
        param = getParams()

        block = self.get_next_block_to_work_on()

        # Update the coinbase transaction with the new extra nonce
        coinbase_script = coinbase_message
        coinbase_tx = {
            'data': tx_make_coinbase(
                coinbase_script,
                scriptPubKey,
                block.blocktemplate['coinbasevalue'],
                block.blocktemplate['height'],
                block.blocktemplate.get("default_witness_commitment"),
            )
        }
        coinbase_tx['txid'] = tx_compute_hash(coinbase_tx['data'])

        #Add transaction to our block
        block.blocktemplate['transactions'].insert(0, coinbase_tx)

        # Recompute the merkle root
        block.blocktemplate['merkleroot'] = tx_compute_merkle_root([tx['txid'] for tx in block.blocktemplate['transactions']])
        merkleRoot = uint256()
        merkleRoot = (ctypes.c_uint64 * 4)(*hashToArray( block.blocktemplate["merkleroot"] ))
        block.hashMerkleRoot = merkleRoot

        #Iterate through a small set of random nonces
        #Probability of finding a good semiprime is extremely high
        Seeds = [st.randbelow( 1 << 64 ) for _ in range(10)] 

        #Siev filter out multiples of small primes
        global siev
        global siever
        global BLOCK_TIME
        T = [t - s for s, t in zip(BLOCK_TIME, BLOCK_TIME[1:])]
        avg = sum(T)/len(T)
        std = statistics.stdev(T)
        timeout = avg + 0*std

        print("Recent Block Solving Stats ( Last ", BLOCK_SIZE, " Blocks )")
        print("    Avg Solve Time:", avg , " Seconds. ", avg/60, " Mins." )
        print("Standard Deviation:", std , " Seconds. ", std/60, " Mins." )
        print("      Yafu Timeout:","avg + 0*std ~ ", timeout, "Seconds or ", timeout//60, "minutes", timeout%60, "Seconds."  )


        check_race = 0

        for nonce in Seeds:
            START = time()
            #print("Nonce: ", nonce, flush=True)
            #Set the nonce
            block.nNonce = nonce

            #Get the W
            W = gHash(block,param)
            W = uint1024ToInt(W)

            #Compute limit range around W
            #print("nBits: ", block.nBits )
            wInterval = 16 * block.nBits
            wMAX = int(W + wInterval)
            wMIN = int(W - wInterval) 

            #Candidates for admissible semiprime
            candidates = [ n for n in range( wMIN, wMAX) if gcd( n, 2*3*5*7*11*13*17*19*23*29*31 ) == 1  ]
            total_time = 0

            #Further sieving
            if siever:
                keys = sorted(siever.keys())
                keys = [ k for k in keys if k <= MAX_SIEVE_LEVEL] #Needs to be adjusted as difficulty level changes.


                for level in keys:
                    start1 = time()
                    lc = len(candidates)
                    candidates = [ n for n in candidates if gcd( n, siever[level]  ) == 1  ]
                    print("Level", level,"sieve time: ", "{:>0.6f}".format( time() - start1 ), " Seconds.    Candidates removed: ",  lc - len(candidates),  )
                    total_time += time() - start1

            elif siev:
                    candidates = [ n for n in candidates if gcd( n, siev  ) == 1  ] 

            print( "Total leveled sieving time:", total_time, " Seconds.")

            #Make sure the candidates have exactly nBits as required by this block
            candidates = [ k for k in candidates if k.bit_length() == block.nBits ] #This line requires python >= 3.10
            candidates = [ k for k in candidates if not isprime(k)                ]
            #Split candidates into  batches of 10 at a time
            shuffle(candidates)

            for idx, cand in enumerate( candidates):
                parse = subprocess.run( "pkill yafu", capture_output=True, shell=True )
                if rpc_getblockcount() >= block.blocktemplate["height"]:
                    print("Race was lost. Next block.")
                    print("Total Block Mining Runtime: ", time() - START, " Seconds." )
                    return None

                #Compute taskset
                taskset = ""
                for idx2 in range(hthreads):
                    taskset +=  str( hthreads*int(cpu_thread_offset) + idx2 ) 
                    if idx2 != (hthreads - 1):
                        taskset += "," 

                run_command = f"rm -rf nfs* siqs* tunerels.out rel* && taskset -c {taskset} ./yafu -one -plan custom  -pretest_ratio 0.31"
                run_command += (
                    f" -threads {str(hthreads)} -lathreads {str(hthreads)}"
                    + " -xover 120 -snfs_xover 115 -of pqFile.txt \"factor("
                    + str(cand)
                    + ")\" "
                )
                print(run_command)
                startf = time()
                parse = subprocess.run( run_command, capture_output=True, shell=True, timeout = timeout )
                for line in parse.stdout.decode('utf-8').split("\n"):
                    print(line)
                print()

                endf = time()
                parse = [ line for line in parse.stdout.decode('utf-8').split("\n") if "=" in line ]
                tmp = []
                flag=False

                for line in parse:
                    if "Total factoring" in line:
                        flag = True
                        continue

                    if flag:
                        tmp.append(line)
                parse = tmp

                #Check if there are any winners in this batch
                factorData = []
                print(
                    "Candidate: ",
                    f"{str(idx)}/{len(candidates)}",
                    "Factor count:  ",
                    len(parse) - 1,
                    "Factoring Time: ",
                    endf - startf,
                    flush=True,
                )
                print(parse)
                print()
                if len(parse) == 2:
                    exit(1)

                if len(parse) != 3:
                    continue

                p,q = int( parse[0].split("=")[1].strip()  ), int(parse[1].split("=")[1].strip())
                n   = p*q
                print("|p1|_2=",p.bit_length(),"|p2|_2=",q.bit_length(), "|n|_2",n.bit_length())
                if ( p.bit_length() ==  ( block.nBits//2 + (block.nBits&1)) ):
                    if ( q.bit_length() ==  ( block.nBits//2 + (block.nBits&1)) ):
                        if( (isprime(p) == isprime(q)) and (isprime(p) == True) ):
                            factorData.append( [n,p,q] )
                for solution in factorData:
                    solution.sort()
                    factors = [ solution[0], solution[1] ]
                    n = solution[2]

                    #Update values for the found block
                    block.nP1     = IntToUint1024(factors[0])
                    block.nNonce  = nonce
                    block.wOffset = n - W

                    #Compute the block hash
                    block_hash = block.compute_raw_hash()

                    #Update block
                    block._hash = block_hash

                    print(" Height: ", block.blocktemplate["height"] )   
                    print("      N: ", n)
                    print("      W: ", W)
                    print("      P: ", factors[0])
                    print("  Nonce: ", nonce)
                    print("wOffset: ", n - W)
                    print("Total Block Mining Runtime: ", time() - START, " Seconds." )

                    return block
		
def getParams():
    param = CParams()
    param.hashRounds = 1
    param.MillerRabinRounds = 50
    return param

gHash = ctypes.CDLL("./gHash.so").gHash
gHash.restype = uint1024

def mine():
    if ( len(sys.argv) != 4):
        print("Usage: python FACTOR.py <threads> <cpu_core_offset> \"ScriptPubKey\"")        
        sys.exit(1)

    if ( len(sys.argv[3]) != 44):
        print("ScriptPubKey must be 44 characters long. If this limit does not suit you, you know enough to fix it.")
        sys.exit(2)

    hthreads = int(sys.argv[1])
    scriptPubKey = sys.argv[3]
    cpu_thread_offset = int(sys.argv[2])
    load_levels()

    while True:
        get_blocktime()
        B = CBlock()
        START = time()

        if block := B.mine(
            scriptPubKey=scriptPubKey,
            hthreads=hthreads,
            cpu_thread_offset=cpu_thread_offset,
        ):
            if rpc_getblockcount() > block.blocktemplate["height"]:
                print("Race was lost. Next block.")
                print("Total Block Mining Runtime: ", time() - START, " Seconds." )
                continue
            else:
                block.rpc_submitblock()

if __name__ == "__main__":
    mine()
