package com.google.bitcoin.core;

import java.math.BigInteger;
import java.util.Date;
import java.util.Map;
import java.util.Vector;

public class CoinDefinition {


    public static final String coinName = "Vertcoin";
    public static final String coinTicker = "VTC";
    public static final String coinURIScheme = "vertcoin";
    public static final String cryptsyMarketId = "151";
    public static final String cryptsyMarketCurrency = "BTC";


    public static final String BLOCKEXPLORER_BASE_URL_PROD = "http://explorer.vertcoin.org/";
    public static final String BLOCKEXPLORER_BASE_URL_TEST = "http://explorer.vertcoin.org/";

    public static final String DONATION_ADDRESS = "VeHzYt4SzTZN5Qnnd4f5zW6MDHPb9mtCtj";  // donation VTC address

    enum CoinHash {
        SHA256,
        scrypt
    };
    public static final CoinHash coinHash = CoinHash.scrypt;
    //Original Values
    public static final int TARGET_TIMESPAN_0 = (int)(3.5 * 24 * 60 * 60);  // 3.5 days per difficulty cycle, on average.
    public static final int TARGET_SPACING_0 = (int)(2.5 * 60);  // 2.5 minutes per block.
    public static final int INTERVAL_0 = TARGET_TIMESPAN_0 / TARGET_SPACING_0;  //2016 blocks

    public static final int TARGET_TIMESPAN = (int)(3.5 * 24 * 60 * 60);  // 22.5 minutes per difficulty cycle, on average.
    public static final int TARGET_SPACING = (int)(150);  // 2.5 minutes per block.
    public static final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;  //9 blocks
    
    public static final int TARGET_TIMESPAN_3 = (int)(3.5 * 24 * 60 * 60);  // 3.5 days per difficulty cycle, on average.
    public static final int TARGET_SPACING_3 = (int)(2.5 * 60);  // 2.5 minutes per block.
    public static final int INTERVAL_3 = TARGET_TIMESPAN_0 / TARGET_SPACING_0;  //2016 blocks

    static final long nTargetSpacing = 150; // 2.5 minutes
    static final long nOriginalInterval = 2016;
    static final long nFilteredInterval =    2016;
    static final long nOriginalTargetTimespan = nOriginalInterval * nTargetSpacing; // 3.5 days
    static final long nFilteredTargetTimespan = nFilteredInterval * nTargetSpacing; // 22.5 minutes

    public static int DIFF_FILTER_THRESHOLD_TESTNET = 26754;
    public static int DIFF_FILTER_THRESHOLD = 26754;

    public static int nDifficultySwitchHeight = 26754;
    //public static int nDifficultySwitchHeightTwo = 62773;
    public static int nDifficultySwitchHeightTwo = 9999999;

    public static final int getInterval(int height, boolean testNet) {
        if(height < nDifficultySwitchHeight)
            return (int)nOriginalInterval;    //1080
        else if(height < nDifficultySwitchHeightTwo)
            return (int)nFilteredInterval;      //108
        else return INTERVAL_3;
    }
    public static final int getIntervalForCheckpoints(int height, boolean testNet) {
        if(height < 8050)
            return (int)nOriginalInterval;    //2016
        else if(height < nDifficultySwitchHeightTwo)
            return (int)nOriginalInterval;      //2016
        else return (int)nOriginalInterval / 4; //504
    }
    public static final int getTargetTimespan(int height, boolean testNet) {
        if(height < nDifficultySwitchHeight)
            return TARGET_TIMESPAN_0;  //3.5 days
        else
            return TARGET_TIMESPAN;    //72 min
    }
    public static int getMaxTimeSpan(int value, int height, boolean testNet)
    {
        if(height < nDifficultySwitchHeight)
            return value * 4;
        else
            return value * 1;   // not used
    }
    public static int getMinTimeSpan(int value, int height, boolean testNet)
    {
        if(height < nDifficultySwitchHeight)
            return value / 4;
        else
            return value * 1;    //not used
    }
    public static int spendableCoinbaseDepth = 100; //main.h: static const int COINBASE_MATURITY
    public static final int MAX_MONEY = 84000000;                 //main.h:  MAX_MONEY
    public static final String MAX_MONEY_STRING = "84000000";     //main.h:  MAX_MONEY

    public static final BigInteger DEFAULT_MIN_TX_FEE = BigInteger.valueOf(100000);   // MIN_TX_FEE
    public static final BigInteger DUST_LIMIT = Utils.CENT; //main.h CTransaction::GetMinFee        0.01 coins

    public static final int PROTOCOL_VERSION = 70002;          //version.h PROTOCOL_VERSION
    public static final int MIN_PROTOCOL_VERSION = 209;        //version.h MIN_PROTO_VERSION

    public static final boolean supportsBloomFiltering = true; //Requires PROTOCOL_VERSION 70000 in the client

    public static final int Port    = 5889;       //protocol.h GetDefaultPort(testnet=false)
    public static final int TestPort = 15889;     //protocol.h GetDefaultPort(testnet=true)

    //
    //  Production
    //
    public static final int AddressHeader = 71;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS
    public static final int p2shHeader = 5;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS
    public static final int dumpedPrivateKeyHeader = 128;   //common to all coins
    public static final long PacketMagic = 0xfabfb5da;      //0xfb, 0xc0, 0xb6, 0xdb

    //Genesis Block Information from main.cpp: LoadBlockIndex
    static public long genesisBlockDifficultyTarget = (0x1e0ffff0L);         //main.cpp: LoadBlockIndex
    static public long genesisBlockTime = 1389311371L;                       //main.cpp: LoadBlockIndex
    static public long genesisBlockNonce = (5749262);                         //main.cpp: LoadBlockIndex
    static public String genesisHash = "4d96a915f49d40b1e5c2844d1ee2dccb90013a990ccea12c492d22110489f0c4"; //main.cpp: hashGenesisBlock
    static public int genesisBlockValue = 50;                                                              //main.cpp: LoadBlockIndex
    //taken from the raw data of the block explorer
    static public String genesisXInBytes = "0002e7034130312f30392f32303134204765726d616e7920746f2048656c7020696e20446973706f73616c206f662053797269616e204368656d6963616c20576561706f6e73";   //"Boston Herald - 21/May/2013 - IRS Official to Take Fifth to Avoid Testifying"
    static public String genessiXOutBytes = "";

    //net.cpp strDNSSeed
    static public String[] dnsSeeds = new String[] {
		"ams1.vertcoin.org",
		"ams2.vertcoin.org",
		"ams3.vertcoin.org",
		"ams4.vertcoin.org",
		"ny.vertcoin.org",
		"la.vertcoin.org",
		"eu.vertcoin.org",
		"nl1.vertcoin.org",
		"nl2.vertcoin.org",
		"se1.vertcoin.org"
    };

    //
    // TestNet - vertcoin - not tested / incomplete
    //
    public static final boolean supportsTestNet = false;
    public static final int testnetAddressHeader = 74;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS_TEST
    public static final int testnetp2shHeader = 202;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS_TEST
    public static final long testnetPacketMagic = 0xfdf0f4fe;      //0xfc, 0xc1, 0xb7, 0xdc
    public static final String testnetGenesisHash = "5e039e1ca1dbf128973bf6cff98169e40a1b194c3b91463ab74956f413b2f9c8";
    static public long testnetGenesisBlockDifficultyTarget = (0x1e0ffff0L);         //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockTime = 1369198853L;                       //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockNonce = (386245382);                         //main.cpp: LoadBlockIndex





    //main.cpp GetBlockValue(height, fee)
    public static BigInteger GetBlockReward(int height)
    {
            return Utils.toNanoCoins(0, 50).shiftRight(height / subsidyDecreaseBlockCount);
    }
    
 

    public static int subsidyDecreaseBlockCount = 840000;     //main.cpp GetBlockValue(height, fee)

    public static BigInteger proofOfWorkLimit = Utils.decodeCompactBits(0x1e0fffffL);  //main.cpp bnProofOfWorkLimit (~uint256(0) >> 20); // digitalcoin: starting difficulty is 1 / 2^12

    static public String[] testnetDnsSeeds = new String[] {
          "not supported"
    };
    //from main.h: CAlert::CheckSignature
    public static final String SATOSHI_KEY = "048AB39D2A9D43577BCD1A92708266267E4B5E5D87C20F5B68C94E0A79E8CA809B4A5A4E428F78A13821AB3FEBBCFF72A3054039D1DBEA3245A35C458BBF01EB34";
    public static final String TESTNET_SATOSHI_KEY = "04826AC11FCF383A1E0F21E2A76807D082FF4E7F139111A7768E4F5A35A5653A2D44A8E19BC8B55AEDC9F9238D424BDC5EBD6D2BAF9CB3D30CEDEA35C47C8350A0";

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = "org.vertcoin.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = "org.vertcoin.test";
    /** Unit test network. */
    public static final String ID_UNITTESTNET = "com.google.vertcoin.unittest";

    //checkpoints.cpp Checkpoints::mapCheckpoints
    public static void initCheckpoints(Map<Integer, Sha256Hash> checkpoints)
    {
    checkpoints.put(0,     new Sha256Hash("4d96a915f49d40b1e5c2844d1ee2dccb90013a990ccea12c492d22110489f0c4")); 
	checkpoints.put(4032,  new Sha256Hash("985c4aa52b56f8dc349089d1141c0baac24b22aec871d44282b8114c8a0ee989")); 
	checkpoints.put(8064,  new Sha256Hash("21156fe43c92249485f234c05b9c654398c57e1e7da2616b790ee275a9e79daa")); 
	checkpoints.put(12096, new Sha256Hash("591ddffbc198a456d5ec4bacba7fc96a248785bc0ba8bf9b95865b47f1b018ca")); 
	checkpoints.put(16128, new Sha256Hash("f708aeb9d32d1cfb99716acbc786d53783a8b4d1402b7291140421d9b0650b02")); 
	checkpoints.put(20160, new Sha256Hash("3da5330dc1abcce95f918663476e94c9643a3936661cb039a7f585054659bb14")); 
	checkpoints.put(24192, new Sha256Hash("69622465ae61faae7919b462c25219930abab18704e87fea891e895d1f7e9bc6")); 
	checkpoints.put(28224, new Sha256Hash("d9ad56894ea985ebf559141a4d533d086ce15c4c7f1c7a6dd42e0f1d10385697"));
	checkpoints.put(32256, new Sha256Hash("2b22783e6eb5b02fdc2669931c60156be4eb1f1d9a8ffed4a69a5f8aa50f9131"));
	checkpoints.put(36288, new Sha256Hash("1dcbbcd6f7e30b588e0ef5a80642eded10b65feebca5e1006658285b72bbf441"));
	checkpoints.put(40320, new Sha256Hash("cf361ecd18812f7b2da3c54cad4f9ab17afb8d2f744405104e9f2f773abd0662"));
	checkpoints.put(44352, new Sha256Hash("44e5b428f5c496dbb196878d20ea10cc2b8082507934f91ab8a27426e067f221"));
	checkpoints.put(48384, new Sha256Hash("8442a9f8b120d9a1769beac12c6d1934797c5c4e55754e55658daaa550338c69"));
	checkpoints.put(52416, new Sha256Hash("e2cc3907563bea6a9d6ac8e0411307e4439fe3ed7a1fee113d107e3891f4b1e6"));
	checkpoints.put(56448, new Sha256Hash("6e7756953eff6995e17c96ab0c3ad048fe96b5e7b7960eff9c4aea26e61af73a"));
    }


}
