// Copyright (c) 2012-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
static const std::string strSecret2 = "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3";
static const std::string strSecret1C = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw";
static const std::string strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";
static const std::string addr1 = "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ";
static const std::string addr2 = "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ";
static const std::string addr1C = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs";
static const std::string addr2C = "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs";

static const std::string strAddressBad = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF";


BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CKey key1  = DecodeSecret(strSecret1);
    BOOST_CHECK(key1.IsValid() && !key1.IsCompressed());
    CKey key2  = DecodeSecret(strSecret2);
    BOOST_CHECK(key2.IsValid() && !key2.IsCompressed());
    CKey key1C = DecodeSecret(strSecret1C);
    BOOST_CHECK(key1C.IsValid() && key1C.IsCompressed());
    CKey key2C = DecodeSecret(strSecret2C);
    BOOST_CHECK(key2C.IsValid() && key2C.IsCompressed());
    CKey bad_key = DecodeSecret(strAddressBad);
    BOOST_CHECK(!bad_key.IsValid());

    CPubKey pubkey1  = key1. GetPubKey();
    CPubKey pubkey2  = key2. GetPubKey();
    CPubKey pubkey1C = key1C.GetPubKey();
    CPubKey pubkey2C = key2C.GetPubKey();

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key1C.VerifyPubKey(pubkey1));
    BOOST_CHECK(key1C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1C));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(DecodeDestination(addr1)  == CTxDestination(PKHash(pubkey1)));
    BOOST_CHECK(DecodeDestination(addr2)  == CTxDestination(PKHash(pubkey2)));
    BOOST_CHECK(DecodeDestination(addr1C) == CTxDestination(PKHash(pubkey1C)));
    BOOST_CHECK(DecodeDestination(addr2C) == CTxDestination(PKHash(pubkey2C)));

    for (int n=0; n<16; n++)
    {
        std::string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg);

        // normal signatures

        std::vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2C));

        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        std::vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CPubKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.RecoverCompact (hashMsg, csign1));
        BOOST_CHECK(rkey2.RecoverCompact (hashMsg, csign2));
        BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));

        BOOST_CHECK(rkey1  == pubkey1);
        BOOST_CHECK(rkey2  == pubkey2);
        BOOST_CHECK(rkey1C == pubkey1C);
        BOOST_CHECK(rkey2C == pubkey2C);
    }

    // test deterministic signing

    std::vector<unsigned char> detsig, detsigc;
    std::string strMsg = "Very deterministic message";
    uint256 hashMsg = Hash(strMsg);
    BOOST_CHECK(key1.Sign(hashMsg, detsig));
    BOOST_CHECK(key1C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("304402205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d022014ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
    BOOST_CHECK(key2.Sign(hashMsg, detsig));
    BOOST_CHECK(key2C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3044022052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd5022061d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
    BOOST_CHECK(key1.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key1C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1c5dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
    BOOST_CHECK(detsigc == ParseHex("205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
    BOOST_CHECK(key2.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key2C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1c52d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd561d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
    BOOST_CHECK(detsigc == ParseHex("2052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd561d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
}

BOOST_AUTO_TEST_CASE(key_signature_tests)
{
    // When entropy is specified, we should see at least one high R signature within 20 signatures
    CKey key = DecodeSecret(strSecret1);
    std::string msg = "A message to be signed";
    uint256 msg_hash = Hash(msg);
    std::vector<unsigned char> sig;
    bool found = false;

    for (int i = 1; i <=20; ++i) {
        sig.clear();
        BOOST_CHECK(key.Sign(msg_hash, sig, false, i));
        found = sig[3] == 0x21 && sig[4] == 0x00;
        if (found) {
            break;
        }
    }
    BOOST_CHECK(found);

    // When entropy is not specified, we should always see low R signatures that are less than 70 bytes in 256 tries
    // We should see at least one signature that is less than 70 bytes.
    found = true;
    bool found_small = false;
    for (int i = 0; i < 256; ++i) {
        sig.clear();
        std::string msg = "A message to be signed" + ToString(i);
        msg_hash = Hash(msg);
        BOOST_CHECK(key.Sign(msg_hash, sig));
        found = sig[3] == 0x20;
        BOOST_CHECK(sig.size() <= 70);
        found_small |= sig.size() < 70;
    }
    BOOST_CHECK(found);
    BOOST_CHECK(found_small);
}

BOOST_AUTO_TEST_CASE(key_key_negation)
{
    // create a dummy hash for signature comparison
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write(MakeUCharSpan(str)).Write(rnd).Finalize(hash);

    // import the static test key
    CKey key = DecodeSecret(strSecret1C);

    // create a signature
    std::vector<unsigned char> vch_sig;
    std::vector<unsigned char> vch_sig_cmp;
    key.Sign(hash, vch_sig);

    // negate the key twice
    BOOST_CHECK(key.GetPubKey().data()[0] == 0x03);
    key.Negate();
    // after the first negation, the signature must be different
    key.Sign(hash, vch_sig_cmp);
    BOOST_CHECK(vch_sig_cmp != vch_sig);
    BOOST_CHECK(key.GetPubKey().data()[0] == 0x02);
    key.Negate();
    // after the second negation, we should have the original key and thus the
    // same signature
    key.Sign(hash, vch_sig_cmp);
    BOOST_CHECK(vch_sig_cmp == vch_sig);
    BOOST_CHECK(key.GetPubKey().data()[0] == 0x03);
}

static CPubKey UnserializePubkey(const std::vector<uint8_t>& data)
{
    CDataStream stream{SER_NETWORK, INIT_PROTO_VERSION};
    stream << data;
    CPubKey pubkey;
    stream >> pubkey;
    return pubkey;
}

static unsigned int GetLen(unsigned char chHeader)
{
    if (chHeader == 2 || chHeader == 3)
        return CPubKey::COMPRESSED_SIZE;
    if (chHeader == 4 || chHeader == 6 || chHeader == 7)
        return CPubKey::SIZE;
    return 0;
}

static void CmpSerializationPubkey(const CPubKey& pubkey)
{
    CDataStream stream{SER_NETWORK, INIT_PROTO_VERSION};
    stream << pubkey;
    CPubKey pubkey2;
    stream >> pubkey2;
    BOOST_CHECK(pubkey == pubkey2);
}

BOOST_AUTO_TEST_CASE(pubkey_unserialize)
{
    for (uint8_t i = 2; i <= 7; ++i) {
        CPubKey key = UnserializePubkey({0x02});
        BOOST_CHECK(!key.IsValid());
        CmpSerializationPubkey(key);
        key = UnserializePubkey(std::vector<uint8_t>(GetLen(i), i));
        CmpSerializationPubkey(key);
        if (i == 5) {
            BOOST_CHECK(!key.IsValid());
        } else {
            BOOST_CHECK(key.IsValid());
        }
    }
}

BOOST_AUTO_TEST_CASE(bip340_test_vectors)
{
    static const std::vector<std::pair<std::array<std::string, 3>, bool>> VECTORS = {
        {{"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9","0000000000000000000000000000000000000000000000000000000000000000","067E337AD551B2276EC705E43F0920926A9CE08AC68159F9D258C9BBA412781C9F059FCDF4824F13B3D7C1305316F956704BB3FEA2C26142E18ACD90A90C947E"},true},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","0E12B8C520948A776753A96F21ABD7FDC2D7D0C0DDC90851BE17B04E75EF86A47EF0DA46C4DC4D0D1BCB8668C2CE16C54C7C23A6716EDE303AF86774917CF928"},true},
        {{"DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8","7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C","FC012F9FB8FE00A358F51EF93DCE0DC0C895F6E9A87C6C4905BC820B0C3677616B8737D14E703AF8E16E22E5B8F26227D41E5128F82D86F747244CC289C74D1D"},true},
        {{"25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF","FC132D4E426DFF535AEC0FA7083AC5118BC1D5FFFD848ABD8290C23F271CA0DD11AEDCEA3F55DA9BD677FE29C9DDA0CF878BCE43FDE0E313D69D1AF7A5AE8369"},true},
        {{"D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9","4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703","00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C630EC50E5363E227ACAC6F542CE1C0B186657E0E0D1A6FFE283A33438DE4738419"},true},
        {{"EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","7036D6BFE1837AE919631039A2CF652A295DFAC9A8BBB0806014B2F48DD7C807941607B563ABBA414287F374A332BA3636DE009EE1EF551A17796B72B68B8A24"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F995A579DA959FA739FCE39E8BD16FECB5CDCF97060B2C73CDE60E87ABCA1AA5D9"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","F8704654F4687B7365ED32E796DE92761390A3BCC495179BFE073817B7ED32824E76B987F7C1F9A751EF5C343F7645D3CFFC7D570B9A7192EBF1898E1344E3BF"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","7036D6BFE1837AE919631039A2CF652A295DFAC9A8BBB0806014B2F48DD7C8076BE9F84A9C5445BEBD780C8B5CCD45C883D0DC47CD594B21A858F31A19AAB71D"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","00000000000000000000000000000000000000000000000000000000000000009915EE59F07F9DBBAEDC31BFCC9B34AD49DE669CD24773BCED77DDA36D073EC8"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","0000000000000000000000000000000000000000000000000000000000000001C7EC918B2B9CF34071BB54BED7EB4BB6BAB148E9A7E36E6B228F95DFA08B43EC"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D941607B563ABBA414287F374A332BA3636DE009EE1EF551A17796B72B68B8A24"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F941607B563ABBA414287F374A332BA3636DE009EE1EF551A17796B72B68B8A24"},false},
        {{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","7036D6BFE1837AE919631039A2CF652A295DFAC9A8BBB0806014B2F48DD7C807FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"},false},
        {{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","7036D6BFE1837AE919631039A2CF652A295DFAC9A8BBB0806014B2F48DD7C807941607B563ABBA414287F374A332BA3636DE009EE1EF551A17796B72B68B8A24"},false}
    };

    for (const auto& test : VECTORS) {
        auto pubkey = XOnlyPubKey(uint256(ParseHex(test.first[0])));
        auto msg = uint256(ParseHex(test.first[1]));
        auto sig = ParseHex(test.first[2]);
        BOOST_CHECK_EQUAL(pubkey.VerifySchnorr(msg, sig), test.second);
    }
}

BOOST_AUTO_TEST_SUITE_END()
