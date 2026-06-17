package com.apicatalog.crypto;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.apicatalog.base.Base16;
import com.apicatalog.crypto.jca.JcaSignatureVerifier;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.KeyCodec;

class TestVerifier {

    @Test
    void testP256_1() throws Throwable {

        var pk = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
        var signature = "1cb4290918ffb04a55ff7ae1e55e316a9990fda8eec67325eac7fcbf2ddf9dd2b06716a657e72b284c9604df3a172ecbf06a1a475b49ac807b1d9162df855636";
        var data = "3a8a522f689025727fb9d1f0fa99a618da023e8494ac74f51015d009d35abc2e517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017";

        var verifier = JcaSignatureVerifier.getInstance("P-256");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.P256_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Base16.decode(signature));

        assertTrue(verified);

    }

    @Test
    void testP256_2() throws Throwable {

        var pk = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
        var data = "3a8a522f689025727fb9d1f0fa99a618da023e8494ac74f51015d009d35abc2e03f59e5b04ab575b1172cb684f22eede72f0e9033e0b5c67d0e2506768d6ce11";        
        var signature = "c6798ff29f725dfd39aa4daf60fbb423cf9baf4e157f6b49f112c201015c6e730dc877154e65cf467f8ee2b61ec86d98ed78334b1cc9f3dba2e1745f37205e92";

        var verifier = JcaSignatureVerifier.getInstance("P-256");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.P256_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Base16.decode(signature));

        assertTrue(verified);

    }

    @Test
    void testP256_3() throws Throwable {

        var pk = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
        var data = "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec2559b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19";        
        var signature = "f15c3b599eb9b3cad05df9d8e8b39a70a86375833b53743c764ac0a88c4457d60707fd7d073e03d906130631d87803f80a9824dc9939632ba92d418181be9d16";

        var verifier = JcaSignatureVerifier.getInstance("P-256");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.P256_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Base16.decode(signature));

        assertTrue(verified);
    }

    @Test
    void testP384_1() throws Throwable {

        var pk = "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ";
        var data = "e32805a26492eac777aa7a138f6d8da3c74e0c7be7b296dcaccf97420c3b92eaad7be6449ca565e165031567f5c7cbc11033878f36ffb458c6495fec9c8814dad5215aad131041e6667db28fef6ea718d0de0eb4546bf527746ad2bc908a4320";
        var signature = "a5999d1154a3fb5db8805fa762c8c41c1b7f40a231a5d42460d36245349771835f43fe0005295d2061be1789589c1f6385312f0e2e36709c310c77e8289587b79b29ecf7aad14ef61a1393cc2e1f93a7a354bd76bab47d558df060c6ae218975";

        var verifier = JcaSignatureVerifier.getInstance("P-384");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.P384_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Base16.decode(signature));

        assertTrue(verified);

    }

    @Test
    void testP384_2() throws Throwable {

        var pk = "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ";
        var data = "83e5057817abb0c6872eafeaba1a9e53893c58eeb7414fb6d8aa3fa8c7917f7ad4792890b257c598baa17f4fbe6d183c3e0be671cc1881035d463158c80921973dab3534d4f8dfacf4ff2725a4115eb718e49d66de0e90e7365cd6062abf2259";
        var signature = "8b7462ce62db0c8ff19878c4b3561c49eb71b4a743086b6d5b0eda70ecf0afc5a03fd88eb207d66b262ed87fd200a4e8e62716e0b329c032b67726b4b0fc737a44c1cefdba2fdccb3ece74cc5845aaa93374455a726f6ee4f5f30da9427f608a";

        var verifier = JcaSignatureVerifier.getInstance("P-384");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.P384_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Base16.decode(signature));

        assertTrue(verified);

    }
    
    @Test
    void testP384_3() throws Throwable {

        var pk = "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ";
        var data = "83e5057817abb0c6872eafeaba1a9e53893c58eeb7414fb6d8aa3fa8c7917f7ad4792890b257c598baa17f4fbe6d183c3e0be671cc1881035d463158c80921973dab3534d4f8dfacf4ff2725a4115eb718e49d66de0e90e7365cd6062abf2259";
        var signature = "zq3EuTeLiGurmB2JR5oL8oWEsT7u2tba4HT1oZbiMYWc5qzsoW2kLYcBcF4HM5vCpJyTkceULKrVXuJQkXeN5seL4uXrFNFRMm53GWy1Yrto8rTWxZi9DkNeWP7yUPs7ELAm";

        var verifier = JcaSignatureVerifier.getInstance("P-384");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.P384_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Multibase.BASE_58_BTC.decode(signature));

        assertTrue(verified);

    }

    @Test
    void testEd25519_1() throws Throwable {

        var pk = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
        var data = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017";
        var signature = "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme";

        var verifier = JcaSignatureVerifier.getInstance("Ed25519");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.ED25519_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Multibase.BASE_58_BTC.decode(signature));

        assertTrue(verified);
    }

    @Test
    void testEd25519_2() throws Throwable {

        var pk = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
        var data = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b003f59e5b04ab575b1172cb684f22eede72f0e9033e0b5c67d0e2506768d6ce11";
        var signature = "zeuuS9pi2ZR8Q41bFFJKS9weSWkwa7pRcxHTHzxjDEHtVSZp3D9Rm3JdzT82EQpmXMb9wvfFJLuDPeSXZaRX1q1c";

        var verifier = JcaSignatureVerifier.getInstance("Ed25519");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.ED25519_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Multibase.BASE_58_BTC.decode(signature));

        assertTrue(verified);

    }

    @Test
    void testEd25519_3() throws Throwable {

        var pk = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
        var data = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19";
        var signature = "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX";

        var verifier = JcaSignatureVerifier.getInstance("Ed25519");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.ED25519_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Multibase.BASE_58_BTC.decode(signature));

        assertTrue(verified);

    }

    @Test
    void testEd25519_4() throws Throwable {

        var pk = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
        var data = "04e14bcf5727cba0c0aa04a04d22a56fef915d5f8f7756bb92ae67cb1d0c4847517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017";
        var signature = "z57Mm1vboMtZiCyJ4aReZsv8co4Re64Y8GEjL1ZARzMbXZgkARFLqFs1P345NpPGG2hgCrS4nNdvJhpwnrNyG3kEF";

        var verifier = JcaSignatureVerifier.getInstance("Ed25519");
        assertNotNull(verifier);

        var verified = verifier.verify(
                KeyCodec.ED25519_PUBLIC_KEY.decode(
                        Multibase.BASE_58_BTC.decode(pk)),
                Base16.decode(data),
                Multibase.BASE_58_BTC.decode(signature));

        assertTrue(verified);

    }
}
