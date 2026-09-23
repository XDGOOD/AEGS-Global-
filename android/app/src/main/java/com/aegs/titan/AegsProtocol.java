package com.aegs.titan;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AEGS v6 Titan Protocol Engine for Android
 * 100% Pure Java implementation of AEGS cryptographic primitives and wire formatting.
 *
 * Implements:
 * - RFC 7748 Curve25519 / X25519 Key Exchange
 * - PBKDF2-HMAC-SHA256 (200,000 iterations) MasterKey derivation
 * - KeyID derivation (first 8 bytes of SHA-256(Token))
 * - HKDF-SHA256 key expansion (RFC 5869: aegs-c2s, aegs-s2c, aegs-cfg, aegs-v2-header-mask)
 * - ChaCha20 Dynamic Header Masking (VER_MAGIC = AG2\x01)
 * - ChaCha20-Poly1305 AEAD Data Encryption with Outer Header AAD Binding (RFC 8439)
 * - Anti-ML Bimodal Semantic Padding (~256B ACKs, ~1350B Full MTU)
 * - Anti-Timing Active Chaffing (bit 0x80 flag)
 * - Handshake packet builder (HANDSHAKE_INIT 72B) & parser (HANDSHAKE_RESP 80B)
 */
public final class AegsProtocol {

    public static final byte[] VER_MAGIC = new byte[]{'A', 'G', '2', 0x01};
    public static final byte TYPE_HANDSHAKE_INIT = 0x01;
    public static final byte TYPE_HANDSHAKE_RESP = 0x02;
    public static final byte TYPE_RESUMPTION     = 0x04;
    public static final byte CHAFF_FLAG          = (byte) 0x80;

    private static final SecureRandom CSPRNG = new SecureRandom();
    private static final BigInteger P1305 = BigInteger.valueOf(2).pow(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger MOD128 = BigInteger.valueOf(2).pow(128);

    public static class HandshakeResult {
        public long sessionId;
        public String assignedIp;
        public int mtu;
        public byte[] sendKey; // C2S_Key
        public byte[] recvKey; // S2C_Key
        public byte[] maskKey;
        public byte[] keyId;
    }

    // =========================================================================
    // 1. Key Derivation (PBKDF2 & HKDF)
    // =========================================================================

    public static byte[] deriveKeyId(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(StandardCharsets.UTF_8));
            byte[] keyId = new byte[8];
            System.arraycopy(hash, 0, keyId, 0, 8);
            return keyId;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static byte[] deriveMasterKey(String token, byte[] keyId) {
        // C++ & Python servers use 16-character hex representation of KeyID as salt
        byte[] salt = (keyId != null && keyId.length == 8)
                ? bytesToHex(keyId).getBytes(StandardCharsets.UTF_8)
                : keyId;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(token.toCharArray(), salt, 200000, 256);
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            // Pure Java fallback: guaranteed execution on any Android / JVM runtime
            return manualPbkdf2HmacSha256(token.getBytes(StandardCharsets.UTF_8), salt, 200000, 32);
        }
    }

    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] t = new byte[0];
            byte[] okm = new byte[length];
            int offset = 0;
            byte counter = 1;

            while (offset < length) {
                mac.update(t);
                mac.update(info);
                mac.update(counter);
                t = mac.doFinal();
                int toCopy = Math.min(t.length, length - offset);
                System.arraycopy(t, 0, okm, offset, toCopy);
                offset += toCopy;
                counter++;
            }
            return okm;
        } catch (Exception e) {
            throw new RuntimeException("HKDF-Expand error", e);
        }
    }

    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] actualSalt = (salt != null && salt.length > 0) ? salt : new byte[32];
            mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (Exception e) {
            throw new RuntimeException("HKDF-Extract error", e);
        }
    }

    public static byte[] hkdf(byte[] ikm, byte[] salt, String infoStr, int length) {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, infoStr.getBytes(StandardCharsets.UTF_8), length);
    }

    // =========================================================================
    // 2. Pure RFC 7748 X25519 Implementation
    // =========================================================================

    public static class X25519KeyPair {
        public final byte[] privateKey;
        public final byte[] publicKey;

        public X25519KeyPair(byte[] priv, byte[] pub) {
            this.privateKey = priv;
            this.publicKey = pub;
        }
    }

    public static X25519KeyPair generateX25519KeyPair() {
        byte[] privateKey = new byte[32];
        CSPRNG.nextBytes(privateKey);
        privateKey[0] &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;
        byte[] publicKey = x25519ScalarMult(privateKey, BASE_POINT);
        return new X25519KeyPair(privateKey, publicKey);
    }

    private static final byte[] BASE_POINT = new byte[]{
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    private static final BigInteger P25519 = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger A24 = BigInteger.valueOf(121665);

    public static byte[] x25519ScalarMult(byte[] scalar, byte[] uCoordinate) {
        byte[] clampedScalar = Arrays.copyOf(scalar, 32);
        clampedScalar[0] &= 248;
        clampedScalar[31] &= 127;
        clampedScalar[31] |= 64;

        BigInteger u = decodeUCoordinate(uCoordinate);
        BigInteger x1 = u;
        BigInteger x2 = BigInteger.ONE;
        BigInteger z2 = BigInteger.ZERO;
        BigInteger x3 = u;
        BigInteger z3 = BigInteger.ONE;
        int swap = 0;

        for (int t = 254; t >= 0; --t) {
            int k_t = (clampedScalar[t / 8] >>> (t % 8)) & 1;
            swap ^= k_t;
            if (swap == 1) {
                BigInteger tempX = x2; x2 = x3; x3 = tempX;
                BigInteger tempZ = z2; z2 = z3; z3 = tempZ;
            }
            swap = k_t;

            BigInteger A = x2.add(z2).mod(P25519);
            BigInteger AA = A.multiply(A).mod(P25519);
            BigInteger B = x2.subtract(z2).mod(P25519);
            BigInteger BB = B.multiply(B).mod(P25519);
            BigInteger E = AA.subtract(BB).mod(P25519);
            BigInteger C = x3.add(z3).mod(P25519);
            BigInteger D = x3.subtract(z3).mod(P25519);
            BigInteger DA = D.multiply(A).mod(P25519);
            BigInteger CB = C.multiply(B).mod(P25519);

            x3 = DA.add(CB).mod(P25519).pow(2).mod(P25519);
            z3 = x1.multiply(DA.subtract(CB).mod(P25519).pow(2)).mod(P25519);
            x2 = AA.multiply(BB).mod(P25519);
            z2 = E.multiply(AA.add(A24.multiply(E))).mod(P25519);
        }

        if (swap == 1) {
            BigInteger tempX = x2; x2 = x3; x3 = tempX;
            BigInteger tempZ = z2; z2 = z3; z3 = tempZ;
        }

        BigInteger result = x2.multiply(z2.modInverse(P25519)).mod(P25519);
        return encodeUCoordinate(result);
    }

    private static BigInteger decodeUCoordinate(byte[] u) {
        byte[] copy = Arrays.copyOf(u, 32);
        copy[31] &= 0x7F;
        byte[] reversed = new byte[33];
        for (int i = 0; i < 32; i++) {
            reversed[32 - i] = copy[i];
        }
        return new BigInteger(reversed);
    }

    private static byte[] encodeUCoordinate(BigInteger val) {
        byte[] bytes = val.toByteArray();
        byte[] res = new byte[32];
        int len = bytes.length;
        for (int i = 0; i < 32; i++) {
            int srcIdx = len - 1 - i;
            if (srcIdx >= 0) {
                res[i] = bytes[srcIdx];
            }
        }
        return res;
    }

    // =========================================================================
    // 3. ChaCha20 & ChaCha20-Poly1305 AEAD Primitives
    // =========================================================================

    public static byte[] maskUnmaskHeader(byte[] header16, byte[] maskKey, byte[] iv12) {
        byte[] out = new byte[16];
        System.arraycopy(header16, 0, out, 0, 16);
        // ChaCha20 block with counter = 0, nonce = iv12
        int[] state = chacha20Init(maskKey, 0, iv12);
        byte[] keyStream = chacha20Block(state);
        for (int i = 0; i < 16; i++) {
            out[i] ^= keyStream[i];
        }
        return out;
    }

    public static byte[] encryptAead(byte[] key, byte[] nonce12, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce12));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            // Pure Java fallback: 100% bit-for-bit match with RFC 8439
            return pureJavaChaCha20Poly1305Encrypt(key, nonce12, plaintext, aad);
        }
    }

    public static byte[] decryptAead(byte[] key, byte[] nonce12, byte[] ciphertextWithTag, byte[] aad) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce12));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertextWithTag);
        } catch (Exception e) {
            // Pure Java fallback: 100% bit-for-bit match with RFC 8439
            return pureJavaChaCha20Poly1305Decrypt(key, nonce12, ciphertextWithTag, aad);
        }
    }

    // Pure Java RFC 8439 ChaCha20-Poly1305 AEAD
    public static byte[] pureJavaChaCha20Poly1305Encrypt(byte[] key, byte[] nonce12, byte[] pt, byte[] aad) {
        int[] s0 = chacha20Init(key, 0, nonce12);
        byte[] b0 = chacha20Block(s0);
        byte[] polyKey = Arrays.copyOf(b0, 32);

        byte[] ct = chacha20Stream(key, 1, nonce12, pt, 0, pt.length);
        byte[] tag = computePoly1305(polyKey, aad, ct);

        byte[] out = new byte[ct.length + 16];
        System.arraycopy(ct, 0, out, 0, ct.length);
        System.arraycopy(tag, 0, out, ct.length, 16);
        return out;
    }

    public static byte[] pureJavaChaCha20Poly1305Decrypt(byte[] key, byte[] nonce12, byte[] ctWithTag, byte[] aad) throws Exception {
        if (ctWithTag.length < 16) throw new IllegalArgumentException("Ciphertext too short for AEAD tag");
        int ctLen = ctWithTag.length - 16;
        byte[] ct = Arrays.copyOf(ctWithTag, ctLen);
        byte[] tag = Arrays.copyOfRange(ctWithTag, ctLen, ctWithTag.length);

        int[] s0 = chacha20Init(key, 0, nonce12);
        byte[] b0 = chacha20Block(s0);
        byte[] polyKey = Arrays.copyOf(b0, 32);

        byte[] expectedTag = computePoly1305(polyKey, aad, ct);
        if (!MessageDigest.isEqual(tag, expectedTag)) {
            throw new RuntimeException("ChaCha20-Poly1305 AAD authentication tag mismatch");
        }

        return chacha20Stream(key, 1, nonce12, ct, 0, ctLen);
    }

    private static byte[] chacha20Stream(byte[] key, int initialCounter, byte[] nonce12, byte[] in, int inOffset, int len) {
        byte[] out = new byte[len];
        int counter = initialCounter;
        int offset = 0;
        while (offset < len) {
            int[] s = chacha20Init(key, counter, nonce12);
            byte[] block = chacha20Block(s);
            int toXor = Math.min(64, len - offset);
            for (int i = 0; i < toXor; i++) {
                out[offset + i] = (byte) (in[inOffset + offset + i] ^ block[i]);
            }
            offset += toXor;
            counter++;
        }
        return out;
    }

    private static byte[] computePoly1305(byte[] key32, byte[] aad, byte[] ct) {
        byte[] rBytes = Arrays.copyOfRange(key32, 0, 16);
        rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
        rBytes[4] &= (byte) 252; rBytes[8] &= (byte) 252; rBytes[12] &= (byte) 252;

        BigInteger r = leToBigInt(rBytes);
        BigInteger s = leToBigInt(Arrays.copyOfRange(key32, 16, 32));
        BigInteger a = BigInteger.ZERO;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            if (aad != null && aad.length > 0) {
                baos.write(aad);
                int padAad = (16 - (aad.length % 16)) % 16;
                if (padAad > 0) baos.write(new byte[padAad]);
            }
            if (ct != null && ct.length > 0) {
                baos.write(ct);
                int padCt = (16 - (ct.length % 16)) % 16;
                if (padCt > 0) baos.write(new byte[padCt]);
            }
            byte[] lenBlock = new byte[16];
            long aadLen = (aad != null) ? aad.length : 0;
            long ctLen = (ct != null) ? ct.length : 0;
            for (int i = 0; i < 8; i++) {
                lenBlock[i] = (byte) ((aadLen >>> (i * 8)) & 0xFF);
                lenBlock[8 + i] = (byte) ((ctLen >>> (i * 8)) & 0xFF);
            }
            baos.write(lenBlock);
        } catch (Exception ignored) {}

        byte[] macData = baos.toByteArray();
        int offset = 0;
        while (offset < macData.length) {
            int blen = Math.min(16, macData.length - offset);
            byte[] rev = new byte[blen + 2];
            rev[1] = 0x01;
            for (int i = 0; i < blen; i++) {
                rev[rev.length - 1 - i] = macData[offset + i];
            }
            BigInteger n = new BigInteger(rev);
            a = a.add(n).multiply(r).mod(P1305);
            offset += 16;
        }

        BigInteger tagInt = a.add(s).mod(MOD128);
        return bigIntToLe16(tagInt);
    }

    private static BigInteger leToBigInt(byte[] b) {
        byte[] rev = new byte[b.length + 1];
        for (int i = 0; i < b.length; i++) rev[b.length - i] = b[i];
        return new BigInteger(rev);
    }

    private static byte[] bigIntToLe16(BigInteger val) {
        byte[] b = val.toByteArray();
        byte[] res = new byte[16];
        int len = b.length;
        for (int i = 0; i < 16; i++) {
            int srcIdx = len - 1 - i;
            if (srcIdx >= 0) res[i] = b[srcIdx];
        }
        return res;
    }

    private static int[] chacha20Init(byte[] key, int counter, byte[] nonce12) {
        int[] s = new int[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = getLittleEndianInt(key, i * 4);
        s[12] = counter;
        s[13] = getLittleEndianInt(nonce12, 0);
        s[14] = getLittleEndianInt(nonce12, 4);
        s[15] = getLittleEndianInt(nonce12, 8);
        return s;
    }

    private static byte[] chacha20Block(int[] state) {
        int[] x = Arrays.copyOf(state, 16);
        for (int i = 0; i < 10; i++) {
            quarterRound(x, 0, 4, 8, 12);
            quarterRound(x, 1, 5, 9, 13);
            quarterRound(x, 2, 6, 10, 14);
            quarterRound(x, 3, 7, 11, 15);
            quarterRound(x, 0, 5, 10, 15);
            quarterRound(x, 1, 6, 11, 12);
            quarterRound(x, 2, 7, 8, 13);
            quarterRound(x, 3, 4, 9, 14);
        }
        byte[] block = new byte[64];
        ByteBuffer buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 16; i++) {
            buf.putInt(x[i] + state[i]);
        }
        return block;
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
    }

    private static int getLittleEndianInt(byte[] b, int offset) {
        return (b[offset] & 0xFF) |
                ((b[offset + 1] & 0xFF) << 8) |
                ((b[offset + 2] & 0xFF) << 16) |
                ((b[offset + 3] & 0xFF) << 24);
    }

    // =========================================================================
    // 4. Handshake Construction & Verification
    // =========================================================================

    public static byte[] buildHandshakeInit(byte[] keyId, byte[] masterKey, byte[] clientPub) {
        byte[] packet = new byte[72];
        packet[0] = TYPE_HANDSHAKE_INIT;
        // Reserved 1..7 = 0x00
        System.arraycopy(keyId, 0, packet, 8, 8);
        System.arraycopy(clientPub, 0, packet, 16, 32);

        long nowMs = System.currentTimeMillis();
        for (int i = 7; i >= 0; i--) {
            packet[48 + i] = (byte) (nowMs & 0xFF);
            nowMs >>= 8;
        }

        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(masterKey, "HmacSHA256"));
            hmac.update(packet, 0, 56);
            byte[] fullMac = hmac.doFinal();
            System.arraycopy(fullMac, 0, packet, 56, 16);
        } catch (Exception e) {
            throw new RuntimeException("Handshake HMAC computation error", e);
        }

        return packet;
    }

    public static HandshakeResult processHandshakeResp(
            byte[] resp, int len, byte[] keyId, byte[] masterKey, byte[] clientPriv) throws Exception {

        if (len < 80) {
            throw new IllegalArgumentException("Handshake response too short: " + len);
        }
        if (resp[0] != TYPE_HANDSHAKE_RESP) {
            throw new IllegalArgumentException("Invalid Handshake response type: " + resp[0]);
        }

        ByteBuffer buf = ByteBuffer.wrap(resp).order(ByteOrder.BIG_ENDIAN);
        buf.position(8);
        long sessionId = buf.getLong();

        byte[] serverEphemeralPub = new byte[32];
        System.arraycopy(resp, 16, serverEphemeralPub, 0, 32);

        byte[] sharedSecret = x25519ScalarMult(clientPriv, serverEphemeralPub);

        // Derive session keys per PROTOCOL.md
        byte[] configKey = hkdf(sharedSecret, masterKey, "aegs-cfg", 32);
        byte[] c2sKey    = hkdf(sharedSecret, masterKey, "aegs-c2s", 32);
        byte[] s2cKey    = hkdf(sharedSecret, masterKey, "aegs-s2c", 32);
        byte[] maskKey   = hkdf(masterKey, "aegis-v2-salt".getBytes(StandardCharsets.UTF_8), "aegs-v2-header-mask", 32);

        // Decrypt EncryptedConfig (offset 48, len 16 ciphertext + 16 tag = 32 bytes)
        byte[] encryptedConfigWithTag = new byte[32];
        System.arraycopy(resp, 48, encryptedConfigWithTag, 0, 32);

        byte[] aad = new byte[48];
        System.arraycopy(resp, 0, aad, 0, 48);

        byte[] nonceZero = new byte[12];
        byte[] configPlain;
        try {
            configPlain = decryptAead(configKey, nonceZero, encryptedConfigWithTag, aad);
        } catch (Exception e) {
            // Interop fallback: python server uses s2cKey for response config
            configPlain = decryptAead(s2cKey, nonceZero, encryptedConfigWithTag, aad);
        }

        // Config payload: assigned_ip[4], mtu[2], zeros[10]
        int b1 = configPlain[0] & 0xFF;
        int b2 = configPlain[1] & 0xFF;
        int b3 = configPlain[2] & 0xFF;
        int b4 = configPlain[3] & 0xFF;
        String assignedIp;
        if (b1 == 10 && b2 == 8) {
            assignedIp = b1 + "." + b2 + "." + b3 + "." + b4;
        } else if (b4 == 10 && b3 == 8) {
            assignedIp = b4 + "." + b3 + "." + b2 + "." + b1;
        } else {
            assignedIp = b1 + "." + b2 + "." + b3 + "." + b4;
        }

        // MTU is little-endian in C++ kernel
        int mtu = (configPlain[4] & 0xFF) | ((configPlain[5] & 0xFF) << 8);
        if (mtu < 576 || mtu > 1500) {
            // Check big-endian fallback
            mtu = ((configPlain[4] & 0xFF) << 8) | (configPlain[5] & 0xFF);
        }
        if (mtu < 576 || mtu > 1500) mtu = 1280;

        HandshakeResult res = new HandshakeResult();
        res.sessionId = sessionId;
        res.assignedIp = assignedIp;
        res.mtu = mtu;
        res.sendKey = c2sKey;
        res.recvKey = s2cKey;
        res.maskKey = maskKey;
        res.keyId = keyId;
        return res;
    }

    // =========================================================================
    // 5. Data Packet Formatting & Bimodal Padding
    // =========================================================================

    public static byte[] buildDataPacket(byte[] ipPacket, int ipLen, byte[] keyId, byte[] maskKey,
                                         byte[] sendKey, long txSeq, boolean isChaff) {
        int targetLen;
        if (ipLen <= 200) {
            targetLen = 256 + (CSPRNG.nextInt(33) - 16); // 256 ± 16
        } else {
            // Target ~1240 bytes so that with 56B outer headers + 16B tag + 28B IP/UDP wire packet stays <= 1340B (0 carrier fragmentation)
            targetLen = 1240 + (CSPRNG.nextInt(33) - 16);
        }
        if (CSPRNG.nextInt(100) < 5) {
            targetLen = 512 + CSPRNG.nextInt(128); // 5% medium jitter to defeat anti-ML bimodal clustering
        }

        int padLen = Math.max(0, targetLen - (2 + ipLen));
        byte[] frame = new byte[2 + ipLen + padLen];
        frame[0] = (byte) ((ipLen >> 8) & 0xFF);
        frame[1] = (byte) (ipLen & 0xFF);
        if (ipLen > 0) {
            System.arraycopy(ipPacket, 0, frame, 2, ipLen);
        }
        if (padLen > 0) {
            byte[] padBytes = new byte[padLen];
            CSPRNG.nextBytes(padBytes);
            System.arraycopy(padBytes, 0, frame, 2 + ipLen, padLen);
        }

        int junkLen = CSPRNG.nextInt(16); // 0-15 bytes junk
        byte[] hdrIv = new byte[12];
        CSPRNG.nextBytes(hdrIv);

        byte[] plainHdr = new byte[16];
        System.arraycopy(keyId, 0, plainHdr, 0, 8);
        plainHdr[8] = (byte) ((junkLen >> 8) & 0xFF);
        plainHdr[9] = (byte) (junkLen & 0xFF);
        plainHdr[10] = isChaff ? CHAFF_FLAG : 0x00;
        plainHdr[11] = 0x00;
        System.arraycopy(VER_MAGIC, 0, plainHdr, 12, 4);

        byte[] maskedHdr = maskUnmaskHeader(plainHdr, maskKey, hdrIv);
        byte[] junk = new byte[junkLen];
        if (junkLen > 0) CSPRNG.nextBytes(junk);

        byte[] outerHdr = new byte[12 + 16 + junkLen];
        System.arraycopy(hdrIv, 0, outerHdr, 0, 12);
        System.arraycopy(maskedHdr, 0, outerHdr, 12, 16);
        if (junkLen > 0) {
            System.arraycopy(junk, 0, outerHdr, 28, junkLen);
        }

        byte[] aeadNonce = new byte[12];
        for (int i = 0; i < 8; i++) {
            aeadNonce[i] = (byte) ((txSeq >> (i * 8)) & 0xFF);
        }
        byte[] rnd4 = new byte[4];
        CSPRNG.nextBytes(rnd4);
        System.arraycopy(rnd4, 0, aeadNonce, 8, 4);

        byte[] cipherWithTag = encryptAead(sendKey, aeadNonce, frame, outerHdr);

        byte[] wirePacket = new byte[outerHdr.length + 12 + cipherWithTag.length];
        System.arraycopy(outerHdr, 0, wirePacket, 0, outerHdr.length);
        System.arraycopy(aeadNonce, 0, wirePacket, outerHdr.length, 12);
        System.arraycopy(cipherWithTag, 0, wirePacket, outerHdr.length + 12, cipherWithTag.length);
        return wirePacket;
    }

    public static byte[] parseDataPacket(byte[] packet, int len, byte[] keyId, byte[] maskKey,
                                         byte[] recvKey) throws Exception {
        // Auto-detect and strip RFC 9000 QUIC mimicry (24-byte Long Header)
        if (len >= 24 && (packet[0] & 0x80) != 0 && packet[5] == 0x08 && packet[14] == 0x08 && packet[23] == 0x00) {
            byte[] unwrapped = new byte[len - 24];
            System.arraycopy(packet, 24, unwrapped, 0, len - 24);
            packet = unwrapped;
            len = unwrapped.length;
        } else if (len >= 45 && packet[0] == 0x16) {
            byte[] unwrapped = parseTlsRealityPayload(packet, len);
            if (unwrapped != null) {
                packet = unwrapped;
                len = unwrapped.length;
            }
        }

        if (len < 56) return null;

        byte[] hdrIv = new byte[12];
        System.arraycopy(packet, 0, hdrIv, 0, 12);

        byte[] maskedHdr = new byte[16];
        System.arraycopy(packet, 12, maskedHdr, 0, 16);

        byte[] plainHdr = maskUnmaskHeader(maskedHdr, maskKey, hdrIv);

        // Verify KeyID & VER_MAGIC
        for (int i = 0; i < 8; i++) {
            if (plainHdr[i] != keyId[i]) return null;
        }
        if (plainHdr[12] != VER_MAGIC[0] || plainHdr[13] != VER_MAGIC[1] ||
                plainHdr[14] != VER_MAGIC[2] || plainHdr[15] != VER_MAGIC[3]) {
            return null;
        }

        // Chaff packet drop (anti-timing dummy frames)
        if ((plainHdr[10] & CHAFF_FLAG) != 0) {
            return new byte[0]; // Empty byte array signifies valid chaff frame to be silently dropped
        }

        int junkLen = ((plainHdr[8] & 0xFF) << 8) | (plainHdr[9] & 0xFF);
        int outerLen = 12 + 16 + junkLen;
        if (len < outerLen + 12 + 16) return null;

        byte[] outerHdr = new byte[outerLen];
        System.arraycopy(packet, 0, outerHdr, 0, outerLen);

        byte[] aeadNonce = new byte[12];
        System.arraycopy(packet, outerLen, aeadNonce, 0, 12);

        int ctLen = len - (outerLen + 12);
        byte[] ctWithTag = new byte[ctLen];
        System.arraycopy(packet, outerLen + 12, ctWithTag, 0, ctLen);

        byte[] frame = decryptAead(recvKey, aeadNonce, ctWithTag, outerHdr);
        if (frame == null || frame.length < 2) return null;

        int payloadLen = ((frame[0] & 0xFF) << 8) | (frame[1] & 0xFF);
        if (payloadLen <= 0 || payloadLen > frame.length - 2) return null;

        byte[] ipPacket = new byte[payloadLen];
        System.arraycopy(frame, 2, ipPacket, 0, payloadLen);
        return ipPacket;
    }

    // =========================================================================
    // 6. Decoy Priming Builders (RFC 5389 STUN & RFC 9000 QUIC)
    // =========================================================================

    public static byte[] buildStunDecoy() {
        byte[] decoy = new byte[20];
        decoy[0] = 0x00; decoy[1] = 0x01; // Binding Request
        decoy[2] = 0x00; decoy[3] = 0x00; // Length = 0
        decoy[4] = 0x21; decoy[5] = 0x12; decoy[6] = (byte) 0xA4; decoy[7] = 0x42; // RFC 5389 Magic Cookie
        byte[] txId = new byte[12];
        CSPRNG.nextBytes(txId);
        System.arraycopy(txId, 0, decoy, 8, 12);
        return decoy;
    }

    public static byte[] buildQuicInitialDecoy() {
        byte[] quic = new byte[1200];
        quic[0] = (byte) 0xC3; // Long Header + Initial
        quic[1] = 0x00; quic[2] = 0x00; quic[3] = 0x00; quic[4] = 0x01; // QUIC v1
        quic[5] = 8; // DCID len
        byte[] dcid = new byte[8]; CSPRNG.nextBytes(dcid);
        System.arraycopy(dcid, 0, quic, 6, 8);
        quic[14] = 8; // SCID len
        byte[] scid = new byte[8]; CSPRNG.nextBytes(scid);
        System.arraycopy(scid, 0, quic, 15, 8);
        quic[23] = 0; // Token len
        quic[24] = 0x44; quic[25] = (byte) 0x96; // 1174 bytes
        byte[] rnd = new byte[1174];
        CSPRNG.nextBytes(rnd);
        System.arraycopy(rnd, 0, quic, 26, 1174);
        return quic;
    }

    public static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xFF));
        }
        return sb.toString();
    }

    // =========================================================================
    // TLS 1.3 Reality Camouflage Engine with Encrypted Client Hello (ECH)
    // =========================================================================
    public static final String DEFAULT_REALITY_SNI = "www.cloudflare.com";

    public static byte[] buildTlsRealityClientHello(byte[] innerAegsPayload, String sni) {
        if (sni == null || sni.isEmpty()) sni = DEFAULT_REALITY_SNI;
        try {
            java.io.ByteArrayOutputStream ext = new java.io.ByteArrayOutputStream();

            // 1. SNI extension (0x0000)
            byte[] sniBytes = sni.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ext.write(0x00); ext.write(0x00);
            int sniExtLen = sniBytes.length + 5;
            ext.write((sniExtLen >> 8) & 0xFF); ext.write(sniExtLen & 0xFF);
            int serverNameListLen = sniBytes.length + 3;
            ext.write((serverNameListLen >> 8) & 0xFF); ext.write(serverNameListLen & 0xFF);
            ext.write(0x00);
            ext.write((sniBytes.length >> 8) & 0xFF); ext.write(sniBytes.length & 0xFF);
            ext.write(sniBytes);

            // 2. Supported Groups (0x000a) with X25519 (0x001d), secp256r1 (0x0017)
            ext.write(0x00); ext.write(0x0a);
            ext.write(0x00); ext.write(0x06);
            ext.write(0x00); ext.write(0x04);
            ext.write(0x00); ext.write(0x1d);
            ext.write(0x00); ext.write(0x17);

            // 3. ALPN extension (0x0010) with "h2"
            byte[] alpnBytes = "h2".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ext.write(0x00); ext.write(0x10);
            int alpnExtLen = alpnBytes.length + 3;
            ext.write((alpnExtLen >> 8) & 0xFF); ext.write(alpnExtLen & 0xFF);
            int alpnListLen = alpnBytes.length + 1;
            ext.write((alpnListLen >> 8) & 0xFF); ext.write(alpnListLen & 0xFF);
            ext.write(alpnBytes.length & 0xFF);
            ext.write(alpnBytes);

            // 4. Supported Versions extension (0x002b) with TLS 1.3 (0x0304)
            ext.write(0x00); ext.write(0x2b);
            ext.write(0x00); ext.write(0x03);
            ext.write(0x02);
            ext.write(0x03); ext.write(0x04);

            // 5. Encrypted Client Hello (ECH, 0xfe0d) encapsulating AEGS Handshake / Frame!
            ext.write(0xfe); ext.write(0x0d);
            byte[] magic = new byte[]{'A', 'E', 'G', '1'};
            int echDataLen = 6 + magic.length + innerAegsPayload.length;
            ext.write((echDataLen >> 8) & 0xFF); ext.write(echDataLen & 0xFF);
            ext.write(0x00);
            ext.write(0x00); ext.write(0x20);
            ext.write(0x00); ext.write(0x01);
            ext.write(0x01);
            ext.write(magic);
            ext.write(innerAegsPayload);

            byte[] extBytes = ext.toByteArray();

            // Assemble ClientHello Body
            java.io.ByteArrayOutputStream ch = new java.io.ByteArrayOutputStream();
            ch.write(0x03); ch.write(0x03); // Legacy version TLS 1.2

            byte[] random = new byte[32];
            new java.security.SecureRandom().nextBytes(random);
            ch.write(random);

            byte[] sessionId = new byte[32];
            new java.security.SecureRandom().nextBytes(sessionId);
            ch.write(sessionId.length & 0xFF);
            ch.write(sessionId);

            // Cipher Suites: GREASE + TLS 1.3 suites
            int[] ciphers = new int[]{0x1a1a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f};
            ch.write(0x00); ch.write(ciphers.length * 2);
            for (int c : ciphers) {
                ch.write((c >> 8) & 0xFF); ch.write(c & 0xFF);
            }

            // Compression (null)
            ch.write(0x01); ch.write(0x00);

            // Total extensions
            ch.write((extBytes.length >> 8) & 0xFF); ch.write(extBytes.length & 0xFF);
            ch.write(extBytes);

            byte[] chBody = ch.toByteArray();

            // Handshake Header (Type 0x01, Length 24-bit)
            java.io.ByteArrayOutputStream hs = new java.io.ByteArrayOutputStream();
            hs.write(0x01);
            hs.write((chBody.length >> 16) & 0xFF);
            hs.write((chBody.length >> 8) & 0xFF);
            hs.write(chBody.length & 0xFF);
            hs.write(chBody);

            byte[] hsBytes = hs.toByteArray();

            // TLS Record Layer (0x16 Handshake, Version 0x0301, Length 16-bit)
            java.io.ByteArrayOutputStream record = new java.io.ByteArrayOutputStream();
            record.write(0x16);
            record.write(0x03); record.write(0x01);
            record.write((hsBytes.length >> 8) & 0xFF);
            record.write(hsBytes.length & 0xFF);
            record.write(hsBytes);

            return record.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Reality ECH build error", e);
        }
    }

    public static byte[] parseTlsRealityPayload(byte[] packet, int len) {
        if (len < 45 || packet[0] != 0x16) return null;
        for (int i = 5; i + 10 <= len; i++) {
            if ((packet[i] & 0xFF) == 0xFE && (packet[i + 1] & 0xFF) == 0x0D) {
                int extLen = ((packet[i + 2] & 0xFF) << 8) | (packet[i + 3] & 0xFF);
                int extEnd = Math.min(len, i + 4 + extLen);
                for (int j = i + 4; j + 4 <= extEnd; j++) {
                    if (packet[j] == 'A' && packet[j + 1] == 'E' && packet[j + 2] == 'G' && packet[j + 3] == '1') {
                        int payloadStart = j + 4;
                        int payloadLen = extEnd - payloadStart;
                        if (payloadLen > 0) {
                            return java.util.Arrays.copyOfRange(packet, payloadStart, payloadStart + payloadLen);
                        }
                    }
                }
            }
        }
        return null;
    }

    private static byte[] manualPbkdf2HmacSha256(byte[] password, byte[] salt, int iterations, int dkLen) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(password, "HmacSHA256"));
            byte[] out = new byte[dkLen];
            int hLen = 32;
            int l = (int) Math.ceil((double) dkLen / hLen);

            for (int i = 1; i <= l; i++) {
                mac.reset();
                mac.update(salt);
                mac.update((byte) ((i >> 24) & 0xFF));
                mac.update((byte) ((i >> 16) & 0xFF));
                mac.update((byte) ((i >> 8) & 0xFF));
                mac.update((byte) (i & 0xFF));
                byte[] u = mac.doFinal();
                byte[] t = Arrays.copyOf(u, u.length);

                for (int c = 1; c < iterations; c++) {
                    u = mac.doFinal(u);
                    for (int k = 0; k < hLen; k++) {
                        t[k] ^= u[k];
                    }
                }
                int copyLen = Math.min(hLen, dkLen - (i - 1) * hLen);
                System.arraycopy(t, 0, out, (i - 1) * hLen, copyLen);
            }
            return out;
        } catch (Exception e) {
            throw new RuntimeException("Manual PBKDF2 error", e);
        }
    }
}
