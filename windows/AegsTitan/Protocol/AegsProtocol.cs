using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AegsTitan.Protocol
{
    public static class AegsProtocol
    {
        public const string DefaultRealitySni = "www.cloudflare.com";
        public const ushort VerMagic = 0xAEE6;

        public class HandshakeResult
        {
            public ulong SessionId { get; set; }
            public string AssignedIp { get; set; } = "10.8.0.2";
            public int Mtu { get; set; } = 1280;
            public byte[] KeyId { get; set; } = Array.Empty<byte>();
            public byte[] MaskKey { get; set; } = Array.Empty<byte>();
            public byte[] AltMaskKey { get; set; } = Array.Empty<byte>();
            public byte[] SendKey { get; set; } = Array.Empty<byte>(); // c2s
            public byte[] RecvKey { get; set; } = Array.Empty<byte>(); // s2c
        }

        public class X25519KeyPair
        {
            public byte[] PublicKey { get; set; } = new byte[32];
            public byte[] PrivateKey { get; set; } = new byte[32];
        }

        public static byte[] DeriveKeyId(string token)
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
            byte[] keyId = new byte[8];
            Array.Copy(hash, 0, keyId, 0, 8);
            return keyId;
        }

        public static byte[] DeriveMasterKey(string token, byte[] keyId)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(token), keyId, 200_000, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32);
        }

        public static X25519KeyPair GenerateX25519KeyPair()
        {
            var kp = new X25519KeyPair();
            RandomNumberGenerator.Fill(kp.PrivateKey);
            kp.PrivateKey[0] &= 248;
            kp.PrivateKey[31] &= 127;
            kp.PrivateKey[31] |= 64;
            Curve25519ScalarMultBase(kp.PublicKey, kp.PrivateKey);
            return kp;
        }

        public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] peerPublicKey)
        {
            byte[] secret = new byte[32];
            Curve25519ScalarMult(secret, privateKey, peerPublicKey);
            return secret;
        }

        public static byte[] BuildHandshakeInit(byte[] keyId, byte[] masterKey, byte[] clientPubKey)
        {
            byte[] pkt = new byte[72];
            pkt[0] = 0x01; // HANDSHAKE_INIT
            Array.Copy(keyId, 0, pkt, 4, 8);
            Array.Copy(clientPubKey, 0, pkt, 12, 32);

            long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            for (int i = 7; i >= 0; i--)
            {
                pkt[44 + (7 - i)] = (byte)((ts >> (i * 8)) & 0xFF);
            }

            using var hmac = new HMACSHA256(masterKey);
            byte[] mac = hmac.ComputeHash(pkt, 0, 52);
            Array.Copy(mac, 0, pkt, 56, 16);
            return pkt;
        }

        public static HandshakeResult ProcessHandshakeResp(byte[] respBytes, byte[] keyId, byte[] masterKey, byte[] clientPrivKey)
        {
            if (respBytes.Length < 80 || respBytes[0] != 0x02)
                throw new InvalidDataException("Invalid HANDSHAKE_RESP header or length");

            ulong sessionId = 0;
            for (int i = 0; i < 8; i++)
            {
                sessionId = (sessionId << 8) | respBytes[8 + i];
            }

            byte[] serverPubKey = new byte[32];
            Array.Copy(respBytes, 16, serverPubKey, 0, 32);

            byte[] sharedSecret = ComputeSharedSecret(clientPrivKey, serverPubKey);

            // HKDF-SHA256 derivation
            byte[] prk = HKDF.Extract(HashAlgorithmName.SHA256, sharedSecret, masterKey);
            byte[] sendKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.ASCII.GetBytes("aegs v6 c2s"));
            byte[] recvKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.ASCII.GetBytes("aegs v6 s2c"));
            byte[] maskKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.ASCII.GetBytes("aegs v6 mask"));
            byte[] altMaskKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.ASCII.GetBytes("aegs v6 altmask"));
            byte[] configKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.ASCII.GetBytes("aegs v6 config"));

            // Decrypt assigned IP & MTU
            byte[] encConfig = new byte[16];
            Array.Copy(respBytes, 48, encConfig, 0, 16);
            byte[] tag = new byte[16];
            Array.Copy(respBytes, 64, tag, 0, 16);

            byte[] nonce = new byte[12];
            Array.Copy(keyId, 0, nonce, 0, 8);
            nonce[8] = 0xAA; nonce[9] = 0x55;

            byte[] plainConfig = new byte[16];
            using var aead = new ChaCha20Poly1305(configKey);
            aead.Decrypt(nonce, encConfig, tag, plainConfig);

            string assignedIp = $"{plainConfig[0]}.{plainConfig[1]}.{plainConfig[2]}.{plainConfig[3]}";
            int mtu = ((plainConfig[4] & 0xFF) << 8) | (plainConfig[5] & 0xFF);
            if (mtu < 576 || mtu > 9000) mtu = 1280;

            return new HandshakeResult
            {
                SessionId = sessionId,
                AssignedIp = assignedIp,
                Mtu = mtu,
                KeyId = keyId,
                MaskKey = maskKey,
                AltMaskKey = altMaskKey,
                SendKey = sendKey,
                RecvKey = recvKey
            };
        }

        public static byte[] BuildDataPacket(byte[] payload, int payloadLen, byte[] keyId, byte[] maskKey, byte[] sendKey, ulong seq, bool isChaff)
        {
            byte[] iv = new byte[12];
            RandomNumberGenerator.Fill(iv);

            byte[] rawHeader = new byte[16];
            Array.Copy(keyId, 0, rawHeader, 0, 8);
            rawHeader[8] = 0; rawHeader[9] = 0; // JunkLen = 0
            rawHeader[10] = (byte)(isChaff ? 0x80 : 0x00);
            rawHeader[11] = 0x00;
            rawHeader[12] = (byte)(VerMagic >> 8);
            rawHeader[13] = (byte)(VerMagic & 0xFF);
            rawHeader[14] = 0; rawHeader[15] = 0;

            byte[] maskedHeader = ApplyChaCha20Mask(rawHeader, maskKey, iv);

            byte[] nonce = new byte[12];
            for (int i = 7; i >= 0; i--)
            {
                nonce[7 - i] = (byte)((seq >> (i * 8)) & 0xFF);
            }

            byte[] ciphertext = new byte[payloadLen];
            byte[] tag = new byte[16];
            using var aead = new ChaCha20Poly1305(sendKey);
            aead.Encrypt(nonce, payload.AsSpan(0, payloadLen), ciphertext, tag, maskedHeader);

            byte[] wire = new byte[12 + 16 + 12 + payloadLen + 16];
            Array.Copy(iv, 0, wire, 0, 12);
            Array.Copy(maskedHeader, 0, wire, 12, 16);
            Array.Copy(nonce, 0, wire, 28, 12);
            Array.Copy(ciphertext, 0, wire, 40, payloadLen);
            Array.Copy(tag, 0, wire, 40 + payloadLen, 16);
            return wire;
        }

        public static byte[]? ParseDataPacket(byte[] rawPacket, byte[] keyId, byte[] maskKey, byte[] altMaskKey, byte[] recvKey)
        {
            if (rawPacket.Length < 56) return null;

            byte[] iv = new byte[12];
            Array.Copy(rawPacket, 0, iv, 0, 12);
            byte[] maskedHeader = new byte[16];
            Array.Copy(rawPacket, 12, maskedHeader, 0, 16);

            byte[] unmasked = ApplyChaCha20Mask(maskedHeader, maskKey, iv);
            bool keyIdOk = true;
            for (int i = 0; i < 8; i++)
            {
                if (unmasked[i] != keyId[i]) { keyIdOk = false; break; }
            }

            if (!keyIdOk && altMaskKey.Length == 32)
            {
                unmasked = ApplyChaCha20Mask(maskedHeader, altMaskKey, iv);
                keyIdOk = true;
                for (int i = 0; i < 8; i++)
                {
                    if (unmasked[i] != keyId[i]) { keyIdOk = false; break; }
                }
            }

            if (!keyIdOk) return null;

            ushort junkLen = (ushort)(((unmasked[8] & 0xFF) << 8) | (unmasked[9] & 0xFF));
            bool isChaff = (unmasked[10] & 0x80) != 0;

            int payloadOffset = 12 + 16 + junkLen + 12;
            int tagOffset = rawPacket.Length - 16;
            if (payloadOffset > tagOffset) return null;

            int cipherLen = tagOffset - payloadOffset;
            byte[] nonce = new byte[12];
            Array.Copy(rawPacket, 12 + 16 + junkLen, nonce, 0, 12);

            byte[] tag = new byte[16];
            Array.Copy(rawPacket, tagOffset, tag, 0, 16);

            byte[] plaintext = new byte[cipherLen];
            try
            {
                using var aead = new ChaCha20Poly1305(recvKey);
                aead.Decrypt(nonce, rawPacket.AsSpan(payloadOffset, cipherLen), tag, plaintext, maskedHeader);
                if (isChaff) return Array.Empty<byte>();
                return plaintext;
            }
            catch
            {
                return null;
            }
        }

        public static byte[] WrapTlsAppData(byte[] payload)
        {
            byte[] frame = new byte[5 + payload.Length];
            frame[0] = 0x17; // Application Data
            frame[1] = 0x03; // TLS 1.2/1.3 legacy version
            frame[2] = 0x03;
            frame[3] = (byte)((payload.Length >> 8) & 0xFF);
            frame[4] = (byte)(payload.Length & 0xFF);
            Array.Copy(payload, 0, frame, 5, payload.Length);
            return frame;
        }

        public static byte[]? ParseTlsRealityPayload(byte[] raw)
        {
            if (raw.Length < 5 || raw[0] != 0x17) return null;
            int length = ((raw[3] & 0xFF) << 8) | (raw[4] & 0xFF);
            if (raw.Length < 5 + length) return null;
            byte[] unwrapped = new byte[length];
            Array.Copy(raw, 5, unwrapped, 0, length);
            return unwrapped;
        }

        public static byte[] BuildTlsRealityClientHello(byte[] handshakePacket, string sni)
        {
            byte[] sniBytes = Encoding.ASCII.GetBytes(sni);
            int sniLen = sniBytes.Length;
            int hsLen = handshakePacket.Length;

            int bodyLen = 34 + 2 + (2 + 1 + 2 + sniLen) + (2 + 2 + hsLen) + 20;
            byte[] record = new byte[5 + 4 + bodyLen];

            record[0] = 0x16; // Handshake
            record[1] = 0x03; record[2] = 0x01; // TLS 1.0 ClientHello framing
            int recLen = 4 + bodyLen;
            record[3] = (byte)(recLen >> 8); record[4] = (byte)(recLen & 0xFF);

            record[5] = 0x01; // ClientHello
            record[6] = 0x00; record[7] = (byte)(bodyLen >> 8); record[8] = (byte)(bodyLen & 0xFF);

            record[9] = 0x03; record[10] = 0x03; // Client version TLS 1.2
            RandomNumberGenerator.Fill(record.AsSpan(11, 32)); // Random (32 B)

            int idx = 43;
            record[idx++] = 0x00; // Session ID len = 0
            record[idx++] = 0x00; record[idx++] = 0x02; // Cipher Suites len = 2
            record[idx++] = 0x13; record[idx++] = 0x01; // TLS_AES_128_GCM_SHA256
            record[idx++] = 0x01; record[idx++] = 0x00; // Compression len = 1 (null)

            int extTotalLen = (4 + 3 + sniLen) + (4 + hsLen);
            record[idx++] = (byte)(extTotalLen >> 8); record[idx++] = (byte)(extTotalLen & 0xFF);

            // Extension 1: Server Name Indication (0x0000)
            record[idx++] = 0x00; record[idx++] = 0x00;
            int sniExtLen = 3 + sniLen;
            record[idx++] = (byte)(sniExtLen >> 8); record[idx++] = (byte)(sniExtLen & 0xFF);
            int sniListLen = 1 + 2 + sniLen;
            record[idx++] = (byte)(sniListLen >> 8); record[idx++] = (byte)(sniListLen & 0xFF);
            record[idx++] = 0x00; // host_name type
            record[idx++] = (byte)(sniLen >> 8); record[idx++] = (byte)(sniLen & 0xFF);
            Array.Copy(sniBytes, 0, record, idx, sniLen); idx += sniLen;

            // Extension 2: Encrypted Client Hello ECH (0xfe0d)
            record[idx++] = 0xFE; record[idx++] = 0x0D;
            record[idx++] = (byte)(hsLen >> 8); record[idx++] = (byte)(hsLen & 0xFF);
            Array.Copy(handshakePacket, 0, record, idx, hsLen); idx += hsLen;

            return record;
        }

        private static byte[] ApplyChaCha20Mask(byte[] data, byte[] key, byte[] iv)
        {
            // Lightweight 1-block ChaCha20 stream cipher XOR keystream
            uint[] state = new uint[16];
            state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
            for (int i = 0; i < 8; i++)
            {
                state[4 + i] = (uint)(key[i * 4] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24));
            }
            state[12] = 0; // counter = 0
            for (int i = 0; i < 3; i++)
            {
                state[13 + i] = (uint)(iv[i * 4] | (iv[i * 4 + 1] << 8) | (iv[i * 4 + 2] << 16) | (iv[i * 4 + 3] << 24));
            }

            uint[] working = new uint[16];
            Array.Copy(state, working, 16);
            for (int r = 0; r < 10; r++)
            {
                QuarterRound(working, 0, 4, 8, 12);
                QuarterRound(working, 1, 5, 9, 13);
                QuarterRound(working, 2, 6, 10, 14);
                QuarterRound(working, 3, 7, 11, 15);
                QuarterRound(working, 0, 5, 10, 15);
                QuarterRound(working, 1, 6, 11, 12);
                QuarterRound(working, 2, 7, 8, 13);
                QuarterRound(working, 3, 4, 9, 14);
            }

            byte[] keyStream = new byte[64];
            for (int i = 0; i < 16; i++)
            {
                uint val = working[i] + state[i];
                keyStream[i * 4] = (byte)(val & 0xFF);
                keyStream[i * 4 + 1] = (byte)((val >> 8) & 0xFF);
                keyStream[i * 4 + 2] = (byte)((val >> 16) & 0xFF);
                keyStream[i * 4 + 3] = (byte)((val >> 24) & 0xFF);
            }

            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ keyStream[i % 64]);
            }
            return result;
        }

        private static void QuarterRound(uint[] x, int a, int b, int c, int d)
        {
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 16);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 12);
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 8);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 7);
        }

        private static uint Rotl(uint v, int c) => (v << c) | (v >> (32 - c));

        // RFC 7748 Pure C# Curve25519 Montgomery Ladder
        private static void Curve25519ScalarMultBase(byte[] result, byte[] scalar)
        {
            byte[] basePoint = new byte[32];
            basePoint[0] = 9;
            Curve25519ScalarMult(result, scalar, basePoint);
        }

        private static void Curve25519ScalarMult(byte[] result, byte[] scalar, byte[] point)
        {
            long[] k = new long[32];
            for (int i = 0; i < 32; i++) k[i] = scalar[i] & 0xFF;
            k[0] &= 248; k[31] &= 127; k[31] |= 64;

            long[] u = new long[16];
            for (int i = 0; i < 16; i++) u[i] = (point[i * 2] & 0xFF) | ((point[i * 2 + 1] & 0xFF) << 8);

            long[] x1 = (long[])u.Clone();
            long[] x2 = new long[16]; x2[0] = 1;
            long[] z2 = new long[16];
            long[] x3 = (long[])u.Clone();
            long[] z3 = new long[16]; z3[0] = 1;

            long swap = 0;
            for (int t = 254; t >= 0; t--)
            {
                long kt = (k[t / 8] >> (t % 8)) & 1;
                swap ^= kt;
                CSwap(swap, x2, x3);
                CSwap(swap, z2, z3);
                swap = kt;

                long[] a = Add(x2, z2);
                long[] aa = Sqr(a);
                long[] b = Sub(x2, z2);
                long[] bb = Sqr(b);
                long[] e = Sub(aa, bb);
                long[] c = Add(x3, z3);
                long[] d = Sub(x3, z3);
                long[] da = Mul(d, a);
                long[] cb = Mul(c, b);

                x3 = Sqr(Add(da, cb));
                z3 = Mul(x1, Sqr(Sub(da, cb)));
                x2 = Mul(aa, bb);
                z2 = Mul(e, Add(aa, MulScalar(e, 121665)));
            }

            CSwap(swap, x2, x3);
            CSwap(swap, z2, z3);

            long[] res = Mul(x2, Inv(z2));
            for (int i = 0; i < 16; i++)
            {
                result[i * 2] = (byte)(res[i] & 0xFF);
                result[i * 2 + 1] = (byte)((res[i] >> 8) & 0xFF);
            }
        }

        private static void CSwap(long swap, long[] a, long[] b)
        {
            long mask = -swap;
            for (int i = 0; i < 16; i++)
            {
                long t = mask & (a[i] ^ b[i]);
                a[i] ^= t;
                b[i] ^= t;
            }
        }

        private static long[] Add(long[] a, long[] b)
        {
            long[] c = new long[16];
            for (int i = 0; i < 16; i++) c[i] = a[i] + b[i];
            return Carry(c);
        }

        private static long[] Sub(long[] a, long[] b)
        {
            long[] c = new long[16];
            for (int i = 0; i < 16; i++) c[i] = a[i] - b[i] + 0x7fffda;
            return Carry(c);
        }

        private static long[] MulScalar(long[] a, long s)
        {
            long[] c = new long[16];
            for (int i = 0; i < 16; i++) c[i] = a[i] * s;
            return Carry(c);
        }

        private static long[] Mul(long[] a, long[] b)
        {
            long[] c = new long[31];
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    c[i + j] += a[i] * b[j];
                }
            }
            for (int i = 0; i < 15; i++)
            {
                c[i] += c[i + 16] * 38;
            }
            long[] res = new long[16];
            Array.Copy(c, res, 16);
            return Carry(res);
        }

        private static long[] Sqr(long[] a) => Mul(a, a);

        private static long[] Inv(long[] a)
        {
            long[] c = (long[])a.Clone();
            for (int i = 253; i >= 0; i--)
            {
                c = Sqr(c);
                if (i != 2 && i != 4) c = Mul(c, a);
            }
            return c;
        }

        private static long[] Carry(long[] a)
        {
            long[] res = (long[])a.Clone();
            for (int i = 0; i < 15; i++)
            {
                res[i + 1] += res[i] >> 16;
                res[i] &= 0xFFFF;
            }
            res[0] += (res[15] >> 16) * 38;
            res[15] &= 0xFFFF;
            return res;
        }
    }
}
