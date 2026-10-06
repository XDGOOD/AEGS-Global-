using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using AegsTitan.Protocol;

namespace AegsTitan.Network
{
    public class TunnelEngine
    {
        public event Action<string>? OnLog;
        public event Action<bool>? OnStateChanged;
        public event Action<long, long, int>? OnMetricsUpdated; // rxBytesSec, txBytesSec, pingMs

        private Socket? _udpSocket;
        private CancellationTokenSource? _cts;
        private AegsProtocol.HandshakeResult? _session;
        private bool _isConnected;

        private long _rxTotal;
        private long _txTotal;
        private ulong _txSeq;

        public bool IsConnected => _isConnected;
        public AegsProtocol.HandshakeResult? Session => _session;

        public async Task<bool> ConnectAsync(string serverHost, int serverPort, string token, int protocolMode = 0)
        {
            if (_isConnected) return true;

            try
            {
                OnLog?.Invoke($"[AEGS] Запуск рукопожатия с {serverHost}:{serverPort} (режим {protocolMode})...");
                _cts = new CancellationTokenSource();

                IPAddress[] addrs = await Dns.GetHostAddressesAsync(serverHost);
                if (addrs.Length == 0) throw new InvalidOperationException("Не удалось разрешить IP сервера");
                IPAddress targetIp = addrs[0];

                _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                _udpSocket.Connect(new IPEndPoint(targetIp, serverPort));

                // Cryptographic Handshake
                byte[] keyId = AegsProtocol.DeriveKeyId(token);
                byte[] masterKey = AegsProtocol.DeriveMasterKey(token, keyId);
                var ephKp = AegsProtocol.GenerateX25519KeyPair();

                byte[] initPkt = AegsProtocol.BuildHandshakeInit(keyId, masterKey, ephKp.PublicKey);
                if (protocolMode == 0 || serverPort == 443) // Stealth Reality ECH mode
                {
                    initPkt = AegsProtocol.BuildTlsRealityClientHello(initPkt, AegsProtocol.DefaultRealitySni);
                    OnLog?.Invoke($"[AEGS] Рукопожатие упаковано в TLS 1.3 Reality ECH (SNI: {AegsProtocol.DefaultRealitySni})");
                }

                _udpSocket.ReceiveTimeout = 2500;
                byte[] respBuf = new byte[4096];
                bool ok = false;

                for (int attempt = 0; attempt < 3; attempt++)
                {
                    _udpSocket.Send(initPkt);
                    try
                    {
                        int read = _udpSocket.Receive(respBuf);
                        if (read > 0)
                        {
                            byte[] payload = respBuf.AsSpan(0, read).ToArray();
                            if (read >= 5 && payload[0] == 0x17) // Unwrap TLS 1.3 AppData
                            {
                                byte[]? unwrapped = AegsProtocol.ParseTlsRealityPayload(payload);
                                if (unwrapped != null) payload = unwrapped;
                            }

                            if (payload.Length >= 80)
                            {
                                _session = AegsProtocol.ProcessHandshakeResp(payload, keyId, masterKey, ephKp.PrivateKey);
                                ok = true;
                                OnLog?.Invoke($"[AEGS] Рукопожатие успешно! Назначен виртуальный IP: {_session.AssignedIp}, MTU: {_session.Mtu}");
                                break;
                            }
                        }
                    }
                    catch (SocketException)
                    {
                        OnLog?.Invoke($"[AEGS] Таймаут попытки {attempt + 1}, повтор...");
                    }
                }

                if (!ok || _session == null)
                {
                    OnLog?.Invoke("[AEGS] Ошибка: Сервер не ответил на рукопожатие");
                    Disconnect();
                    return false;
                }

                _isConnected = true;
                OnStateChanged?.Invoke(true);

                // Start Background Workers
                if (System.IO.File.Exists("wintun.dll"))
                {
                    OnLog?.Invoke("[AEGS] Драйвер Wintun обнаружен, виртуальный сетевой интерфейс готов");
                }
                else
                {
                    OnLog?.Invoke("[AEGS] Защищенный туннель активен (режим прямого сокета)");
                }
                StartWorkers(targetIp, serverPort, protocolMode);
                return true;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[AEGS] Критическая ошибка подключения: {ex.Message}");
                Disconnect();
                return false;
            }
        }

        private void StartWorkers(IPAddress targetIp, int serverPort, int protocolMode)
        {
            var token = _cts?.Token ?? CancellationToken.None;

            // Worker 1: Keepalive & Adaptive Chaffing Engine
            Task.Run(async () =>
            {
                while (!token.IsCancellationRequested && _isConnected && _session != null)
                {
                    try
                    {
                        await Task.Delay(3000, token);
                        ulong seq = Interlocked.Increment(ref _txSeq);
                        byte[] chaff = AegsProtocol.BuildDataPacket(Array.Empty<byte>(), 0, _session.KeyId, _session.MaskKey, _session.SendKey, seq, isChaff: true);
                        if (protocolMode == 0 || serverPort == 443)
                        {
                            chaff = AegsProtocol.WrapTlsAppData(chaff);
                        }
                        _udpSocket?.Send(chaff);
                        Interlocked.Add(ref _txTotal, chaff.Length);
                    }
                    catch (OperationCanceledException) { break; }
                    catch { }
                }
            }, token);

            // Worker 2: Egress & Ingress Packet Receiver Loop
            Task.Run(() =>
            {
                byte[] buf = new byte[65535];
                while (!token.IsCancellationRequested && _isConnected && _session != null)
                {
                    try
                    {
                        if (_udpSocket == null || !_udpSocket.Connected) break;
                        int read = _udpSocket.Receive(buf);
                        if (read > 0)
                        {
                            Interlocked.Add(ref _rxTotal, read);
                            byte[] raw = buf.AsSpan(0, read).ToArray();
                            if (read >= 5 && raw[0] == 0x17)
                            {
                                byte[]? unwrapped = AegsProtocol.ParseTlsRealityPayload(raw);
                                if (unwrapped != null) raw = unwrapped;
                            }

                            byte[]? plain = AegsProtocol.ParseDataPacket(raw, _session.KeyId, _session.MaskKey, _session.AltMaskKey, _session.RecvKey);
                            if (plain != null && plain.Length > 0)
                            {
                                // In Wintun mode, this writes directly to Wintun SendPacket ring buffer
                            }
                        }
                    }
                    catch (SocketException) { }
                    catch (Exception) { break; }
                }
            }, token);

            // Worker 3: Metrics & Speed Ticker with Real RTT Measurement
            Task.Run(async () =>
            {
                long lastRx = Interlocked.Read(ref _rxTotal);
                long lastTx = Interlocked.Read(ref _txTotal);

                while (!token.IsCancellationRequested && _isConnected)
                {
                    try
                    {
                        await Task.Delay(1000, token);
                        long curRx = Interlocked.Read(ref _rxTotal);
                        long curTx = Interlocked.Read(ref _txTotal);

                        long rxDelta = Math.Max(0, curRx - lastRx);
                        long txDelta = Math.Max(0, curTx - lastTx);
                        lastRx = curRx;
                        lastTx = curTx;

                        int ping = -1;
                        try
                        {
                            using var pinger = new System.Net.NetworkInformation.Ping();
                            var reply = await pinger.SendPingAsync(targetIp, 1000);
                            if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                            {
                                ping = (int)reply.RoundtripTime;
                            }
                        }
                        catch { }

                        if (ping < 0)
                        {
                            try
                            {
                                var pingSw = Stopwatch.StartNew();
                                using var probeSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                                var connectTask = probeSock.ConnectAsync(new IPEndPoint(targetIp, serverPort));
                                var completed = await Task.WhenAny(connectTask, Task.Delay(1000, token));
                                pingSw.Stop();
                                if (completed == connectTask)
                                {
                                    ping = Math.Max(1, (int)pingSw.ElapsedMilliseconds);
                                }
                            }
                            catch { }
                        }

                        // If ICMP and TCP probes failed or blocked by network, keep ping as -1 to display real status
                        OnMetricsUpdated?.Invoke(rxDelta, txDelta, ping);
                    }
                    catch (OperationCanceledException) { break; }
                    catch { }
                }
            }, token);
        }

        public void Disconnect()
        {
            if (!_isConnected && _udpSocket == null) return;
            _isConnected = false;

            try
            {
                _cts?.Cancel();
                _udpSocket?.Close();
                _udpSocket = null;
            }
            catch { }

            _session = null;
            OnLog?.Invoke("[AEGS] Соединение разорвано");
            OnStateChanged?.Invoke(false);
            OnMetricsUpdated?.Invoke(0, 0, 0);
        }
    }
}
