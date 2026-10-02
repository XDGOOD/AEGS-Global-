using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using AegsTitan.Network;
using Wpf.Ui.Controls;

namespace AegsTitan
{
    public partial class MainWindow : FluentWindow
    {
        private readonly TunnelEngine _engine;
        private readonly string _serverHost = "31.76.9.86";
        private readonly int _serverPort = 443;

        private readonly DispatcherTimer _sessionTimer;
        private DateTime _connectedTime;
        private readonly List<double> _rxHistory = new();
        private readonly List<double> _txHistory = new();
        private const int MaxHistoryPoints = 25;

        public MainWindow()
        {
            InitializeComponent();

            _engine = new TunnelEngine();
            _engine.OnStateChanged += Engine_OnStateChanged;
            _engine.OnMetricsUpdated += Engine_OnMetricsUpdated;
            _engine.OnLog += Engine_OnLog;

            _sessionTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _sessionTimer.Tick += SessionTimer_Tick;

            // Initialize empty graph points
            for (int i = 0; i < MaxHistoryPoints; i++)
            {
                _rxHistory.Add(0);
                _txHistory.Add(0);
            }
            RedrawGraph();
        }

        private async void BtnConnect_Click(object sender, RoutedEventArgs e)
        {
            if (_engine.IsConnected)
            {
                _engine.Disconnect();
            }
            else
            {
                BtnConnect.IsEnabled = false;
                TxtStatusTitle.Text = "CONNECTING...";
                TxtStatusTitle.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                TxtStatus.Text = "Установка защищённого соединения...";
                TxtSessionTimer.Text = "Подключение к узлу...";

                string token = TxtToken.Text.Trim();
                if (string.IsNullOrEmpty(token)) token = "aegs_secure_token_titan_v6";
                int profile = CmbProfile.SelectedIndex;

                bool success = await _engine.ConnectAsync(_serverHost, _serverPort, token, profile);
                BtnConnect.IsEnabled = true;

                if (!success)
                {
                    TxtStatusTitle.Text = "ERROR";
                    TxtStatusTitle.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                    TxtStatus.Text = "Ошибка подключения к серверу";
                    TxtSessionTimer.Text = "Повторите попытку";
                }
            }
        }

        private void Engine_OnStateChanged(bool isConnected)
        {
            Dispatcher.Invoke(() =>
            {
                if (isConnected)
                {
                    _connectedTime = DateTime.Now;
                    _sessionTimer.Start();

                    TxtStatusTitle.Text = "SECURE";
                    TxtStatusTitle.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00F2FE"));
                    TxtStatus.Text = "Статус: Защита активна (Connected)";
                    TxtSubStatus.Text = $"IP: {_engine.Session?.AssignedIp ?? "10.8.0.2"} • Reality ECH 443";

                    ShieldGlowContainer.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#064E3B"));
                    ShieldGlowContainer.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
                    ShieldIconText.Text = "🛡️";

                    BtnConnectText.Text = "DISCONNECT";
                    BtnConnectText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                    BtnActionIcon.Text = "⏹";
                }
                else
                {
                    _sessionTimer.Stop();

                    TxtStatusTitle.Text = "STANDBY";
                    TxtStatusTitle.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#94A3B8"));
                    TxtStatus.Text = "Статус: Готово к запуску";
                    TxtSubStatus.Text = "TLS 1.3 Reality ECH • 0-RTT • Порт 443";
                    TxtSessionTimer.Text = "Нажмите для старта";

                    ShieldGlowContainer.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#182338"));
                    ShieldGlowContainer.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00F2FE"));
                    ShieldIconText.Text = "🛡️";

                    BtnConnectText.Text = "CONNECT";
                    BtnConnectText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00F2FE"));
                    BtnActionIcon.Text = "⚡";

                    TxtRxSpeed.Text = "0.0 КБ/с";
                    TxtTxSpeed.Text = "0.0 КБ/с";
                    TxtPing.Text = "-- мс";

                    // Reset graph
                    for (int i = 0; i < MaxHistoryPoints; i++)
                    {
                        _rxHistory[i] = 0;
                        _txHistory[i] = 0;
                    }
                    RedrawGraph();
                }
            });
        }

        private void SessionTimer_Tick(object? sender, EventArgs e)
        {
            var elapsed = DateTime.Now - _connectedTime;
            TxtSessionTimer.Text = $"Сессия активна: {elapsed:hh\\:mm\\:ss}";
        }

        private void Engine_OnMetricsUpdated(long rxBytesSec, long txBytesSec, int pingMs)
        {
            Dispatcher.Invoke(() =>
            {
                TxtRxSpeed.Text = FormatSpeed(rxBytesSec);
                TxtTxSpeed.Text = FormatSpeed(txBytesSec);
                TxtPing.Text = $"{pingMs} мс";

                // Add to history and redraw wave graph
                _rxHistory.Add(rxBytesSec);
                if (_rxHistory.Count > MaxHistoryPoints) _rxHistory.RemoveAt(0);

                _txHistory.Add(txBytesSec);
                if (_txHistory.Count > MaxHistoryPoints) _txHistory.RemoveAt(0);

                RedrawGraph();
            });
        }

        private void RedrawGraph()
        {
            double width = GraphCanvas.ActualWidth > 50 ? GraphCanvas.ActualWidth : 420;
            double height = GraphCanvas.ActualHeight > 50 ? GraphCanvas.ActualHeight : 140;

            double maxVal = 1024 * 100; // minimum scale 100 KB/s
            foreach (var v in _rxHistory) if (v > maxVal) maxVal = v;
            foreach (var v in _txHistory) if (v > maxVal) maxVal = v;

            var rxPoints = new PointCollection();
            var txPoints = new PointCollection();

            double stepX = width / (MaxHistoryPoints - 1);

            for (int i = 0; i < MaxHistoryPoints; i++)
            {
                double x = i * stepX;
                double rxY = height - 10 - (_rxHistory[i] / maxVal) * (height - 25);
                double txY = height - 10 - (_txHistory[i] / maxVal) * (height - 25);

                rxPoints.Add(new Point(x, Math.Max(5, Math.Min(height - 5, rxY))));
                txPoints.Add(new Point(x, Math.Max(5, Math.Min(height - 5, txY))));
            }

            PolyDownload.Points = rxPoints;
            PolyUpload.Points = txPoints;
        }

        private void Engine_OnLog(string msg)
        {
            Dispatcher.Invoke(() =>
            {
                TxtLogTicker.Text = msg;
            });
        }

        private static string FormatSpeed(long bytesSec)
        {
            if (bytesSec >= 1_048_576)
                return $"{(bytesSec / 1_048_576.0):F1} МБ/с";
            if (bytesSec >= 1024)
                return $"{(bytesSec / 1024.0):F0} КБ/с";
            return $"{bytesSec} Б/с";
        }

        protected override void OnClosed(EventArgs e)
        {
            _sessionTimer.Stop();
            _engine.Disconnect();
            base.OnClosed(e);
        }
    }
}