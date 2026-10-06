using System;
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
        private string _serverHost = "127.0.0.1";
        private int _serverPort = 443;

        private readonly DispatcherTimer _sessionTimer;
        private DateTime _connectedTime;

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
        }

        private void BtnOpenSettings_Click(object sender, RoutedEventArgs e)
        {
            DashboardView.Visibility = Visibility.Collapsed;
            SettingsView.Visibility = Visibility.Visible;
        }

        private void BtnBackToDashboard_Click(object sender, RoutedEventArgs e)
        {
            SettingsView.Visibility = Visibility.Collapsed;
            DashboardView.Visibility = Visibility.Visible;
        }

        private async void BtnConnect_Click(object sender, RoutedEventArgs e)
        {
            if (_engine.IsConnected)
            {
                _engine.Disconnect();
            }
            else
            {
                string rawInput = TxtToken.Text.Trim();
                string serverHost = _serverHost;
                int serverPort = _serverPort;
                string token = rawInput;

                if (rawInput.StartsWith("aegs://", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var uri = new Uri(rawInput);
                        if (!string.IsNullOrEmpty(uri.Host)) serverHost = uri.Host;
                        if (uri.Port > 0) serverPort = uri.Port;
                        string path = uri.AbsolutePath.TrimStart('/');
                        string queryToken = "";
                        if (!string.IsNullOrEmpty(uri.Query))
                        {
                            var q = uri.Query.TrimStart('?').Split('&');
                            foreach (var p in q)
                            {
                                var kv = p.Split('=');
                                if (kv.Length == 2 && kv[0].Equals("token", StringComparison.OrdinalIgnoreCase))
                                {
                                    queryToken = Uri.UnescapeDataString(kv[1]);
                                    break;
                                }
                            }
                        }
                        token = !string.IsNullOrEmpty(queryToken) ? queryToken : path;
                        if (!string.IsNullOrEmpty(uri.Fragment))
                        {
                            string frag = uri.Fragment.TrimStart('#');
                            if (frag.Contains('?')) frag = frag.Substring(0, frag.IndexOf('?'));
                            frag = frag.Trim();
                            if (!string.IsNullOrEmpty(frag) && !token.Contains("#"))
                            {
                                token = token + "#" + frag;
                            }
                        }
                    }
                    catch { }
                }
                else if (rawInput.Contains(':') && rawInput.Contains('/'))
                {
                    try
                    {
                        var uri = new Uri("aegs://" + rawInput);
                        if (!string.IsNullOrEmpty(uri.Host)) serverHost = uri.Host;
                        if (uri.Port > 0) serverPort = uri.Port;
                        string path = uri.AbsolutePath.TrimStart('/');
                        token = path;
                        if (!string.IsNullOrEmpty(uri.Fragment))
                        {
                            string frag = uri.Fragment.TrimStart('#');
                            if (frag.Contains('?')) frag = frag.Substring(0, frag.IndexOf('?'));
                            frag = frag.Trim();
                            if (!string.IsNullOrEmpty(frag) && !token.Contains("#"))
                            {
                                token = token + "#" + frag;
                            }
                        }
                    }
                    catch { }
                }

                if (string.IsNullOrEmpty(token) || token.Length < 16)
                {
                    TxtStatus.Text = "Требуется ключ доступа";
                    TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F85149"));
                    TxtSessionTimer.Text = "Вставьте ссылку aegs:// или токен в настройках";
                    return;
                }

                _serverHost = serverHost;
                _serverPort = serverPort;

                if (TxtFooterServer != null)
                {
                    TxtFooterServer.Text = $"{_serverHost}:{_serverPort}";
                }

                BtnConnect.IsEnabled = false;
                TxtStatus.Text = "Подключение...";
                TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E3B341"));
                TxtSessionTimer.Text = "Установка защищённого соединения...";

                int profile = CmbProfile.SelectedIndex;

                bool success = await _engine.ConnectAsync(_serverHost, _serverPort, token, profile);
                BtnConnect.IsEnabled = true;

                if (!success)
                {
                    TxtStatus.Text = "Ошибка подключения";
                    TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F85149"));
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

                    TxtStatus.Text = "Защита активна";
                    TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3FB950"));
                    TxtSubStatus.Text = $"IP: {_engine.Session?.AssignedIp ?? "10.8.0.2"} • {_serverHost}:{_serverPort}";

                    ShieldCircle.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0D2818"));
                    ShieldCircle.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3FB950"));
                    BtnActionText.Text = "СТОП";
                    BtnActionText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F85149"));
                }
                else
                {
                    _sessionTimer.Stop();

                    TxtStatus.Text = "Готово к подключению";
                    TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E6EDF3"));
                    TxtSubStatus.Text = "TLS 1.3 Reality ECH • 0-RTT";
                    TxtSessionTimer.Text = "Нажмите щит для старта";

                    ShieldCircle.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#111827"));
                    ShieldCircle.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937"));
                    BtnActionText.Text = "СТАРТ";
                    BtnActionText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00F2FE"));

                    TxtRxSpeed.Text = "0.0 КБ/с";
                    TxtTxSpeed.Text = "0.0 КБ/с";
                    TxtPing.Text = "-- мс";
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
                TxtPing.Text = pingMs >= 0 ? $"{pingMs} мс" : "-- мс";
            });
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