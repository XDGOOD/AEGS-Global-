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
        private readonly string _serverHost = "31.76.9.86";
        private readonly int _serverPort = 443;

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
                BtnConnect.IsEnabled = false;
                TxtStatus.Text = "Подключение...";
                TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E3B341"));
                TxtSessionTimer.Text = "Установка защищённого соединения...";

                string token = TxtToken.Text.Trim();
                if (string.IsNullOrEmpty(token)) token = "aegs_secure_token_titan_v6";
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
                    TxtSubStatus.Text = $"IP: {_engine.Session?.AssignedIp ?? "10.8.0.2"} • Reality ECH 443";

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
                TxtPing.Text = $"{pingMs} мс";
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