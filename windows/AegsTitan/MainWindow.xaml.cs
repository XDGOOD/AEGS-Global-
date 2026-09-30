using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Controls;
using AegsTitan.Network;

namespace AegsTitan
{
    public partial class MainWindow : Window
    {
        private readonly TunnelEngine _engine;
        private readonly string _serverHost = "31.76.9.86";
        private readonly int _serverPort = 443;

        public MainWindow()
        {
            InitializeComponent();

            _engine = new TunnelEngine();
            _engine.OnStateChanged += Engine_OnStateChanged;
            _engine.OnMetricsUpdated += Engine_OnMetricsUpdated;
            _engine.OnLog += Engine_OnLog;
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
                TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));

                string token = TxtToken.Text.Trim();
                if (string.IsNullOrEmpty(token)) token = "aegs_secure_token_titan_v6";
                int profile = CmbProfile.SelectedIndex;

                bool success = await _engine.ConnectAsync(_serverHost, _serverPort, token, profile);
                BtnConnect.IsEnabled = true;

                if (!success)
                {
                    TxtStatus.Text = "Ошибка подключения";
                    TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                }
            }
        }

        private void Engine_OnStateChanged(bool isConnected)
        {
            Dispatcher.Invoke(() =>
            {
                if (isConnected)
                {
                    TxtStatus.Text = "Защита активна";
                    TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
                    TxtSubStatus.Text = $"IP: {_engine.Session?.AssignedIp ?? "10.8.0.2"} • Reality ECH 443";

                    var outerGlow = BtnConnect.Template.FindName("OuterGlow", BtnConnect) as Ellipse;
                    var innerCore = BtnConnect.Template.FindName("InnerCore", BtnConnect) as Ellipse;
                    var btnIcon = BtnConnect.Template.FindName("BtnIcon", BtnConnect) as TextBlock;

                    if (outerGlow != null) outerGlow.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
                    if (innerCore != null) innerCore.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#064E3B"));
                    if (btnIcon != null) { btnIcon.Text = "🛡️"; }
                }
                else
                {
                    TxtStatus.Text = "Служба готова к запуску";
                    TxtStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A1A1AA"));
                    TxtSubStatus.Text = "TLS 1.3 Reality ECH • Порт 443";

                    var outerGlow = BtnConnect.Template.FindName("OuterGlow", BtnConnect) as Ellipse;
                    var innerCore = BtnConnect.Template.FindName("InnerCore", BtnConnect) as Ellipse;
                    var btnIcon = BtnConnect.Template.FindName("BtnIcon", BtnConnect) as TextBlock;

                    if (outerGlow != null) outerGlow.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3F3F46"));
                    if (innerCore != null) innerCore.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#18181B"));
                    if (btnIcon != null) { btnIcon.Text = "⚡"; }

                    TxtRxSpeed.Text = "0.0 КБ/с";
                    TxtTxSpeed.Text = "0.0 КБ/с";
                    TxtPing.Text = "-- мс";
                }
            });
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
            _engine.Disconnect();
            base.OnClosed(e);
        }
    }
}