using System.Windows;

namespace ModernSign
{
    public partial class PinPromptWindow : Window
    {
        public string Pin { get; private set; }
        public PinPromptWindow()
        {
            InitializeComponent();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            Pin = PinPasswordBox.Password;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}