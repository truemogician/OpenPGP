using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace Client {
	/// <summary>
	///     Interaction logic for LoginDialog.xaml
	/// </summary>
	public partial class RegisterDialog : Window {
		private bool _canceled;

		public RegisterDialog() {
			InitializeComponent();
		}

		public new static (string Username, string Password)? ShowDialog() {
			var dialog = new RegisterDialog();
			(dialog as Window).ShowDialog();
			return dialog._canceled ? null : (dialog.UsernameTextBox.Text, dialog.PasswordTextBox.Password);
		}

		public new static (string Username, string Password)? Show() {
			var dialog = new RegisterDialog();
			(dialog as Window).Show();
			return dialog._canceled ? null : (dialog.UsernameTextBox.Text, dialog.PasswordTextBox.Password);
		}

		private void TextBoxKeyUp(object sender, KeyEventArgs args) {
			if (args.Key != Key.Enter)
				return;
			if (sender.Equals(UsernameTextBox))
				PasswordTextBox.Focus();
			else if (sender.Equals(PasswordTextBox))
				RepeatPasswordTextBox.Focus();
			else
				ConfirmButtonClick(sender, args);
		}

		private void ConfirmButtonClick(object sender, RoutedEventArgs args) {
			if (PasswordTextBox.Password != RepeatPasswordTextBox.Password) {
				PasswordTextBox.Clear();
				RepeatPasswordTextBox.Clear();
				PasswordTextBox.Background = RepeatPasswordTextBox.Background = Brushes.Coral;
			}
			else
				Close();
		}

		private void CancelButtonClick(object sender, RoutedEventArgs args) {
			_canceled = true;
			Close();
		}

		private void PasswordBoxGotFocus(object sender, RoutedEventArgs args) {
			PasswordTextBox.Background.ClearValue(BackgroundProperty);
			RepeatPasswordTextBox.Background.ClearValue(BackgroundProperty);
		}
	}
}