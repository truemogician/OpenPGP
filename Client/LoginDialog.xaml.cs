using System.Windows;
using System.Windows.Input;

namespace Client {
	/// <summary>
	///     Interaction logic for LoginDialog.xaml
	/// </summary>
	public partial class LoginDialog {
		private bool _canceled = true;

		public LoginDialog() {
			InitializeComponent();
			UsernameTextBox.Focus();
		}

		public new static (string Username, string Password)? ShowDialog() {
			var dialog = new LoginDialog();
			(dialog as Window).ShowDialog();
			return dialog._canceled ? null : (dialog.UsernameTextBox.Text, dialog.PasswordTextBox.Password);
		}

		public new static (string Username, string Password)? Show() {
			var dialog = new LoginDialog();
			(dialog as Window).Show();
			return dialog._canceled ? null : (dialog.UsernameTextBox.Text, dialog.PasswordTextBox.Password);
		}

		private void TextBoxKeyUp(object sender, KeyEventArgs args) {
			if (args.Key != Key.Enter)
				return;
			if (sender.Equals(UsernameTextBox))
				PasswordTextBox.Focus();
			else
				ConfirmButtonClick(sender, args);
		}

		private void ConfirmButtonClick(object sender, RoutedEventArgs args) {
			_canceled = false;
			Close();
		}

		private void CancelButtonClick(object sender, RoutedEventArgs args) => Close();
	}
}