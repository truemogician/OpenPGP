using System.IO;
using System.Windows;

namespace Client {
	/// <summary>
	///     Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window {
		public const string UserCredentialDirectory = "Users";

		public MainWindow() {
			InitializeComponent();
			if (!Directory.Exists(UserCredentialDirectory))
				Directory.CreateDirectory(UserCredentialDirectory);
		}

		private void CreateUserButtonClick(object sender, RoutedEventArgs args) { }
	}
}