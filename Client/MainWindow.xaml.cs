using System;
using System.IO;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Forms;
using Core;
using TrueMogician.Exceptions;
using MessageBox = System.Windows.MessageBox;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace Client {
	/// <summary>
	///     Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow {
		public const string UserCredentialDirectory = "Users";

		private readonly OpenFileDialog _openDialog = new();

		private readonly SaveFileDialog _saveDialog = new();

		private readonly FolderBrowserDialog _folderDialog = new();

		public MainWindow() {
			InitializeComponent();
			if (!Directory.Exists(UserCredentialDirectory))
				Directory.CreateDirectory(UserCredentialDirectory);
		}

		public static SHA256 Hasher { get; } = SHA256.Create();

		private UserCredential? LoggedUser { get; set; }

		private static string GetUserFilePath(string username) {
			var hashedUsername = Hasher.ComputeHash(username.ToRawBytes()).ToRawString();
			return Path.Combine(UserCredentialDirectory, $"{hashedUsername}.usr");
		}

		private static LoginResult Login(string username, string password, out UserCredential? user) {
			user = null;
			var path = GetUserFilePath(username);
			if (!File.Exists(path))
				return LoginResult.UserNotFound;
			var encryptedUser = EncryptedUserCredential.Load(path);
			user = encryptedUser.Decrypt(username, password);
			return user is null ? LoginResult.WrongPassword : LoginResult.Success;
		}

		private static UserCredential? Login(string username, string password) {
			switch (Login(username, password, out var user)) {
				case LoginResult.Success: return user;
				case LoginResult.UserNotFound:
					MessageBox.Show($"用户{username}不存在", "用户不存在", MessageBoxButton.OK, MessageBoxImage.Exclamation);
					break;
				case LoginResult.WrongPassword:
					MessageBox.Show($"用户密码错误", "密码错误", MessageBoxButton.OK, MessageBoxImage.Error);
					break;
			}
			return null;
		}

		private UserCredential? GetUser() {
			if (LoggedUser is not null)
				return LoggedUser;
			var userInfo = LoginDialog.ShowDialog();
			return userInfo is null
				? null
				: Login(userInfo.Value.Username, userInfo.Value.Password);
		}

		private void Encrypt(UserCredential user, string path) {
			try {
				user.EncryptEntity(path);
			}
			catch (FileExistedException ex) {
				switch (MessageBox.Show($"加密文件{ex.Path!}已存在，选择“是”进行覆盖，选择“否”另选位置保存，选择“取消”终止操作", "文件冲突", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning)) {
					case MessageBoxResult.Cancel: return;
					case MessageBoxResult.Yes:
						File.Delete(ex.Path!);
						user.EncryptEntity(path);
						break;
					case MessageBoxResult.No:
						_saveDialog.Title = "请选择加密文件的保存路径";
						_saveDialog.AddExtension = true;
						_saveDialog.DefaultExt = ".pgp";
						_saveDialog.FileName = $"{Path.GetFileName(path)}.usr";
						if (_saveDialog.ShowDialog() != true)
							return;
						user.EncryptEntity(path, _saveDialog.FileName);
						break;
				}
			}
		}

		private void LoginButtonClick(object sender, RoutedEventArgs args) {
			if (LoginButton.IsChecked == true) {
				var userInfo = LoginDialog.ShowDialog();
				if (userInfo is null) {
					LoginButton.IsChecked = false;
					return;
				}
				var user = Login(userInfo.Value.Username, userInfo.Value.Password);
				if (user is null)
					LoginButton.IsChecked = false;
				else {
					LoggedUser = user;
					LoginButton.ToolTip = $"用户{userInfo.Value.Username}已登录";
				}
			}
			else {
				LoggedUser = null;
				LoginButton.ToolTip = "登录";
			}
		}

		private void CreateUserButtonClick(object sender, RoutedEventArgs args) {
			var userInfo = RegisterDialog.ShowDialog();
			if (userInfo is null)
				return;
			var path = GetUserFilePath(userInfo.Value.Username);
			if (File.Exists(path)) {
				MessageBox.Show($"用户{userInfo.Value.Username}已存在", "用户已存在", MessageBoxButton.OK, MessageBoxImage.Exclamation);
				return;
			}
			var user = UserCredential.Create(userInfo.Value.Username, userInfo.Value.Password);
			user.Encrypt().Save(path);
		}

		private void DeleteUserButtonClick(object sender, RoutedEventArgs args) {
			var username = GetUser()?.Username;
			if (username is null)
				return;
			var confirmed = MessageBox.Show($"确定要删除用户{username}吗？若之前没有备份用户文件，删除之后所有该用户加密的文件将永远无法再被读取", "警告", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
			if (confirmed == MessageBoxResult.OK)
				File.Delete(GetUserFilePath(username));
		}

		private void ImportUserButtonClick(object sender, RoutedEventArgs args) {
			_openDialog.Title = "请选择需要导入的用户文件";
			_openDialog.Filter = "用户文件(*.usr)|*.usr|所有文件|*.*";
			_openDialog.CheckPathExists = true;
			_openDialog.CheckFileExists = true;
			if (_openDialog.ShowDialog() != true)
				return;
			var path = _openDialog.FileName;
			EncryptedUserCredential user;
			try {
				user = EncryptedUserCredential.Load(path);
			}
			catch (FormatException) {
				MessageBox.Show($"文件或已损坏", "格式错误", MessageBoxButton.OK, MessageBoxImage.Error);
				return;
			}
			File.Copy(path, Path.Combine(UserCredentialDirectory, $"{user.HashedUsername}.usr"));
		}

		private void ExportUserButtonClick(object sender, RoutedEventArgs args) {
			var username = GetUser()?.Username;
			if (username is null)
				return;
			_saveDialog.Title = "请选择用户文件的导出路径";
			_saveDialog.AddExtension = true;
			_saveDialog.DefaultExt = ".usr";
			_saveDialog.FileName = $"{username}.usr";
			if (_saveDialog.ShowDialog() != true)
				return;
			File.Copy(GetUserFilePath(username), _saveDialog.FileName);
		}

		private void EncryptFileButtonClick(object sender, RoutedEventArgs args) {
			_openDialog.Title = "请选择需要加密的文件";
			_openDialog.Filter = "所有文件|*.*";
			_openDialog.CheckPathExists = true;
			_openDialog.CheckFileExists = true;
			if (_openDialog.ShowDialog() != true)
				return;
			var path = _openDialog.FileName;
			var user = GetUser();
			if (user is null)
				return;
			Encrypt(user, path);
		}

		private void EncryptDirectoryButtonClick(object sender, RoutedEventArgs args) {
			_folderDialog.Description = "请选择需要加密的文件夹";
			if (_folderDialog.ShowDialog() != System.Windows.Forms.DialogResult.Cancel)
				return;
			var path = _folderDialog.SelectedPath;
			var user = GetUser();
			if (user is null)
				return;
			Encrypt(user, path);
		}

		private void DecryptFileButtonClick(object sender, RoutedEventArgs args) {
			_openDialog.Title = "请选择需要解密的文件";
			_openDialog.Filter = "PGP加密文件(*.pgp)|*.pgp|所有文件|*.*";
			_openDialog.CheckPathExists = true;
			_openDialog.CheckFileExists = true;
			if (_openDialog.ShowDialog() != true)
				return;
			var path = _openDialog.FileName;
			var user = GetUser();
			if (user is null)
				return;
			try {
				user.DecryptEntity(path);
			}
			catch (AuthenticationException) {
				MessageBox.Show($"文件并非由该用户加密，无法解密", "认证失败", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		private enum LoginResult : byte {
			Success,

			UserNotFound,

			WrongPassword
		}
	}
}