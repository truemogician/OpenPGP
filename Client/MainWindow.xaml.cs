using System;
using System.IO;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using Core;
using TrueMogician.Exceptions;
using DragDropEffects = System.Windows.DragDropEffects;
using MessageBox = System.Windows.MessageBox;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;
using DragEventArgs = System.Windows.DragEventArgs;

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

		private static SHA256 Hasher { get; } = SHA256.Create();

		private UserCredential? LoggedUser { get; set; }

		private static string GetUserFilePath(string username) => GetUserFilePath(Hasher.ComputeHash(username.ToRawBytes()));

		public static string GetUserFilePath(byte[] hashedUsername) => Path.Combine(UserCredentialDirectory, $"{new BigInteger(hashedUsername):X}.usr");

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

		private void Encrypt(UserCredential user, string[] paths) {
			Task.Run(
				() => {
					Dispatcher.Invoke(() => StatusTextBlock.Text = paths.Length == 1 ? $"开始加密文件/文件夹\"{Path.GetFileName(paths[0])}\"" : $"开始加密\"{Path.GetFileName(paths[0])}\"等{paths.Length}个文件/文件夹");
					string? dstPath = null;
					var startTime = DateTime.Now;
					try {
						dstPath = user.EncryptEntities(paths);
					}
					catch (FileExistedException ex) {
						switch (MessageBox.Show($"加密文件{ex.Path!}已存在，选择“是”进行覆盖，选择“否”另选位置保存，选择“取消”终止操作", "文件冲突", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning)) {
							case MessageBoxResult.Cancel:
								Dispatcher.Invoke(() => StatusTextBlock.Text = "文件加密已取消");
								return;
							case MessageBoxResult.Yes:
								File.Delete(ex.Path!);
								dstPath = user.EncryptEntities(paths);
								break;
							case MessageBoxResult.No:
								_saveDialog.Title = "请选择加密文件的保存路径";
								_saveDialog.AddExtension = true;
								_saveDialog.DefaultExt = ".pgp";
								_saveDialog.FileName = (paths.Length == 1 ? Path.GetFileName(paths[0]) : Path.GetDirectoryName(paths[0])) + ".pgp";
								if (_saveDialog.ShowDialog() != true)
									return;
								startTime = DateTime.Now;
								dstPath = user.EncryptEntities(paths, _saveDialog.FileName);
								break;
						}
					}
					Dispatcher.Invoke(() => StatusTextBlock.Text = $"加密文件{Path.GetFileName(dstPath)}已保存，耗时{(DateTime.Now - startTime).TotalSeconds:F}秒");
				}
			);
		}

		private void Decrypt(UserCredential user, string path) {
			Task.Run(
				() => {
					Dispatcher.Invoke(() => StatusTextBlock.Text = $"开始解密文件{Path.GetFileName(path)}");
					string? dstPath = null;
					var startTime = DateTime.Now;
					try {
						dstPath = user.DecryptEntity(path);
					}
					catch (AuthenticationException) {
						MessageBox.Show("文件并非由该用户加密，无法解密", "认证失败", MessageBoxButton.OK, MessageBoxImage.Error);
					}
					catch (FileExistedException) {
						var result = MessageBox.Show("目标文件夹中部分文件与加密文件冲突，选择“是”进行覆盖，选择“否”跳过，选择“取消”终止操作", "文件冲突", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
						if (result == MessageBoxResult.Cancel) {
							Dispatcher.Invoke(() => StatusTextBlock.Text = "文件解密已取消");
							return;
						}
						startTime = DateTime.Now;
						dstPath = user.DecryptEntity(
							path,
							null,
							result switch {
								MessageBoxResult.Yes => ZipArchiveExtensions.ConflictStrategy.Overwrite,
								MessageBoxResult.No  => ZipArchiveExtensions.ConflictStrategy.Skip,
								_                    => ZipArchiveExtensions.ConflictStrategy.Throw
							}
						);
					}
					Dispatcher.Invoke(() => StatusTextBlock.Text = $"文件已解密到\"{Path.GetFileName(dstPath)}\"，耗时{(DateTime.Now - startTime).TotalSeconds:F}秒");
				}
			);
		}

		private void LoginButtonClick(object sender, RoutedEventArgs args) {
			if (LoginButton.IsChecked == true) {
				LoginButton.IsChecked = false;
				var userInfo = LoginDialog.ShowDialog();
				if (userInfo is null)
					return;
				var user = Login(userInfo.Value.Username, userInfo.Value.Password);
				if (user is not null) {
					LoginButton.IsChecked = true;
					LoggedUser = user;
					LoginButton.ToolTip = $"用户\"{userInfo.Value.Username}\"已登录";
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
				MessageBox.Show($"用户\"{userInfo.Value.Username}\"已存在", "用户已存在", MessageBoxButton.OK, MessageBoxImage.Exclamation);
				return;
			}
			var user = UserCredential.Create(userInfo.Value.Username, userInfo.Value.Password);
			user.Encrypt().Save(path);
			StatusTextBlock.Text = $"用户\"{userInfo.Value.Username}\"已创建";
		}

		private void DeleteUserButtonClick(object sender, RoutedEventArgs args) {
			var username = GetUser()?.Username;
			if (username is null)
				return;
			var confirmed = MessageBox.Show($"确定要删除用户\"{username}\"吗？若之前没有备份用户文件，删除之后所有该用户加密的文件将永远无法再被读取", "警告", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
			if (confirmed == MessageBoxResult.OK) {
				File.Delete(GetUserFilePath(username));
				if (LoggedUser is not null) {
					LoggedUser = null;
					LoginButton.IsChecked = false;
					LoginButton.ToolTip = "登录";
				}
				StatusTextBlock.Text = $"用户\"{username}\"已删除";
			}
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
			catch (InvalidDataException) {
				MessageBox.Show("文件或已损坏", "格式错误", MessageBoxButton.OK, MessageBoxImage.Error);
				return;
			}
			var targetPath = GetUserFilePath(user.HashedUsername);
			if (File.Exists(targetPath)) {
				MessageBox.Show("该用户已存在", "导入冲突", MessageBoxButton.OK, MessageBoxImage.Error);
				return;
			}
			File.Copy(path, targetPath);
			StatusTextBlock.Text = "用户已导入";
		}

		private void ExportUserButtonClick(object sender, RoutedEventArgs args) {
			var username = GetUser()?.Username;
			if (username is null)
				return;
			_saveDialog.Title = "请选择用户文件的导出路径";
			_saveDialog.AddExtension = true;
			_saveDialog.DefaultExt = ".usr";
			_saveDialog.FileName = $"{username}.usr";
			_saveDialog.Filter = "加密用户凭证文件(*.usr)|*.usr";
			if (_saveDialog.ShowDialog() != true)
				return;
			File.Copy(GetUserFilePath(username), _saveDialog.FileName);
			StatusTextBlock.Text = $"用户\"{username}\"已导出";
		}

		private void EncryptFileButtonClick(object sender, RoutedEventArgs args) {
			_openDialog.Title = "请选择需要加密的文件";
			_openDialog.Filter = "所有文件|*.*";
			_openDialog.Multiselect = true;
			_openDialog.CheckPathExists = true;
			_openDialog.CheckFileExists = true;
			if (_openDialog.ShowDialog() != true)
				return;
			var user = GetUser();
			if (user is null)
				return;
			Encrypt(user, _openDialog.FileNames);
		}

		private void EncryptDirectoryButtonClick(object sender, RoutedEventArgs args) {
			_folderDialog.Description = "请选择需要加密的文件夹";
			if (_folderDialog.ShowDialog() == System.Windows.Forms.DialogResult.Cancel)
				return;
			var user = GetUser();
			if (user is null)
				return;
			Encrypt(user, new[] {_folderDialog.SelectedPath});
		}

		private void DecryptFileButtonClick(object sender, RoutedEventArgs args) {
			_openDialog.Title = "请选择需要解密的文件";
			_openDialog.Filter = "PGP加密文件(*.pgp)|*.pgp|所有文件|*.*";
			_openDialog.CheckPathExists = true;
			_openDialog.CheckFileExists = true;
			if (_openDialog.ShowDialog() != true)
				return;
			var user = GetUser();
			if (user is null)
				return;
			Decrypt(user, _openDialog.FileName);
		}

		private void DragDropAreaDragEnter(object sender, DragEventArgs args) {
			string[]? paths = args.GetFileNames();
			if (paths is null) {
				args.Effects = DragDropEffects.None;
				goto End;
			}
			if (sender.Equals(EncryptionArea))
				args.Effects = DragDropEffects.Copy;
			else {
				if (paths.Length == 1 && Path.GetExtension(paths[0]) == ".pgp")
					args.Effects = DragDropEffects.Copy;
				else
					args.Effects = DragDropEffects.None;
			}
		End:
			args.Handled = true;
		}

		private void DragDropAreaDrop(object sender, DragEventArgs args) {
			if (args.Effects.HasFlag(DragDropEffects.Copy) && args.GetFileNames() is { } paths) {
				if (sender.Equals(DecryptionArea) && (paths.Length != 1 || Path.GetExtension(paths[0]) != ".pgp"))
					return;
				var user = GetUser();
				if (user is null)
					return;
				if (sender.Equals(EncryptionArea))
					Encrypt(user, paths);
				else
					Decrypt(user, paths[0]);
			}
		}

		private enum LoginResult : byte {
			Success,

			UserNotFound,

			WrongPassword
		}
	}
}