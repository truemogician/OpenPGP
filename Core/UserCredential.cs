using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Core {
	public class UserCredential {
		internal UserCredential(string username, string password, byte[] publicKey, byte[] privateKey) {
			Username = username;
			Password = password;
			PublicKey = publicKey;
			PrivateKey = privateKey;
			RSA = RSA.Create();
			RSA.ImportRSAPublicKey(publicKey, out _);
			RSA.ImportRSAPrivateKey(privateKey, out _);
		}

		internal UserCredential(string username, string password, RSA rsa) {
			Username = username;
			Password = password;
			RSA = rsa;
			PublicKey = rsa.ExportRSAPublicKey();
			PrivateKey = rsa.ExportRSAPrivateKey();
		}

		public string Username { get; }

		public string Password { get; }

		public byte[] PublicKey { get; }

		public byte[] PrivateKey { get; }

		public RSA RSA { get; }

		public static UserCredential Create(string username, string password) => new(username, password, RSA.Create());

		public EncryptedUserCredential Encrypt(UserCredentialEncryptor encryptor) => encryptor.Encrypt(this);
	}

	public class EncryptedUserCredential {
		public EncryptedUserCredential(string encryptedUsername, string encryptedPassword, byte[] encryptedPublicKey, byte[] encryptedPrivateKey) {
			EncryptedUsername = encryptedUsername;
			EncryptedPassword = encryptedPassword;
			EncryptedPublicKey = encryptedPublicKey;
			EncryptedPrivateKey = encryptedPrivateKey;
		}

		public string EncryptedUsername { get; }

		public string EncryptedPassword { get; }

		public byte[] EncryptedPublicKey { get; }

		public byte[] EncryptedPrivateKey { get; }

		public static EncryptedUserCredential Load(string path) {
			if (!File.Exists(path))
				throw new FileNotFoundException($"User credential file {path} not found");
			using var reader = new StreamReader(path);
			try {
				return new EncryptedUserCredential(
					reader.ReadLine()!,
					reader.ReadLine()!,
					reader.ReadLine()!.ToRawBytes(),
					reader.ReadLine()!.ToRawBytes()
				);
			}
			catch (Exception ex) {
				throw new FormatException($"User credential file {path} is corrupted", ex);
			}
		}

		public void Save(string path) {
			using var writer = new StreamWriter(path);
			writer.WriteLine(EncryptedUsername);
			writer.WriteLine(EncryptedPassword);
			writer.WriteLine(EncryptedPublicKey);
			writer.WriteLine(EncryptedPrivateKey);
			writer.Close();
		}

		public UserCredential Decrypt(UserCredentialEncryptor decryptor) => decryptor.Decrypt(this);
	}
}
