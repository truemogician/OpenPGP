using System;
using System.IO;
using System.Security.Cryptography;

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

		/// <summary>
		///     Create a new <see cref="UserCredential" />
		/// </summary>
		/// <param name="username">Username</param>
		/// <param name="password">Password</param>
		public static UserCredential Create(string username, string password) => new(username, password, RSA.Create());

		/// <summary>
		///     Encrypt current <see cref="UserCredential" />
		/// </summary>
		/// <inheritdoc cref="UserCredentialEncryptor.Encrypt(UserCredential)" />
		public EncryptedUserCredential Encrypt() => UserCredentialEncryptor.Encrypt(this);
	}

	public class EncryptedUserCredential {
		internal EncryptedUserCredential(byte[] hashedUsername, string encryptedPassword, byte[] encryptedPublicKey, byte[] encryptedPrivateKey) {
			HashedUsername = hashedUsername;
			EncryptedPassword = encryptedPassword;
			EncryptedPublicKey = encryptedPublicKey;
			EncryptedPrivateKey = encryptedPrivateKey;
		}

		public byte[] HashedUsername { get; }

		public string EncryptedPassword { get; }

		public byte[] EncryptedPublicKey { get; }

		public byte[] EncryptedPrivateKey { get; }

		/// <summary>
		///     Create <see cref="EncryptedUserCredential" /> from a file
		/// </summary>
		/// <param name="path">Path of the encrypted user credential file</param>
		/// <exception cref="InvalidDataException" />
		public static EncryptedUserCredential Load(string path) {
			if (!File.Exists(path))
				throw new FileNotFoundException($"User credential file {path} not found");
			using var reader = new FileStream(path, FileMode.Open, FileAccess.Read);
			try {
				var hashedUsername = reader.Read(32);
				byte[] length = new byte[4];
				reader.Read(length, 0, 4);
				var encryptedPassword = reader.Read(BitConverter.ToInt32(length));
				reader.Read(length, 0, 4);
				var encryptedPublicKey = reader.Read(BitConverter.ToInt32(length));
				reader.Read(length, 0, 4);
				var encryptedPrivateKey = reader.Read(BitConverter.ToInt32(length));
				return new EncryptedUserCredential(hashedUsername, encryptedPassword.ToRawString(), encryptedPublicKey, encryptedPrivateKey);
			}
			catch (Exception ex) {
				throw new InvalidDataException($"User credential file {path} is corrupted", ex);
			}
		}

		/// <summary>
		///     Save current <see cref="UserCredential" /> to file
		/// </summary>
		public void Save(string path) {
			using var writer = new FileStream(path, FileMode.Create, FileAccess.Write);
			writer.Write(HashedUsername);
			var passwordBytes = EncryptedPassword.ToRawBytes();
			writer.Write(BitConverter.GetBytes(passwordBytes.Length));
			writer.Write(passwordBytes);
			writer.Write(BitConverter.GetBytes(EncryptedPublicKey.Length));
			writer.Write(EncryptedPublicKey);
			writer.Write(BitConverter.GetBytes(EncryptedPrivateKey.Length));
			writer.Write(EncryptedPrivateKey);
		}

		/// <inheritdoc cref="UserCredentialEncryptor.Decrypt(EncryptedUserCredential, string, string)" />
		public UserCredential? Decrypt(string username, string password) => UserCredentialEncryptor.Decrypt(this, username, password);
	}
}