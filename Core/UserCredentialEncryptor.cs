using System.Security.Cryptography;
using System.Text;

namespace Core {
	public class UserCredentialEncryptor {
		public UserCredentialEncryptor(Aes aes) {
			AesEncryptor = aes.CreateEncryptor();
			AesDecryptor = aes.CreateDecryptor();
		}

		public UserCredentialEncryptor(byte[] key, byte[] iv) {
			Aes aes = Aes.Create();
			aes.Key = key;
			aes.IV = iv;
			AesEncryptor = aes.CreateEncryptor();
			AesDecryptor = aes.CreateDecryptor();
		}

		public UserCredentialEncryptor(string key, string iv) : this(key.ToRawBytes(), iv.ToRawBytes()) { }

		public ICryptoTransform AesEncryptor { get; }

		public ICryptoTransform AesDecryptor { get; }

		public SHA256 Hasher { get; } = SHA256.Create();

		public EncryptedUserCredential Encrypt(UserCredential userCredential) {
			byte[] hashedUsername = Hasher.ComputeHash(userCredential.Username.ToRawBytes());
			byte[] hashedPassword = Hasher.ComputeHash(userCredential.Password.ToRawBytes());
			var aes = Aes.Create();
			aes.IV = hashedUsername[..16];
			aes.Key = hashedPassword;
			var encryptor = aes.CreateEncryptor();
			return new EncryptedUserCredential(
				Encrypt(userCredential.Username),
				Encrypt(userCredential.Password),
				encryptor.Encrypt(userCredential.PublicKey),
				encryptor.Encrypt(userCredential.PrivateKey)
			);
		}

		public UserCredential Decrypt(EncryptedUserCredential userCredential) {
			var username = Decrypt(userCredential.EncryptedUsername);
			var password = Decrypt(userCredential.EncryptedPassword);
			byte[] hashedUsername = Hasher.ComputeHash(username.ToRawBytes());
			byte[] hashedPassword = Hasher.ComputeHash(password.ToRawBytes());
			var aes = Aes.Create();
			aes.IV = hashedUsername[..16];
			aes.Key = hashedPassword;
			var decryptor = aes.CreateDecryptor();
			return new UserCredential(
				username,
				password,
				decryptor.Decrypt(userCredential.EncryptedPublicKey),
				decryptor.Decrypt(userCredential.EncryptedPrivateKey)
			);
		}

		private string Encrypt(string plainText) => AesEncryptor.Encrypt(plainText);

		private string Decrypt(string cipherText) => AesDecryptor.Decrypt(cipherText);
	}
}