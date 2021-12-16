using System.Security.Cryptography;

namespace Core {
	public static class UserCredentialEncryptor {
		public static SHA256 Hasher { get; } = SHA256.Create();

		public static EncryptedUserCredential Encrypt(UserCredential userCredential) {
			byte[] hashedUsername = Hasher.ComputeHash(userCredential.Username.ToRawBytes());
			byte[] hashedPassword = Hasher.ComputeHash(userCredential.Password.ToRawBytes());
			var aes = Aes.Create();
			aes.IV = hashedUsername[..16];
			aes.Key = hashedPassword;
			var encryptor = aes.CreateEncryptor();
			return new EncryptedUserCredential(
				encryptor.Encrypt(userCredential.Username),
				encryptor.Encrypt(userCredential.Password),
				encryptor.Encrypt(userCredential.PublicKey),
				encryptor.Encrypt(userCredential.PrivateKey)
			);
		}

		public static UserCredential? Decrypt(EncryptedUserCredential userCredential, string username, string password) {
			byte[] hashedUsername = Hasher.ComputeHash(username.ToRawBytes());
			byte[] hashedPassword = Hasher.ComputeHash(password.ToRawBytes());
			var aes = Aes.Create();
			aes.IV = hashedUsername[..16];
			aes.Key = hashedPassword;
			var decryptor = aes.CreateDecryptor();
			try {
				string? decryptedUsername = decryptor.Decrypt(userCredential.EncryptedUsername);
				if (username != decryptedUsername)
					return null;
				string? decryptedPassword = decryptor.Decrypt(userCredential.EncryptedPassword);
				if (password != decryptedPassword)
					return null;
			}
			catch (CryptographicException) {
				return null;
			}
			return new UserCredential(
				username,
				password,
				decryptor.Decrypt(userCredential.EncryptedPublicKey),
				decryptor.Decrypt(userCredential.EncryptedPrivateKey)
			);
		}
	}
}