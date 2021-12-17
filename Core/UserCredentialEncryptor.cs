using System.Linq;
using System.Security.Cryptography;

namespace Core {
	public static class UserCredentialEncryptor {
		public static SHA256 Hasher { get; } = SHA256.Create();

		/// <summary>
		///     Encrypt <paramref name="userCredential" />
		/// </summary>
		/// <returns>Encrypted user credential</returns>
		public static EncryptedUserCredential Encrypt(UserCredential userCredential) {
			byte[] hashedUsername = Hasher.ComputeHash(userCredential.Username.ToRawBytes());
			byte[] hashedPassword = Hasher.ComputeHash(userCredential.Password.ToRawBytes());
			var aes = Aes.Create();
			aes.IV = hashedUsername[..16];
			aes.Key = hashedPassword;
			var encryptor = aes.CreateEncryptor();
			return new EncryptedUserCredential(
				hashedUsername,
				encryptor.Encrypt(userCredential.Password),
				encryptor.Encrypt(userCredential.PublicKey),
				encryptor.Encrypt(userCredential.PrivateKey)
			);
		}

		/// <summary>
		///     Decrypt <paramref name="userCredential" /> with <paramref name="username" /> and <paramref name="password" />
		///     provided
		/// </summary>
		/// <returns>
		///     <see cref="UserCredential" /> if <paramref name="username" /> and <paramref name="password" /> are correct,
		///     else <see langword="null" />
		/// </returns>
		public static UserCredential? Decrypt(EncryptedUserCredential userCredential, string username, string password) {
			byte[] hashedUsername = Hasher.ComputeHash(username.ToRawBytes());
			if (!userCredential.HashedUsername.SequenceEqual(hashedUsername))
				return null;
			byte[] hashedPassword = Hasher.ComputeHash(password.ToRawBytes());
			var aes = Aes.Create();
			aes.IV = hashedUsername[..16];
			aes.Key = hashedPassword;
			var decryptor = aes.CreateDecryptor();
			try {
				string decryptedPassword = decryptor.Decrypt(userCredential.EncryptedPassword);
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