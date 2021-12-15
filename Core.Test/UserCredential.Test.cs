using System.Security.Cryptography;
using NUnit.Framework;

namespace Core.Test {
	public class UserCredentialTests {
		public static UserCredentialEncryptor Encryptor { get; } = new(Aes.Create());

		[TestCase("username", "password")]
		public void EnDecryptTest(string username, string password) {
			var user = UserCredential.Create(username, password);
			var encryptedUser = user.Encrypt(Encryptor);
			var newUser = encryptedUser.Decrypt(Encryptor);
			Assert.AreEqual(user.Username, newUser.Username);
			Assert.AreEqual(user.Password, newUser.Password);
			Assert.AreEqual(user.PublicKey, newUser.PublicKey);
			Assert.AreEqual(user.PrivateKey, newUser.PrivateKey);
		}
	}
}