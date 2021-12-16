using NUnit.Framework;

namespace Core.Test {
	public class UserCredentialTests {
		[TestCase("username", "password")]
		public void EnDecryptTest(string username, string password) {
			var user = UserCredential.Create(username, password);
			var encryptedUser = user.Encrypt();
			var decryptedUser = encryptedUser.Decrypt(username, "wrong" + password);
			Assert.IsNull(decryptedUser);
			decryptedUser = encryptedUser.Decrypt(username, password);
			Assert.IsNotNull(decryptedUser);
			Assert.AreEqual(user.Username, decryptedUser.Username);
			Assert.AreEqual(user.Password, decryptedUser.Password);
			Assert.AreEqual(user.PublicKey, decryptedUser.PublicKey);
			Assert.AreEqual(user.PrivateKey, decryptedUser.PrivateKey);
		}
	}
}