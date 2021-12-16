using System.IO;
using System.Reflection;
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

		[TestCase("username", "password")]
		public void SaveLoadTest(string username, string password) {
			const string tmpPath = @"tmp.usr";
			var user = UserCredential.Create(username, password);
			var encrypted = user.Encrypt();
			try {
				encrypted.Save(tmpPath);
				var loaded = EncryptedUserCredential.Load(tmpPath);
				foreach (var property in typeof(EncryptedUserCredential).GetProperties(BindingFlags.Public | BindingFlags.Instance))
					Assert.AreEqual(property.GetValue(encrypted), property.GetValue(loaded));
			}
			finally {
				File.Delete(tmpPath);
			}
		}
	}
}