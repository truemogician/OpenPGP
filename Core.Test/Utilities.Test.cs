using System.Security.Cryptography;
using NUnit.Framework;

namespace Core.Test {
	public class UtilitiesTests {
		public static readonly Aes Aes = Aes.Create();

		[TestCase(@"abcdefg")]
		public void RawStringRawBytesTest(string input) {
			byte[] bytes = input.ToRawBytes();
			string str = bytes.ToRawString();
			Assert.AreEqual(input, str);
		}

		[TestCase(new byte[] {123, 255, 23, 14, 240, 0})]
		public void RawBytesRawStringTest(byte[] input) {
			string str = input.ToRawString();
			byte[] bytes = str.ToRawBytes();
			Assert.AreEqual(input, bytes);
		}

		[TestCase(@"abcd")]
		public void AesExtensionsTest(string text) {
			string cipher = Aes.Encrypt(text);
			Assert.AreEqual(text, Aes.Decrypt(cipher));
		}
	}
}