using System;
using System.IO;
using System.Linq;
using NUnit.Framework;

namespace Core.Test {
	public class EntityEncryptorTests {
		public const string Username = "username";

		public const string Password = "password";

		public static readonly UserCredential User = UserCredential.Create(Username, Password);

		[TestCase("test-file")]
		[TestCase("test-directory")]
		public void EnDecryptTest(string path) {
			string pgpFile = path + ".pgp";
			if (File.Exists(pgpFile))
				File.Delete(pgpFile);
			string pgp = User.EncryptEntities(new[] {path}, pgpFile);
			string dstDirectory = Path.Combine(Path.GetDirectoryName(pgp)!, "result");
			if (Directory.Exists(dstDirectory))
				Directory.Delete(dstDirectory, true);
			try {
				User.DecryptEntity(pgp, dstDirectory);
				string decryptedEntity = Path.Combine(dstDirectory, Path.GetFileName(path));
				Assert.IsTrue(CompareEntities(path, decryptedEntity));
			}
			finally {
				File.Delete(pgpFile);
				Directory.Delete(dstDirectory, true);
			}
		}

		private static bool CompareEntities(string path1, string path2) {
			bool isFile = File.Exists(path1) & File.Exists(path2);
			bool isDirectory = Directory.Exists(path1) && Directory.Exists(path2);
			if (!isFile && !isDirectory)
				return false;
			var (name1, name2) = (Path.GetFileName(path1), Path.GetFileName(path2));
			if (name1 != name2)
				return false;
			if (isFile)
				return File.ReadAllBytes(path1).SequenceEqual(File.ReadAllBytes(path2));
			string[] subEntities1 = Directory.GetFileSystemEntries(path1);
			string[] subEntities2 = Directory.GetFileSystemEntries(path2);
			if (subEntities1.Length != subEntities2.Length)
				return false;
			Array.Sort(subEntities1);
			Array.Sort(subEntities2);
			return !subEntities1.Where((t, i) => !CompareEntities(t, subEntities2[i])).Any();
		}
	}
}