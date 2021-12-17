using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using TrueMogician.Exceptions;

namespace Core {
	public static class EntityEncryptor {
		/// <exception cref="FileSystemEntityNotFoundException" />
		/// <exception cref="FileExistedException" />
		public static string EncryptEntities(this UserCredential user, string[] srcPaths, string? dstPath = null) {
			if (srcPaths.Length == 0)
				throw new ArgumentException(null, nameof(srcPaths));
			if (srcPaths.FirstOrDefault(path => !Directory.Exists(path) && !File.Exists(path)) is { } notFoundPath)
				throw new FileSystemEntityNotFoundException(path: notFoundPath);
			dstPath ??= (srcPaths.Length == 1 ? srcPaths[0] : Path.Combine(Path.GetDirectoryName(srcPaths[0])!, Path.GetFileName(Path.GetDirectoryName(srcPaths[0])!))) + ".pgp";
			if (File.Exists(dstPath))
				throw new FileExistedException(path: dstPath);
			string tmpFile;
			do {
				tmpFile = Path.GetRandomFileName();
			} while (File.Exists(tmpFile));
			using (var archive = ZipFile.Open(tmpFile, ZipArchiveMode.Create)) {
				foreach (var path in srcPaths)
					if (File.Exists(path))
						archive.CreateEntryFromFile(path);
					else
						archive.CreateEntryFromDirectory(path);
			}
			var randomAes = Aes.Create();
			using (var writer = new FileStream(dstPath, FileMode.Create, FileAccess.Write)) {
				writer.Write(UserCredentialEncryptor.Hasher.ComputeHash(user.Username.ToRawBytes()));
				byte[] encryptedKey = user.RSA.Encrypt(randomAes.Key, RSAEncryptionPadding.Pkcs1);
				byte[] encryptedIV = user.RSA.Encrypt(randomAes.IV, RSAEncryptionPadding.Pkcs1);
				writer.Write(BitConverter.GetBytes(encryptedKey.Length));
				writer.Write(BitConverter.GetBytes(encryptedIV.Length));
				writer.Write(encryptedKey);
				writer.Write(encryptedIV);
				writer.Write(randomAes.Encrypt(File.ReadAllBytes(tmpFile)));
			}
			File.Delete(tmpFile);
			return dstPath;
		}

		/// <exception cref="FileNotFoundException" />
		/// <exception cref="FileExistedException" />
		/// <exception cref="AuthenticationException" />
		/// <exception cref="InvalidDataException" />
		public static string DecryptEntity(this UserCredential user, string srcPath, string? dstDirectory = null, ConflictStrategy strategy = ConflictStrategy.Throw) {
			if (!File.Exists(srcPath))
				throw new FileNotFoundException($"File {srcPath} not found");
			dstDirectory ??= Path.GetDirectoryName(srcPath)!;
			if (!Directory.Exists(dstDirectory))
				Directory.CreateDirectory(dstDirectory);
			using var reader = new FileStream(srcPath, FileMode.Open, FileAccess.Read);
			var hashedUsername = reader.Read(32);
			if (!hashedUsername.SequenceEqual(UserCredentialEncryptor.Hasher.ComputeHash(user.Username.ToRawBytes())))
				throw new AuthenticationException($"Encrypted file {srcPath} doesn't belongs to user {user.Username}");
			var aes = Aes.Create();
			var keyLength = BitConverter.ToInt32(reader.Read(4));
			var ivLength = BitConverter.ToInt32(reader.Read(4));
			aes.Key = user.RSA.Decrypt(reader.Read(keyLength), RSAEncryptionPadding.Pkcs1);
			aes.IV = user.RSA.Decrypt(reader.Read(ivLength), RSAEncryptionPadding.Pkcs1);
			string tmpFile;
			do {
				tmpFile = Path.GetRandomFileName();
			} while (File.Exists(tmpFile));
			File.WriteAllBytes(tmpFile, aes.Decrypt(reader.ReadBytes()));
			ZipArchive archive;
			try {
				archive = ZipFile.OpenRead(tmpFile);
			}
			catch (InvalidDataException) {
				throw new InvalidDataException($"Encrypted file {srcPath} is corrupted");
			}
			archive.ExtractToDirectory(dstDirectory, strategy);
			archive.Dispose();
			File.Delete(tmpFile);
			return dstDirectory;
		}

		/// <exception cref="FileExistedException" />
		public static void ExtractToDirectory(this ZipArchive archive, string destinationDirectoryName, ConflictStrategy conflictStrategy) {
			var conflictFile = archive.Entries.FirstOrDefault(e => File.Exists(Path.Combine(destinationDirectoryName, e.FullName)));
			bool hasConflict = conflictFile is not null;
			if (hasConflict)
				switch (conflictStrategy) {
					case ConflictStrategy.Abort: return;
					case ConflictStrategy.Throw: throw new FileExistedException(path: conflictFile!.FullName);
				}
			else {
				archive.ExtractToDirectory(destinationDirectoryName);
				return;
			}
			foreach (var entry in archive.Entries) {
				var path = Path.Combine(destinationDirectoryName, entry.FullName);
				if (Path.GetDirectoryName(path) is { } dir && !Directory.Exists(dir))
					Directory.CreateDirectory(dir);
				else if (hasConflict && File.Exists(path))
					switch (conflictStrategy) {
						case ConflictStrategy.Skip: continue;
						case ConflictStrategy.Rename:
							path = GetNonConflictingName(path);
							break;
					}
				if (entry.Name == string.Empty)
					continue;
				entry.ExtractToFile(path, conflictStrategy == ConflictStrategy.Overwrite);
			}
		}

		private static string GetNonConflictingName(string path) {
			if (!File.Exists(path))
				return path;
			string folder = Path.GetDirectoryName(path)!;
			string name = Path.GetFileNameWithoutExtension(path);
			string ext = Path.GetExtension(path);
			for (var i = 1;; ++i) {
				path = Path.Combine(folder, $"{name}({i}){ext}");
				if (!File.Exists(path))
					return path;
			}
		}

		public enum ConflictStrategy : byte {
			Throw,

			Abort,

			Skip,

			Overwrite,

			Rename
		}
	}
}