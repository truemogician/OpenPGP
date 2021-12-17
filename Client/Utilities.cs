using System.Windows;
using DragEventArgs = System.Windows.DragEventArgs;

namespace Client {
	public static class WPFExtensions {
		public static string[]? GetFileNames(this DragEventArgs args) {
			if (!args.Data.GetDataPresent(DataFormats.FileDrop))
				return null;
			return args.Data.GetData(DataFormats.FileDrop) is string[] arr ? arr : null;
		}
	}
}