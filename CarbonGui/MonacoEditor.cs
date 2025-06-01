using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Microsoft.Web.WebView2.Wpf;
using System.Text.RegularExpressions;

namespace CarbonGui
{

	class MonacoEditor
    {
        class MonacoFilesChecker
        {
            public void CheckMonacoFiles()
            {
                string basePath = Path.Combine(Directory.GetCurrentDirectory(), MonacoPath);
                CheckFile(basePath, "index.html", "CarbonGui.Resources.index.html");
                CheckFile(basePath, "vs/loader.js", "CarbonGui.Resources.vs.loader.js");
                CheckFile(basePath, "vs/base/worker/workerMain.js", "CarbonGui.Resources.vs.base.worker.workerMain.js");
                CheckFile(basePath, "vs/editor/editor.main.js", "CarbonGui.Resources.vs.editor.editor.main.js");
                CheckFile(basePath, "vs/editor/editor.main.css", "CarbonGui.Resources.vs.editor.editor.main.css");
                CheckFile(basePath, "vs/editor/editor.main.nls.js", "CarbonGui.Resources.vs.editor.editor.main.nls.js");
                CheckFile(basePath, "vs/basic-languages/lua/lua.js", "CarbonGui.Resources.vs.basiclanguages.lua.lua.js");
            }

            public string getIndexPath()
            {
                string basePath = Path.Combine(Directory.GetCurrentDirectory(), MonacoPath);
                string indexPath = Path.Combine(basePath, "index.html");
                return indexPath.Replace('\\', '/');
            }

            private void CheckFile(string basePath, string relativePath, string resourceName)
            {
                string filePath = Path.Combine(basePath, relativePath);
                bool fileExists = File.Exists(filePath);
                bool isDifferent = false;

                Stream resourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
                if (resourceStream == null)
                    throw new FileNotFoundException($"Resource {resourceName} not found.");

                if (fileExists && (CalculateFileHash(filePath) != CalculateStreamHash(resourceStream)))
                    isDifferent = true;

                if (!fileExists || isDifferent)
                {
                    string directory = Path.GetDirectoryName(filePath);
                    if (!Directory.Exists(directory))
                        Directory.CreateDirectory(directory);

                    using (var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                        resourceStream.CopyTo(fileStream);
                }
            }

            private string CalculateFileHash(string filePath)
            {
                using (var md5 = MD5.Create())
                using (var fileStream = File.OpenRead(filePath))
                    return BitConverter.ToString(md5.ComputeHash(fileStream));
            }

            private string CalculateStreamHash(Stream stream)
            {
                using (var md5 = MD5.Create())
                {
                    var originalPosition = stream.Position;
                    stream.Position = 0;
                    string result = BitConverter.ToString(md5.ComputeHash(stream));
                    stream.Position = originalPosition;
                    return result;
                }
            }

            private const string MonacoPath = "bin/monaco";
        }

        public MonacoEditor(WebView2 codeEditor)
        {
            CodeEditor = codeEditor;
            var monacoFiles = new MonacoFilesChecker();
            monacoFiles.CheckMonacoFiles();
            CodeEditor.CoreWebView2.Navigate($"file:///{monacoFiles.getIndexPath()}");
        }

        public void SetEditorContent(string code)
        {
            CodeEditor.CoreWebView2.ExecuteScriptAsync($"setEditorContent({code})");
        }

        public async Task<string> GetEditorContentAsync()
        {
            var jsonString = await CodeEditor.CoreWebView2.ExecuteScriptAsync("getEditorContent()");

            if (jsonString.StartsWith("\"") && jsonString.EndsWith("\""))
                jsonString = jsonString.Substring(1, jsonString.Length - 2);

            return Regex.Unescape(jsonString);
        }

        WebView2 CodeEditor = null;
    }

}
