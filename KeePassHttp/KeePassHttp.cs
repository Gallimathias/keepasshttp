using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net;
using System.Windows.Forms;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;

using KeePass.Plugins;
using KeePass.UI;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Security;

using Newtonsoft.Json;
using KeePass.Util.Spr;
using KeePassLib.Serialization;
using System.Resources;

namespace KeePassHttp
{
    internal delegate void RequestHandler(Request request, Response response, Aes aes);

    public enum CMode { ENCRYPT, DECRYPT }
    public sealed partial class KeePassHttpExt : Plugin
    {
        public const string KEEPASSHTTP_NAME = "KeePassHttp Settings";
        public const string ASSOCIATE_KEY_PREFIX = "AES Key: ";
        public const int DEFAULT_PORT = 19455;
        public const string DEFAULT_HOST = "localhost";

        public override string UpdateUrl => "https://passifox.appspot.com/kph/latest-version.txt";

        /// <summary>
        /// TODO make configurable
        /// </summary>
        private const string HTTP_SCHEME = "http://";
        private const int DEFAULT_NOTIFICATION_TIME = 5000;
        private const string KEEPASSHTTP_GROUP_NAME = "KeePassHttp Passwords";
        //private const string HTTPS_PREFIX = "https://localhost:";
        //private const int HTTPS_PORT = DEFAULT_PORT + 1;

        /// <summary>
        /// an arbitrarily generated uuid for the keepasshttp root entry
        /// </summary>
        public readonly byte[] KEEPASSHTTP_UUID = {
                0x34, 0x69, 0x7a, 0x40, 0x8a, 0x5b, 0x41, 0xc0,
                0x9f, 0x36, 0x89, 0x7d, 0x62, 0x3e, 0xcb, 0x31
                                                };


        private IPluginHost host;
        private HttpListener listener;

        private Thread httpThread;
        private volatile bool stopped;
        private Dictionary<string, RequestHandler> handlers;

        public KeePassHttpExt() : base()
        {
            stopped = false;
            handlers = new Dictionary<string, RequestHandler>();
        }

        //public string UpdateUrl = "";

        public override void Terminate()
        {
            stopped = true;
            listener.Stop();
            listener.Close();
            httpThread.Interrupt();
        }

        internal string[] GetUserPass(PwEntry entry) => GetUserPass(new PwEntryDatabase(entry, host.Database));

        internal string[] GetUserPass(PwEntryDatabase entryDatabase) =>
            // follow references
            GetUserPass(entryDatabase, new SprContext(entryDatabase.Entry, entryDatabase.Database,
                    SprCompileFlags.All, false, false));

        internal string[] GetUserPass(PwEntryDatabase entryDatabase, SprContext ctx)
        {
            void f() =>
                // apparently, SprEngine.Compile might modify the database
                host.MainWindow.UpdateUI(false, null, false, null, false, null, false);

            if (host.MainWindow.InvokeRequired)
                host.MainWindow.Invoke(new MethodInvoker(f));
            else
                f();

            return new string[] {
                SprEngine.Compile(entryDatabase.Entry.Strings.ReadSafe(PwDefs.UserNameField), ctx),
                SprEngine.Compile(entryDatabase.Entry.Strings.ReadSafe(PwDefs.PasswordField), ctx) };
        }

        private SearchParameters MakeSearchParameters() => new SearchParameters
        {
            SearchInTitles = true,
            RegularExpression = true,
            SearchInGroupNames = false,
            SearchInNotes = false,
            SearchInOther = false,
            SearchInPasswords = false,
            SearchInTags = false,
            SearchInUrls = true,
            SearchInUserNames = false,
            SearchInUuids = false
        };

        private string CryptoTransform(string input, bool base64in, bool base64out, Aes cipher, CMode mode)
        {
            byte[] bytes;

            if (base64in)
                bytes = Decode64(input);
            else
                bytes = Encoding.UTF8.GetBytes(input);


            using (var c = mode == CMode.ENCRYPT ? cipher.CreateEncryptor() : cipher.CreateDecryptor())
            {
                var buf = c.TransformFinalBlock(bytes, 0, bytes.Length);
                return base64out ? Encode64(buf) : Encoding.UTF8.GetString(buf);
            }
        }

        private PwEntry GetConfigEntry(bool create)
        {
            var root = host.Database.RootGroup;
            var uuid = new PwUuid(KEEPASSHTTP_UUID);
            var entry = root.FindEntry(uuid, false);

            if (entry == null && create)
            {
                entry = new PwEntry(false, true)
                {
                    Uuid = uuid
                };

                entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, KEEPASSHTTP_NAME));
                root.AddEntry(entry, true);
                UpdateUI(null);
            }
            return entry;
        }

        private int GetNotificationTime()
        {
            var time = DEFAULT_NOTIFICATION_TIME;
            var entry = GetConfigEntry(false);
            if (entry != null)
            {
                var s = entry.Strings.ReadSafe("Prompt Timeout");
                if (s != null && s.Trim() != "")
                {
                    try
                    {
                        time = Int32.Parse(s) * 1000;
                    }
                    catch { }
                }
            }

            return time;
        }

        private void ShowNotification(string text) => ShowNotification(text, null, null);

        private void ShowNotification(string text, EventHandler onclick) => ShowNotification(text, onclick, null);

        private void ShowNotification(string text, EventHandler onclick, EventHandler onclose)
        {
            void notificate()
            {
                var notify = host.MainWindow.MainNotifyIcon;
                if (notify == null)
                    return;

                EventHandler clicked = null;
                EventHandler closed = null;

                clicked = delegate
                {
                    notify.BalloonTipClicked -= clicked;
                    notify.BalloonTipClosed -= closed;
                    onclick?.Invoke(notify, null);
                };
                closed = delegate
                {
                    notify.BalloonTipClicked -= clicked;
                    notify.BalloonTipClosed -= closed;
                    onclose?.Invoke(notify, null);
                };

                //notify.BalloonTipIcon = ToolTipIcon.Info;
                notify.BalloonTipTitle = "KeePassHttp";
                notify.BalloonTipText = text;
                notify.ShowBalloonTip(GetNotificationTime());
                // need to add listeners after showing, or closed is sent right away
                notify.BalloonTipClosed += closed;
                notify.BalloonTipClicked += clicked;
            }

            if (host.MainWindow.InvokeRequired)
                host.MainWindow.Invoke(new MethodInvoker(notificate));
            else
                notificate();
        }

        public override bool Initialize(IPluginHost host)
        {
            var httpSupported = HttpListener.IsSupported;
            this.host = host;

            var optionsMenu = new ToolStripMenuItem("KeePassHttp Options...");
            optionsMenu.Click += OnOptionsClick;
            optionsMenu.Image = Properties.Resources.earth_lock;
            //optionsMenu.Image = global::KeePass.Properties.Resources.B16x16_File_Close;
            this.host.MainWindow.ToolsMenu.DropDownItems.Add(optionsMenu);

            if (httpSupported)
            {
                try
                {
                    handlers.Add(Request.TEST_ASSOCIATE, TestAssociateHandler);
                    handlers.Add(Request.ASSOCIATE, AssociateHandler);
                    handlers.Add(Request.GET_LOGINS, GetLoginsHandler);
                    handlers.Add(Request.GET_LOGINS_COUNT, GetLoginsCountHandler);
                    handlers.Add(Request.GET_ALL_LOGINS, GetAllLoginsHandler);
                    handlers.Add(Request.SET_LOGIN, SetLoginHandler);
                    handlers.Add(Request.GENERATE_PASSWORD, GeneratePassword);

                    listener = new HttpListener();

                    var configOpt = new ConfigOpt(this.host.CustomConfig);

                    listener.Prefixes.Add(HTTP_SCHEME + configOpt.ListenerHost + ":" + configOpt.ListenerPort.ToString() + "/");
                    //listener.Prefixes.Add(HTTPS_PREFIX + HTTPS_PORT + "/");
                    listener.Start();

                    httpThread = new Thread(new ThreadStart(Run));
                    httpThread.Start();
                }
                catch (HttpListenerException e)
                {
                    MessageBox.Show(host.MainWindow,
                        "Unable to start HttpListener!\nDo you really have only one installation of KeePassHttp in your KeePass-directory?\n\n" + e,
                        "Unable to start HttpListener",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                }
            }
            else
            {
                MessageBox.Show(host.MainWindow, "The .NET HttpListener is not supported on your OS",
                        ".NET HttpListener not supported",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
            }
            return httpSupported;
        }

        private void OnOptionsClick(object sender, EventArgs e) => UIUtil.ShowDialogAndDestroy(new OptionsForm(new ConfigOpt(host.CustomConfig)));

        private void Run()
        {
            while (!stopped)
            {
                try
                {
                    var r = listener.BeginGetContext(new AsyncCallback(RequestHandler), listener);
                    r.AsyncWaitHandle.WaitOne();
                    r.AsyncWaitHandle.Close();
                }
                catch (ThreadInterruptedException) { }
                catch (HttpListenerException e)
                {
                    MessageBox.Show(host.MainWindow, "Unable to process request!\n\n" + e,
                        "Unable to process request",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                }
            }
        }

        private JsonSerializer NewJsonSerializer() => JsonSerializer.Create(new JsonSerializerSettings
        {
            DefaultValueHandling = DefaultValueHandling.Ignore,
            NullValueHandling = NullValueHandling.Ignore
        });

        private Response ProcessRequest(Request r, HttpListenerResponse resp)
        {
            string hash = host.Database.RootGroup.Uuid.ToHexString() + host.Database.RecycleBinUuid.ToHexString();
            hash = GetSHA1(hash);

            var response = new Response(r.RequestType, hash);

            using (var aes = new AesManaged())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                var handler = handlers[r.RequestType];
                if (handler != null)
                {
                    try
                    {
                        handler(r, response, aes);
                    }
                    catch (Exception e)
                    {
                        ShowNotification("***BUG*** " + e, (s, evt) => MessageBox.Show(host.MainWindow, e + ""));
                        response.Error = e + "";
                        resp.StatusCode = (int)HttpStatusCode.BadRequest;
                    }
                }
                else
                {
                    response.Error = "Unknown command: " + r.RequestType;
                    resp.StatusCode = (int)HttpStatusCode.BadRequest;
                }
            }

            return response;
        }

        private void RequestHandler(IAsyncResult r)
        {
            try
            {
                LocalRequestHandler(r);
            }
            catch (Exception e)
            {
                MessageBox.Show(host.MainWindow, "RequestHandler failed: " + e);
            }
        }

        private void LocalRequestHandler(IAsyncResult r)
        {
            if (stopped)
                return;

            var l = (HttpListener)r.AsyncState;
            var ctx = l.EndGetContext(r);
            var req = ctx.Request;
            var resp = ctx.Response;

            var serializer = NewJsonSerializer();
            Request request = null;

            resp.StatusCode = (int)HttpStatusCode.OK;
            using (var ins = new JsonTextReader(new StreamReader(req.InputStream)))
            {
                try
                {
                    request = serializer.Deserialize<Request>(ins);
                }
                catch (JsonSerializationException e)
                {
                    var buffer = Encoding.UTF8.GetBytes(e + "");
                    resp.StatusCode = (int)HttpStatusCode.BadRequest;
                    resp.ContentLength64 = buffer.Length;
                    resp.OutputStream.Write(buffer, 0, buffer.Length);
                } // ignore, bad request
            }

            var db = host.Database;

            if (request != null && (new ConfigOpt(host.CustomConfig).UnlockDatabaseRequest || request.TriggerUnlock == "true") && !db.IsOpen)
            {
                host.MainWindow.Invoke(new MethodInvoker(() => host.MainWindow.EnsureVisibleForegroundWindow(true, true)));

                // UnlockDialog not already opened
                bool bNoDialogOpened = (GlobalWindowManager.WindowCount == 0);

                if (!db.IsOpen && bNoDialogOpened)
                    host.MainWindow.Invoke(new MethodInvoker(() =>
                        host.MainWindow.OpenDatabase(host.MainWindow.DocumentManager.ActiveDocument.LockedIoc, null, false)));
            }

            if (request != null && db.IsOpen)
            {
                Response response = null;

                if (request != null)
                    response = ProcessRequest(request, resp);

                resp.ContentType = "application/json";

                if (response != null)
                {
                    using (var writer = new StringWriter())
                    {
                        serializer.Serialize(writer, response);
                        var buffer = Encoding.UTF8.GetBytes(writer.ToString());
                        resp.ContentLength64 = buffer.Length;
                        resp.OutputStream.Write(buffer, 0, buffer.Length);
                    }
                }
            }
            else
            {
                resp.StatusCode = (int)HttpStatusCode.ServiceUnavailable;
            }

            var outs = resp.OutputStream;
            outs.Close();
            resp.Close();
        }
        
        private void UpdateUI(PwGroup group)
        {
            var win = host.MainWindow;

            if (group == null)
                group = host.Database.RootGroup;

            void f() => win.UpdateUI(false, null, true, group, true, null, true);

            if (win.InvokeRequired)
                win.Invoke(new MethodInvoker(f));
            else
                f();
        }
        
        /// <summary>
        /// Liefert den SHA1 Hash 
        /// </summary>
        /// <param name="input">Eingabestring</param>
        /// <returns>SHA1 Hash der Eingabestrings</returns>
        private string GetSHA1(string input)
        {
            //Umwandlung des Eingastring in den SHA1 Hash
            using (var sha1 = new SHA1CryptoServiceProvider())
                return string.Concat(sha1.ComputeHash(Encoding.Default.GetBytes(input)).Select(x => x.ToString("X2"))).ToLower();
        }
    }
}
