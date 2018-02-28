using System.Security.Cryptography;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System;
using System.Threading;

using KeePass.Plugins;
using KeePassLib.Collections;
using KeePassLib.Security;
using KeePassLib.Utility;
using KeePassLib;

using Newtonsoft.Json;
using Microsoft.Win32;
using KeePass.UI;
using KeePass;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Cryptography;
using KeePass.Util.Spr;
using KeePass.Forms;

namespace KeePassHttp
{
    public sealed partial class KeePassHttpExt : Plugin
    {
        private string GetHost(string uri)
        {
            var host = uri;
            try
            {
                var url = new Uri(uri);
                host = url.Host;

                if (!url.IsDefaultPort)
                {
                    host += ":" + url.Port.ToString();
                }
            }
            catch
            {
                // ignore exception, not a URI, assume input is host
            }
            return host;
        }

        private string GetScheme(string uri)
        {
            var scheme = "";
            try
            {
                var url = new Uri(uri);
                scheme = url.Scheme;
            }
            catch
            {
                // ignore exception, not a URI, assume input is host
            }
            return scheme;
        }

        private bool CanShowBalloonTips()
        {
            // tray icon is not visible --> no balloon tips for it
            if (Program.Config.UI.TrayIcon.ShowOnlyIfTrayed && !host.MainWindow.IsTrayed())
                return false;

            // only use balloon tips on windows machines
            if (Environment.OSVersion.Platform == PlatformID.Win32NT || Environment.OSVersion.Platform == PlatformID.Win32S || Environment.OSVersion.Platform == PlatformID.Win32Windows)
            {
                int enabledBalloonTipsMachine = (int)Registry.GetValue("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                        "EnableBalloonTips",
                        1);
                int enabledBalloonTipsUser = (int)Registry.GetValue("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                     "EnableBalloonTips",
                     1);
                return (enabledBalloonTipsMachine == 1 && enabledBalloonTipsUser == 1);
            }

            return false;
        }

        private void GetAllLoginsHandler(Request request, Response response, Aes aes)
        {
            if (!VerifyRequest(request, aes))
                return;

            var list = new PwObjectList<PwEntry>();
            var root = host.Database.RootGroup;
            var parms = MakeSearchParameters();

            parms.SearchString = @"^[A-Za-z0-9:/-]+\.[A-Za-z0-9:/-]+$"; // match anything looking like a domain or url

            root.SearchEntries(parms, list);

            foreach (var entry in list)
                response.Entries.Add(
                    new ResponseEntry(entry.Strings.ReadSafe(PwDefs.TitleField), GetUserPass(entry)[0], null, entry.Uuid.ToHexString(), null));

            response.Success = true;
            response.Id = request.Id;
            SetResponseVerifier(response, aes);

            foreach (var entry in response.Entries)
            {
                entry.Name = CryptoTransform(entry.Name, false, true, aes, CMode.ENCRYPT);
                entry.Login = CryptoTransform(entry.Login, false, true, aes, CMode.ENCRYPT);
                entry.Uuid = CryptoTransform(entry.Uuid, false, true, aes, CMode.ENCRYPT);
            }
        }

        private IEnumerable<PwEntryDatabase> FindMatchingEntries(Request request, Aes aes)
        {
            string submitHost = null;
            string realm = null;
            var listResult = new List<PwEntryDatabase>();
            var url = CryptoTransform(request.Url, true, false, aes, CMode.DECRYPT);
            string formHost, searchHost;
            formHost = searchHost = GetHost(url);
            string hostScheme = GetScheme(url);

            if (request.SubmitUrl != null)
                submitHost = GetHost(CryptoTransform(request.SubmitUrl, true, false, aes, CMode.DECRYPT));

            if (request.Realm != null)
                realm = CryptoTransform(request.Realm, true, false, aes, CMode.DECRYPT);

            var origSearchHost = searchHost;
            var parms = MakeSearchParameters();

            List<PwDatabase> listDatabases = new List<PwDatabase>();

            var configOpt = new ConfigOpt(host.CustomConfig);

            if (configOpt.SearchInAllOpenedDatabases)
            {
                foreach (PwDocument doc in host.MainWindow.DocumentManager.Documents)
                {
                    if (doc.Database.IsOpen)
                        listDatabases.Add(doc.Database);
                }
            }
            else
            {
                listDatabases.Add(host.Database);
            }

            int listCount = 0;

            foreach (PwDatabase db in listDatabases)
            {
                searchHost = origSearchHost;
                //get all possible entries for given host-name
                while (listResult.Count == listCount && (origSearchHost == searchHost || searchHost.IndexOf(".") != -1))
                {
                    parms.SearchString = string.Format("^{0}$|/{0}/?", searchHost);
                    var listEntries = new PwObjectList<PwEntry>();
                    db.RootGroup.SearchEntries(parms, listEntries);

                    foreach (var le in listEntries)
                        listResult.Add(new PwEntryDatabase(le, db));

                    searchHost = searchHost.Substring(searchHost.IndexOf(".") + 1);

                    //searchHost contains no dot --> prevent possible infinite loop
                    if (searchHost == origSearchHost)
                        break;
                }

                listCount = listResult.Count;
            }

            bool hideExpired(PwEntry e)
            {
                DateTime dtNow = DateTime.UtcNow;

                if (e.Expires && (e.ExpiryTime <= dtNow))
                {
                    return false;
                }

                return true;
            }

            if (configOpt.MatchSchemes)
                return listResult.Where(e => GetFilterShemes(e.Entry, hostScheme));
            else if (configOpt.HideExpired)
                return listResult.Where(e => hideExpired(e.Entry));
            else
                return listResult.Where(e => GetFilter(e.Entry, submitHost, realm, formHost));
        }

        private bool GetFilterShemes(PwEntry e, string hostScheme)
        {
            var title = e.Strings.ReadSafe(PwDefs.TitleField);
            var entryUrl = e.Strings.ReadSafe(PwDefs.UrlField);

            if (entryUrl != null)
            {
                var entryScheme = GetScheme(entryUrl);

                if (entryScheme == hostScheme)
                    return true;
            }

            return GetScheme(title) == hostScheme;
        }

        private bool GetFilter(PwEntry e, string submitHost, string realm, string formHost)
        {
            var title = e.Strings.ReadSafe(PwDefs.TitleField);
            var entryUrl = e.Strings.ReadSafe(PwDefs.UrlField);

            var c = GetEntryConfig(e);

            if (c != null)
            {
                if (c.Allow.Contains(formHost) && (submitHost == null || c.Allow.Contains(submitHost)))
                    return true;

                if (c.Deny.Contains(formHost) || (submitHost != null && c.Deny.Contains(submitHost)))
                    return false;

                if (realm != null && c.Realm != realm)
                    return false;
            }

            if (entryUrl != null &&
                (entryUrl.StartsWith("http://") ||
                entryUrl.StartsWith("https://") ||
                title.StartsWith("ftp://") ||
                title.StartsWith("sftp://")))
            {
                if (formHost.EndsWith(GetHost(entryUrl)))
                    return true;
            }

            if (title.StartsWith("http://") ||
                title.StartsWith("https://") ||
                title.StartsWith("ftp://") ||
                title.StartsWith("sftp://"))
            {
                if (formHost.EndsWith(GetHost(title)))
                    return true;
            }

            return formHost.Contains(title) || (entryUrl != null && formHost.Contains(entryUrl));
        }

        private void GetLoginsCountHandler(Request request, Response response, Aes aes)
        {
            if (!VerifyRequest(request, aes))
                return;

            response.Success = true;
            response.Id = request.Id;
            SetResponseVerifier(response, aes);
            response.Count = FindMatchingEntries(request, aes).ToList().Count;
        }

        private void GetLoginsHandler(Request request, Response response, Aes aes)
        {
            if (!VerifyRequest(request, aes))
                return;

            string submithost = null;
            var host = GetHost(CryptoTransform(request.Url, true, false, aes, CMode.DECRYPT));

            if (request.SubmitUrl != null)
                submithost = GetHost(CryptoTransform(request.SubmitUrl, true, false, aes, CMode.DECRYPT));

            var items = FindMatchingEntries(request, aes);
            if (items.ToList().Count > 0)
            {
                bool filter(PwEntry e)
                {
                    var c = GetEntryConfig(e);

                    var title = e.Strings.ReadSafe(PwDefs.TitleField);
                    var entryUrl = e.Strings.ReadSafe(PwDefs.UrlField);

                    if (c != null)
                        return title != host && entryUrl != host && !c.Allow.Contains(host) ||
                            (submithost != null && !c.Allow.Contains(submithost) && submithost != title && submithost != entryUrl);

                    return title != host && entryUrl != host ||
                        (submithost != null && title != submithost && entryUrl != submithost);
                };

                var configOpt = new ConfigOpt(this.host.CustomConfig);
                var config = GetConfigEntry(true);
                var autoAllowS = config.Strings.ReadSafe("Auto Allow");
                var autoAllow = autoAllowS != null && autoAllowS.Trim() != "";
                autoAllow = autoAllow || configOpt.AlwaysAllowAccess;
                var needPrompting = from e in items where filter(e.Entry) select e;

                if (needPrompting.ToList().Count > 0 && !autoAllow)
                {
                    var win = this.host.MainWindow;

                    using (var f = new AccessControlForm())
                    {
                        win.Invoke((MethodInvoker)delegate
                        {
                            f.Icon = win.Icon;
                            f.Plugin = this;
                            f.Entries = items.Where(e => filter(e.Entry)).Select(e => e.Entry).ToList();
                            //f.Entries = needPrompting.ToList();
                            f.StartPosition = win.Visible ? FormStartPosition.CenterParent : FormStartPosition.CenterScreen;
                            f.Host = submithost ?? host;
                            f.Load += (s, e) => f.Activate();
                            f.ShowDialog(win);

                            if (f.Remember && (f.Allowed || f.Denied))
                            {
                                foreach (var e in needPrompting)
                                {
                                    var c = GetEntryConfig(e.Entry);

                                    if (c == null)
                                        c = new KeePassHttpEntryConfig();

                                    var set = f.Allowed ? c.Allow : c.Deny;
                                    set.Add(host);

                                    if (submithost != null && submithost != host)
                                        set.Add(submithost);

                                    SetEntryConfig(e.Entry, c);

                                }
                            }
                            if (!f.Allowed)
                            {
                                items = items.Except(needPrompting);
                            }
                        });
                    }
                }

                string compareToUrl = null;

                if (request.SubmitUrl != null)
                    compareToUrl = CryptoTransform(request.SubmitUrl, true, false, aes, CMode.DECRYPT);

                if (String.IsNullOrEmpty(compareToUrl))
                    compareToUrl = CryptoTransform(request.Url, true, false, aes, CMode.DECRYPT);

                compareToUrl = compareToUrl.ToLower();

                foreach (var entryDatabase in items)
                {
                    string entryUrl = string.Copy(entryDatabase.Entry.Strings.ReadSafe(PwDefs.UrlField));

                    if (string.IsNullOrWhiteSpace(entryUrl))
                        entryUrl = entryDatabase.Entry.Strings.ReadSafe(PwDefs.TitleField);

                    entryUrl = entryUrl.ToLower();

                    entryDatabase.Entry.UsageCount = (ulong)LevenshteinDistance(compareToUrl, entryUrl);

                }

                var itemsList = items.ToList();

                if (configOpt.SpecificMatchingOnly)
                {
                    ulong lowestDistance = itemsList.Count > 0 ? itemsList.Min(e => e.Entry.UsageCount) : 0;

                    itemsList = itemsList.Where(e => e.Entry.UsageCount == lowestDistance).ToList();
                }

                if (configOpt.SortResultByUsername)
                    itemsList = itemsList.OrderBy(e => e.Entry.UsageCount).ThenBy(e => GetUserPass(e)[0]).ToList();
                else
                    itemsList = itemsList.OrderBy(e => e.Entry.UsageCount).ThenBy(e => e.Entry.Strings.ReadSafe(PwDefs.TitleField)).ToList();

                foreach (var entryDatabase in itemsList)
                {
                    var e = PrepareElementForResponseEntries(configOpt, entryDatabase);
                    response.Entries.Add(e);
                }

                if (itemsList.Count > 0)
                    if (configOpt.ReceiveCredentialNotification)
                        ShowNotification(String.Format("{0}: {1} is receiving credentials for:\n    {2}", request.Id, host, string.Join(
                            "\n    ", response.Entries.Select(e => e.Name).Distinct())));


                response.Success = true;
                response.Id = request.Id;
                SetResponseVerifier(response, aes);

                foreach (var entry in response.Entries)
                {
                    entry.Name = CryptoTransform(entry.Name, false, true, aes, CMode.ENCRYPT);
                    entry.Login = CryptoTransform(entry.Login, false, true, aes, CMode.ENCRYPT);
                    entry.Uuid = CryptoTransform(entry.Uuid, false, true, aes, CMode.ENCRYPT);
                    entry.Password = CryptoTransform(entry.Password, false, true, aes, CMode.ENCRYPT);

                    if (entry.StringFields != null)
                    {
                        foreach (var sf in entry.StringFields)
                        {
                            sf.Key = CryptoTransform(sf.Key, false, true, aes, CMode.ENCRYPT);
                            sf.Value = CryptoTransform(sf.Value, false, true, aes, CMode.ENCRYPT);
                        }
                    }
                }

                response.Count = response.Entries.Count;
            }
            else
            {
                response.Success = true;
                response.Id = request.Id;
                SetResponseVerifier(response, aes);
            }
        }
        //http://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Levenshtein_distance#C.23
        private int LevenshteinDistance(string source, string target)
        {
            if (string.IsNullOrEmpty(source))
            {
                if (string.IsNullOrEmpty(target))
                    return 0;

                return target.Length;
            }

            if (string.IsNullOrEmpty(target))
                return source.Length;

            if (source.Length > target.Length)
            {
                var temp = target;
                target = source;
                source = temp;
            }

            var m = target.Length;
            var n = source.Length;
            var distance = new int[2, m + 1];
            // Initialize the distance 'matrix'
            for (var j = 1; j <= m; j++)
                distance[0, j] = j;

            var currentRow = 0;
            for (var i = 1; i <= n; ++i)
            {
                currentRow = i & 1;
                distance[currentRow, 0] = i;
                var previousRow = currentRow ^ 1;
                for (var j = 1; j <= m; j++)
                {
                    var cost = target[j - 1] == source[i - 1] ? 0 : 1;
                    distance[currentRow, j] = Math.Min(Math.Min(
                                            distance[previousRow, j] + 1,
                                            distance[currentRow, j - 1] + 1),
                                            distance[previousRow, j - 1] + cost);
                }
            }

            return distance[currentRow, m];
        }

        private ResponseEntry PrepareElementForResponseEntries(ConfigOpt configOpt, PwEntryDatabase entryDatabase)
        {
            SprContext ctx = new SprContext(entryDatabase.Entry, entryDatabase.Database, SprCompileFlags.All, false, false);

            var name = entryDatabase.Entry.Strings.ReadSafe(PwDefs.TitleField);
            var loginpass = GetUserPass(entryDatabase, ctx);
            var login = loginpass[0];
            var passwd = loginpass[1];
            var uuid = entryDatabase.Entry.Uuid.ToHexString();

            List<ResponseStringField> fields = null;
            if (configOpt.ReturnStringFields)
            {
                fields = new List<ResponseStringField>();

                foreach (var sf in entryDatabase.Entry.Strings)
                {
                    // follow references
                    var sfValue = SprEngine.Compile(entryDatabase.Entry.Strings.ReadSafe(sf.Key), ctx);

                    if (configOpt.ReturnStringFieldsWithKphOnly)
                    {
                        if (sf.Key.StartsWith("KPH: "))
                            fields.Add(new ResponseStringField(sf.Key.Substring(5), sfValue));
                    }
                    else
                    {
                        fields.Add(new ResponseStringField(sf.Key, sfValue));
                    }
                }

                if (fields.Count > 0)
                    fields = fields.OrderBy(e => e.Key).ToList();
                else
                    fields = null;
            }

            return new ResponseEntry(name, login, passwd, uuid, fields);
        }

        private void SetLoginHandler(Request request, Response response, Aes aes)
        {
            if (!VerifyRequest(request, aes))
                return;

            string url = CryptoTransform(request.Url, true, false, aes, CMode.DECRYPT);
            var urlHost = GetHost(url);

            PwUuid uuid = null;
            string username, password;

            username = CryptoTransform(request.Login, true, false, aes, CMode.DECRYPT);
            password = CryptoTransform(request.Password, true, false, aes, CMode.DECRYPT);

            if (request.Uuid != null)
                uuid = new PwUuid(MemUtil.HexStringToByteArray(
                        CryptoTransform(request.Uuid, true, false, aes, CMode.DECRYPT)));

            if (uuid != null)
                // modify existing entry
                UpdateEntry(uuid, username, password, urlHost, request.Id);
            else
                // create new entry
                CreateEntry(username, password, urlHost, url, request, aes);

            response.Success = true;
            response.Id = request.Id;
            SetResponseVerifier(response, aes);
        }

        private void AssociateHandler(Request request, Response response, Aes aes)
        {
            if (!TestRequestVerifier(request, aes, request.Key))
                return;

            // key is good, prompt user to save
            using (var form = new ConfirmAssociationForm())
            {
                var window = host.MainWindow;
                form.Activate();
                form.Icon = window.Icon;
                form.Key = request.Key;
                form.Load += delegate { form.Activate(); };
                form.ShowDialog(window);
                window.Invoke(new MethodInvoker(() => ConfirmAssociation(request, response, aes, form, window)));
            }
        }

        private void ConfirmAssociation(Request request, Response response, Aes aes, ConfirmAssociationForm form, MainForm win)
        {
            if (form.KeyId == null)
                return;

            var entry = GetConfigEntry(true);

            bool keyNameExists = true;
            while (keyNameExists)
            {
                DialogResult keyExistsResult = DialogResult.Yes;

                foreach (var s in entry.Strings)
                {
                    if (s.Key == ASSOCIATE_KEY_PREFIX + form.KeyId)
                    {
                        keyExistsResult = MessageBox.Show(
                            win,
                            "A shared encryption-key with the name \"" + form.KeyId + "\" already exists.\nDo you want to overwrite it?",
                            "Overwrite existing key?",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Warning,
                            MessageBoxDefaultButton.Button1
                        );
                        break;
                    }
                }

                if (keyExistsResult == DialogResult.No)
                    form.ShowDialog(win);
                else
                    keyNameExists = false;
            }

            if (form.KeyId == null)
                return;

            entry.Strings.Set(ASSOCIATE_KEY_PREFIX + form.KeyId, new ProtectedString(true, request.Key));
            entry.Touch(true);
            response.Id = form.KeyId;
            response.Success = true;
            SetResponseVerifier(response, aes);
            UpdateUI(null);
        }

        private void TestAssociateHandler(Request request, Response response, Aes aes)
        {
            if (!VerifyRequest(request, aes))
                return;

            response.Success = true;
            response.Id = request.Id;
            SetResponseVerifier(response, aes);
        }

        private void GeneratePassword(Request request, Response response, Aes aes)
        {
            if (!VerifyRequest(request, aes))
                return;

            byte[] pbEntropy = null;
            PwProfile autoProfile = Program.Config.PasswordGenerator.AutoGeneratedPasswordsProfile;
            PwGenerator.Generate(out ProtectedString psNew, autoProfile, pbEntropy, Program.PwGeneratorPool);

            byte[] pbNew = psNew.ReadUtf8();

            if (pbNew != null)
            {
                uint uBits = QualityEstimation.EstimatePasswordBits(pbNew);
                ResponseEntry item = new ResponseEntry(Request.GENERATE_PASSWORD, uBits.ToString(), StrUtil.Utf8.GetString(pbNew), Request.GENERATE_PASSWORD, null);
                response.Entries.Add(item);
                response.Success = true;
                response.Count = 1;
                MemUtil.ZeroByteArray(pbNew);
            }

            response.Id = request.Id;
            SetResponseVerifier(response, aes);

            foreach (var entry in response.Entries)
            {
                entry.Name = CryptoTransform(entry.Name, false, true, aes, CMode.ENCRYPT);
                entry.Login = CryptoTransform(entry.Login, false, true, aes, CMode.ENCRYPT);
                entry.Uuid = CryptoTransform(entry.Uuid, false, true, aes, CMode.ENCRYPT);
                entry.Password = CryptoTransform(entry.Password, false, true, aes, CMode.ENCRYPT);
            }
        }

        private KeePassHttpEntryConfig GetEntryConfig(PwEntry e)
        {
            if (e.Strings.Exists(KEEPASSHTTP_NAME))
            {
                var json = e.Strings.ReadSafe(KEEPASSHTTP_NAME);
                using (var ins = new JsonTextReader(new StringReader(json)))
                    return NewJsonSerializer().Deserialize<KeePassHttpEntryConfig>(ins);
            }

            return null;
        }

        private void SetEntryConfig(PwEntry e, KeePassHttpEntryConfig c)
        {
            var writer = new StringWriter();
            NewJsonSerializer().Serialize(writer, c);
            e.Strings.Set(KEEPASSHTTP_NAME, new ProtectedString(false, writer.ToString()));
            e.Touch(true);
            UpdateUI(e.ParentGroup);
        }

        private bool UpdateEntry(PwUuid uuid, string username, string password, string formHost, string requestId)
        {
            PwEntry entry = null;

            var configOpt = new ConfigOpt(host.CustomConfig);

            if (configOpt.SearchInAllOpenedDatabases)
            {
                foreach (PwDocument doc in host.MainWindow.DocumentManager.Documents)
                {
                    if (doc.Database.IsOpen)
                    {
                        entry = doc.Database.RootGroup.FindEntry(uuid, true);

                        if (entry != null)
                            break;
                    }
                }
            }
            else
            {
                entry = host.Database.RootGroup.FindEntry(uuid, true);
            }

            if (entry == null)
                return false;

            string[] up = GetUserPass(entry);
            var u = up[0];
            var p = up[1];

            if (u != username || p != password)
            {
                bool allowUpdate = configOpt.AlwaysAllowUpdates;

                if (!allowUpdate)
                {
                    host.MainWindow.Activate();

                    DialogResult result;
                    if (host.MainWindow.IsTrayed())
                    {
                        result = MessageBox.Show(
                            String.Format("Do you want to update the information in {0} - {1}?", formHost, u),
                            "Update Entry", MessageBoxButtons.YesNo,
                            MessageBoxIcon.None, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                    }
                    else
                    {
                        result = MessageBox.Show(
                            host.MainWindow,
                            String.Format("Do you want to update the information in {0} - {1}?", formHost, u),
                            "Update Entry", MessageBoxButtons.YesNo,
                            MessageBoxIcon.Information, MessageBoxDefaultButton.Button1);
                    }


                    if (result == DialogResult.Yes)
                        allowUpdate = true;
                }

                if (allowUpdate)
                {
                    PwObjectList<PwEntry> mVHistory = entry.History.CloneDeep();
                    entry.History = mVHistory;
                    entry.CreateBackup(null);

                    entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, username));
                    entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, password));
                    entry.Touch(true, false);
                    UpdateUI(entry.ParentGroup);

                    return true;
                }
            }

            return false;
        }

        private bool CreateEntry(string username, string password, string urlHost, string url, Request r, Aes aes)
        {
            string realm = null;
            if (r.Realm != null)
                realm = CryptoTransform(r.Realm, true, false, aes, CMode.DECRYPT);

            var root = host.Database.RootGroup;
            var group = root.FindCreateGroup(KEEPASSHTTP_GROUP_NAME, false);

            if (group == null)
            {
                group = new PwGroup(true, true, KEEPASSHTTP_GROUP_NAME, PwIcon.WorldComputer);
                root.AddGroup(group, true);
                UpdateUI(null);
            }

            string submithost = null;

            if (r.SubmitUrl != null)
                submithost = GetHost(CryptoTransform(r.SubmitUrl, true, false, aes, CMode.DECRYPT));

            string baseUrl = url;

            // index bigger than https:// <-- this slash
            if (baseUrl.LastIndexOf("/") > 9)
                baseUrl = baseUrl.Substring(0, baseUrl.LastIndexOf("/") + 1);

            PwEntry entry = new PwEntry(true, true);
            entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, urlHost));
            entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, username));
            entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, password));
            entry.Strings.Set(PwDefs.UrlField, new ProtectedString(true, baseUrl));

            if ((submithost != null && urlHost != submithost) || realm != null)
            {
                var config = new KeePassHttpEntryConfig();
                if (submithost != null)
                    config.Allow.Add(submithost);
                if (realm != null)
                    config.Realm = realm;

                var serializer = NewJsonSerializer();
                var writer = new StringWriter();
                serializer.Serialize(writer, config);
                entry.Strings.Set(KEEPASSHTTP_NAME, new ProtectedString(false, writer.ToString()));
            }

            group.AddEntry(entry, true);
            UpdateUI(group);

            return true;
        }
    }
}
