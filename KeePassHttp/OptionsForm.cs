using KeePassLib;
using KeePassHttp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using KeePassLib.Collections;

namespace KeePassHttp
{
    public partial class OptionsForm : Form
    {
        readonly ConfigOpt config;
        private bool restartRequired;

        public OptionsForm(ConfigOpt config)
        {
            restartRequired = false;
            this.config = config;
            InitializeComponent();
        }

        private PwEntry GetConfigEntry(PwDatabase db) => db.RootGroup.FindEntry(new PwUuid(new KeePassHttpExt().KEEPASSHTTP_UUID), false);

        private void OptionsFormLoad(object sender, EventArgs e)
        {
            credNotifyCheckbox.Checked = config.ReceiveCredentialNotification;
            credMatchingCheckbox.Checked = config.SpecificMatchingOnly;
            unlockDatabaseCheckbox.Checked = config.UnlockDatabaseRequest;
            credAllowAccessCheckbox.Checked = config.AlwaysAllowAccess;
            credAllowUpdatesCheckbox.Checked = config.AlwaysAllowUpdates;
            credSearchInAllOpenedDatabases.Checked = config.SearchInAllOpenedDatabases;
            hideExpiredCheckbox.Checked = config.HideExpired;
            matchSchemesCheckbox.Checked = config.MatchSchemes;
            returnStringFieldsCheckbox.Checked = config.ReturnStringFields;
            returnStringFieldsWithKphOnlyCheckBox.Checked = config.ReturnStringFieldsWithKphOnly;
            SortByUsernameRadioButton.Checked = config.SortResultByUsername;
            SortByTitleRadioButton.Checked = !config.SortResultByUsername;
            portNumber.Value = config.ListenerPort;
            hostName.Text = config.ListenerHost;

            ReturnStringFieldsCheckboxCheckedChanged(null, EventArgs.Empty);
        }

        private void OkButtonClick(object sender, EventArgs e)
        {
            config.ReceiveCredentialNotification = credNotifyCheckbox.Checked;
            config.SpecificMatchingOnly = credMatchingCheckbox.Checked;
            config.UnlockDatabaseRequest = unlockDatabaseCheckbox.Checked;
            config.AlwaysAllowAccess = credAllowAccessCheckbox.Checked;
            config.AlwaysAllowUpdates = credAllowUpdatesCheckbox.Checked;
            config.SearchInAllOpenedDatabases = credSearchInAllOpenedDatabases.Checked;
            config.HideExpired = hideExpiredCheckbox.Checked;
            config.MatchSchemes = matchSchemesCheckbox.Checked;
            config.ReturnStringFields = returnStringFieldsCheckbox.Checked;
            config.ReturnStringFieldsWithKphOnly = returnStringFieldsWithKphOnlyCheckBox.Checked;
            config.SortResultByUsername = SortByUsernameRadioButton.Checked;
            config.ListenerPort = (int)portNumber.Value;
            config.ListenerHost = hostName.Text;

            if (restartRequired)
            {
                MessageBox.Show(
                    "You have successfully changed the port number and/or the host name.\nA restart of KeePass is required!\n\nPlease restart KeePass now.",
                    "Restart required!",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
        }

        private void RemoveButtonClick(object sender, EventArgs e)
        {
            if (!KeePass.Program.MainForm.DocumentManager.ActiveDatabase.IsOpen)
            {
                MessageBox.Show("No shared encryption-keys found in KeePassHttp Settings.", "No keys found",
                               MessageBoxButtons.OK,
                               MessageBoxIcon.Information);
                return;
            }

            PwDatabase db = KeePass.Program.MainForm.DocumentManager.ActiveDatabase;
            var entry = GetConfigEntry(db);

            if (entry == null)
            {
                MessageBox.Show("The active database is locked!\nPlease unlock the selected database or choose another one which is unlocked.",
                    "Database locked!", MessageBoxButtons.OK, MessageBoxIcon.Error);

                return;
            }

            List<string> deleteKeys = new List<string>();

            foreach (var s in entry.Strings)
            {
                if (s.Key.IndexOf(KeePassHttpExt.ASSOCIATE_KEY_PREFIX) == 0)
                    deleteKeys.Add(s.Key);
            }


            if (deleteKeys.Count > 0)
            {
                PwObjectList<PwEntry> m_vHistory = entry.History.CloneDeep();
                entry.History = m_vHistory;
                entry.CreateBackup(null);

                foreach (var key in deleteKeys)
                    entry.Strings.Remove(key);

                entry.Touch(true);
                KeePass.Program.MainForm.UpdateUI(false, null, true, db.RootGroup, true, null, true);

                MessageBox.Show(
                    String.Format("Successfully removed {0} encryption-key{1} from KeePassHttp Settings.", deleteKeys.Count.ToString(), deleteKeys.Count == 1 ? "" : "s"),
                    String.Format("Removed {0} key{1} from database", deleteKeys.Count.ToString(), deleteKeys.Count == 1 ? "" : "s"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("The active database does not contain an entry of KeePassHttp Settings.", "KeePassHttp Settings not available!", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }

        }

        private void RemovePermissionsButtonClick(object sender, EventArgs e)
        {
            if (!KeePass.Program.MainForm.DocumentManager.ActiveDatabase.IsOpen)
            {
                MessageBox.Show("The active database is locked!\nPlease unlock the selected database or choose another one which is unlocked.",
                    "Database locked!", MessageBoxButtons.OK, MessageBoxIcon.Error);

                return;
            }

            PwDatabase db = KeePass.Program.MainForm.DocumentManager.ActiveDatabase;

            uint counter = 0;
            var entries = db.RootGroup.GetEntries(true);

            if (entries.Count() > 999)
            {
                MessageBox.Show(
                    String.Format("{0} entries detected!\nSearching and removing permissions could take some while.\n\nWe will inform you when the process has been finished.",
                    entries.Count().ToString()),
                    String.Format("{0} entries detected", entries.Count().ToString()),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }

            foreach (var entry in entries)
            {
                foreach (var str in entry.Strings)
                {
                    if (str.Key == KeePassHttpExt.KEEPASSHTTP_NAME)
                    {
                        PwObjectList<PwEntry> m_vHistory = entry.History.CloneDeep();
                        entry.History = m_vHistory;
                        entry.CreateBackup(null);

                        entry.Strings.Remove(str.Key);

                        entry.Touch(true);

                        counter += 1;

                        break;
                    }
                }
            }

            if (counter > 0)
            {
                KeePass.Program.MainForm.UpdateUI(false, null, true, db.RootGroup, true, null, true);
                MessageBox.Show(
                    string.Format($"Successfully removed permissions from {0} entr{1}.", counter.ToString(), counter == 1 ? "y" : "ies"),
                    string.Format($"Removed permissions from {0} entr{1}", counter.ToString(), counter == 1 ? "y" : "ies"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
            else
            {
                MessageBox.Show(
                    "The active database does not contain an entry with permissions.",
                    "No entry with permissions found!",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }

        }

        private void SetRestartRequired(object sender, EventArgs e)
            => restartRequired = (config.ListenerPort != portNumber.Value) || (config.ListenerHost != hostName.Text);

        private void ReturnStringFieldsCheckboxCheckedChanged(object sender, EventArgs e)
            => returnStringFieldsWithKphOnlyCheckBox.Enabled = returnStringFieldsCheckbox.Checked;
    }
}
