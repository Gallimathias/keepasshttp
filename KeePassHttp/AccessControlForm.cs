using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

using KeePassLib;

namespace KeePassHttp
{
    public partial class AccessControlForm : Form
    {
        public string Host
        {
            set
            {
                host = value;
                SetLabel();
            }
        }
        public List<PwEntry> Entries { set => SetEntries(value); }
        public bool Remember => RememberCheck.Checked;
        public bool Allowed { get; private set; }
        public bool Denied { get; private set; }

        internal KeePassHttpExt Plugin;

        private readonly string message;
        private int count;
        private string host;


        public AccessControlForm()
        {
            count = 0;
            host = null;
            Allowed = false;
            Denied = false;
            Plugin = null;
            message = "{0} has requested access to passwords for the above {1}.{2} " +
            "Please select whether you want to allow access{3}.";

            InitializeComponent();
        }

        private void AllowButtonClick(object sender, EventArgs e)
        {
            Allowed = true;
            Close();
        }

        private void DenyButtonClick(object sender, EventArgs e)
        {
            Denied = true;
            Close();
        }

        private void SetLabel()
        {
            if (host == null)
                return;

            ConfirmTextLabel.Text = string.Format(
                message,
                host,
                count == 1 ? "item" : "items",
                count == 1 ? "" : "\nYou can only grant access to all items.",
                count == 1 ? "" : " to all of them"
            );
        }

        private void SetEntries(List<PwEntry> value)
        {
            EntriesBox.SelectionMode = SelectionMode.None;
            count = value.Count;
            SetLabel();

            foreach (var e in value)
            {
                if (e == null ||
                    e.Strings == null ||
                    e.Strings.Get(PwDefs.TitleField) == null)
                {
                    continue;
                }

                var title = e.Strings.Get(PwDefs.TitleField).ReadString();

                if (Plugin == null || Plugin.GetUserPass(e) == null)
                    continue;

                var username = Plugin.GetUserPass(e)[0];

                EntriesBox.Items.Add(title + " - " + username);
            }
        }
    }
}
