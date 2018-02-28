using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace KeePassHttp
{
    public partial class ConfirmAssociationForm : Form
    {
        public string KeyId => Saved ? KeyName.Text : null;
        public bool Saved { get; private set; }
        public string Key
        {
            get => KeyLabel.Text;
            set => KeyLabel.Text = value;
        }

        public ConfirmAssociationForm()
        {
            InitializeComponent();
            Saved = false;
        }

        private void SaveClick(object sender, EventArgs e)
        {
            var value = KeyName.Text;

            if (value != null && value.Trim() != "")
            {
                Saved = true;
                Close();
            }
        }

        private void CancelClick(object sender, EventArgs e) => Close();

    }
}
