using KeePassLib;

namespace KeePassHttp
{
    class PwEntryDatabase
    {
        public PwEntry Entry { get; private set; }
        public PwDatabase Database { get; private set; }
        
        
        public PwEntryDatabase(PwEntry entry, PwDatabase database)
        {
            Entry = entry;
            Database = database;
        }
    }
}
