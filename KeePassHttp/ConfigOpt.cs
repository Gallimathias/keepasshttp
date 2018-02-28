using KeePass.App.Configuration;

namespace KeePassHttp
{
    public class ConfigOpt
    {
        public const string RECEIVE_CREDENTIAL_NOTIFICATIONKEY = "KeePassHttp_ReceiveCredentialNotification";
        public const string SPECIFIC_MATCHING_ONLYKEY = "KeePassHttp_SpecificMatchingOnly";
        public const string UNLOCK_DATABASE_REQUESTKEY = "KeePassHttp_UnlockDatabaseRequest";
        public const string ALWAYS_ALLOW_ACCESSKEY = "KeePassHttp_AlwaysAllowAccess";
        public const string ALWAYS_ALLOW_UPDATESKEY = "KeePassHttp_AlwaysAllowUpdates";
        public const string SEARCH_IN_ALL_OPENED_DATABASESKEY = "KeePassHttp_SearchInAllOpenedDatabases";
        public const string HIDE_EXPIRED_KEY = "KeePassHttp_HideExpired";
        public const string MATCH_SCHEMES_KEY = "KeePassHttp_MatchSchemes";
        public const string RETURN_STRING_FIELDSKEY = "KeePassHttp_ReturnStringFields";
        public const string RETURN_STRING_FIELDS_WITH_KPH_ONLYKEY = "KeePassHttp_ReturnStringFieldsWithKphOnly";
        public const string SORT_RESULT_BY_USERNAMEKEY = "KeePassHttp_SortResultByUsername";
        public const string LISTENER_PORTKEY = "KeePassHttp_ListenerPort";
        public const string LISTENER_HOSTKEY = "KeePassHttp_ListenerHost";


        public bool ReceiveCredentialNotification
        {
            get => config.GetBool(RECEIVE_CREDENTIAL_NOTIFICATIONKEY, true);
            set => config.SetBool(RECEIVE_CREDENTIAL_NOTIFICATIONKEY, value);
        }

        public bool UnlockDatabaseRequest
        {
            get => config.GetBool(UNLOCK_DATABASE_REQUESTKEY, false);
            set => config.SetBool(UNLOCK_DATABASE_REQUESTKEY, value);
        }

        public bool SpecificMatchingOnly
        {
            get => config.GetBool(SPECIFIC_MATCHING_ONLYKEY, false);
            set => config.SetBool(SPECIFIC_MATCHING_ONLYKEY, value);
        }

        public bool AlwaysAllowAccess
        {
            get => config.GetBool(ALWAYS_ALLOW_ACCESSKEY, false);
            set => config.SetBool(ALWAYS_ALLOW_ACCESSKEY, value);
        }

        public bool AlwaysAllowUpdates
        {
            get => config.GetBool(ALWAYS_ALLOW_UPDATESKEY, false);
            set => config.SetBool(ALWAYS_ALLOW_UPDATESKEY, value);
        }

        public bool SearchInAllOpenedDatabases
        {
            get => config.GetBool(SEARCH_IN_ALL_OPENED_DATABASESKEY, false);
            set => config.SetBool(SEARCH_IN_ALL_OPENED_DATABASESKEY, value);
        }

        public bool HideExpired
        {
            get => config.GetBool(HIDE_EXPIRED_KEY, false);
            set => config.SetBool(HIDE_EXPIRED_KEY, value);
        }
        public bool MatchSchemes
        {
            get => config.GetBool(MATCH_SCHEMES_KEY, false);
            set => config.SetBool(MATCH_SCHEMES_KEY, value);
        }

        public bool ReturnStringFields
        {
            get => config.GetBool(RETURN_STRING_FIELDSKEY, false);
            set => config.SetBool(RETURN_STRING_FIELDSKEY, value);
        }

        public bool ReturnStringFieldsWithKphOnly
        {
            get => config.GetBool(RETURN_STRING_FIELDS_WITH_KPH_ONLYKEY, true);
            set => config.SetBool(RETURN_STRING_FIELDS_WITH_KPH_ONLYKEY, value);
        }

        public bool SortResultByUsername
        {
            get => config.GetBool(SORT_RESULT_BY_USERNAMEKEY, true);
            set => config.SetBool(SORT_RESULT_BY_USERNAMEKEY, value);
        }

        public long ListenerPort
        {
            get => config.GetLong(LISTENER_PORTKEY, KeePassHttpExt.DEFAULT_PORT);
            set => config.SetLong(LISTENER_PORTKEY, value);
        }

        public string ListenerHost
        {
            get => config.GetString(LISTENER_HOSTKEY, KeePassHttpExt.DEFAULT_HOST);
            set => config.SetString(LISTENER_HOSTKEY, value);
        }

        private readonly AceCustomConfig config;

        public ConfigOpt(AceCustomConfig config) => this.config = config;

    }
}