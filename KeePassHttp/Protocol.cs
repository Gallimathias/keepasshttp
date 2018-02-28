using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

using KeePass.Plugins;
using System.Reflection;
using System.Diagnostics;
using System;

namespace KeePassHttp
{
    public sealed partial class KeePassHttpExt : Plugin
    {
        private static string Encode64(byte[] b) => Convert.ToBase64String(b);

        private static byte[] Decode64(string s) => Convert.FromBase64String(s);

        private bool VerifyRequest(Request request, Aes aes)
        {
            var entry = GetConfigEntry(false);

            if (entry == null)
                return false;

            var s = entry.Strings.Get(ASSOCIATE_KEY_PREFIX + request.Id);

            if (s == null)
                return false;

            return TestRequestVerifier(request, aes, s.ReadString());
        }

        private bool TestRequestVerifier(Request request, Aes aes, string key)
        {
            var success = false;
            var crypted = Decode64(request.Verifier);

            aes.Key = Decode64(key);
            aes.IV = Decode64(request.Nonce);

            using (var dec = aes.CreateDecryptor())
            {
                try
                {
                    var buf = dec.TransformFinalBlock(crypted, 0, crypted.Length);
                    success = Encoding.UTF8.GetString(buf) == request.Nonce;
                }
                catch (CryptographicException) { } // implicit failure
            }
            return success;
        }

        private void SetResponseVerifier(Response response, Aes aes)
        {
            aes.GenerateIV();
            response.Nonce = Encode64(aes.IV);
            response.Verifier = CryptoTransform(response.Nonce, false, true, aes, CMode.ENCRYPT);
        }
    }

    public class Request
    {
        public const string GET_LOGINS = "get-logins";
        public const string GET_LOGINS_COUNT = "get-logins-count";
        public const string GET_ALL_LOGINS = "get-all-logins";
        public const string SET_LOGIN = "set-login";
        public const string ASSOCIATE = "associate";
        public const string TEST_ASSOCIATE = "test-associate";
        public const string GENERATE_PASSWORD = "generate-password";

        public string RequestType { get; internal set; }

        /// <summary>
        /// Sort selection by best URL matching for given hosts
        /// </summary>
        public string SortSelection { get; internal set; }

        /// <summary>
        /// Trigger unlock of database even if feature is disabled in KPH (because of user interaction to fill-in)
        /// </summary>
        public string TriggerUnlock { get; internal set; }

        /// <summary>
        /// Always encrypted, used with set-login, uuid is set
        /// if modifying an existing login
        /// </summary>
        public string Login { get; internal set; }
        public string Password { get; internal set; }
        public string Uuid { get; internal set; }

        /// <summary>
        /// Always encrypted, used with get and set-login
        /// </summary>
        public string Url { get; internal set; }

        /// <summary>
        /// Always encrypted, used with get-login
        /// </summary>
        public string SubmitUrl { get; internal set; }

        /// <summary>
        /// Send the AES key ID with the 'associate' request
        /// </summary>
        public string Key { get; internal set; }

        /// <summary>
        /// Always required, an identifier given by the KeePass user
        /// </summary>
        public string Id { get; internal set; }
        /// <summary>
        /// A value used to ensure that the correct key has been chosen,
        /// it is always the value of Nonce encrypted with Key
        /// </summary>
        public string Verifier { get; internal set; }
        /// <summary>
        /// Nonce value used in conjunction with all encrypted fields,
        /// randomly generated for each request
        /// </summary>
        public string Nonce { get; internal set; }

        /// <summary>
        /// Realm value used for filtering results.  Always encrypted.
        /// </summary>
        public string Realm { get; internal set; }
    }

    public class Response
    {
        /// <summary>
        /// Mirrors the request type of KeePassRequest
        /// </summary>
        public string RequestType { get; internal set; }

        public string Error { get; internal set; }

        public bool Success { get; internal set; }

        /// <summary>
        /// The user selected string as a result of 'associate',
        /// always returned on every request
        /// </summary>
        public string Id { get; internal set; }

        /// <summary>
        /// response to get-logins-count, number of entries for requested Url
        /// </summary>
        public int Count { get; internal set; }

        /// <summary>
        /// response the current version of KeePassHttp
        /// </summary>
        public string Version { get; internal set; }

        /// <summary>
        /// response an unique hash of the database composed of RootGroup UUid and RecycleBin UUid
        /// </summary>
        public string Hash { get; internal set; }

        /// <summary>
        /// The resulting entries for a get-login request
        /// </summary>
        public List<ResponseEntry> Entries { get; private set; }

        /// <summary>
        /// Nonce value used in conjunction with all encrypted fields,
        /// randomly generated for each request
        /// </summary>
        public string Nonce { get; internal set; }

        /// <summary>
        /// Same purpose as Request.Verifier, but a new value
        /// </summary>
        public string Verifier { get; internal set; }

        public Response(string request, string hash)
        {
            RequestType = request;

            if (request == Request.GET_LOGINS || request == Request.GET_ALL_LOGINS || request == Request.GENERATE_PASSWORD)
                Entries = new List<ResponseEntry>();
            else
                Entries = null;

            Version = FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).ProductVersion;

            Hash = hash;
        }
    }

    public class ResponseEntry
    {
        public string Login { get; internal set; }
        public string Password { get; internal set; }
        public string Uuid { get; internal set; }
        public string Name { get; internal set; }
        public List<ResponseStringField> StringFields { get; internal set; }

        public ResponseEntry() { }
        public ResponseEntry(string name, string login, string password, string uuid, List<ResponseStringField> stringFields)
        {
            Login = login;
            Password = password;
            Uuid = uuid;
            Name = name;
            StringFields = stringFields;
        }
    }

    public class ResponseStringField
    {
        public string Key { get; internal set; }
        public string Value { get; internal set; }

        public ResponseStringField() { }
        public ResponseStringField(string key, string value)
        {
            Key = key;
            Value = value;
        }

    }

    public class KeePassHttpEntryConfig
    {
        public HashSet<string> Allow { get; internal set; }
        public HashSet<string> Deny { get; internal set; }
        public string RegExp { get; internal set; }
        public string Realm { get; internal set; }

        public KeePassHttpEntryConfig()
        {
            Allow = new HashSet<string>();
            Deny = new HashSet<string>();
            Realm = null;
            RegExp = null;
        }

    }
}
