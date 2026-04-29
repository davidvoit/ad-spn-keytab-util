/*
 * Copyright 2026 David Voit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

using System.ComponentModel.DataAnnotations;
using System.Security;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using McMaster.Extensions.CommandLineUtils;

namespace ActiveDirectoryServiceUserKeytabUtil;

class ActiveDirectoryServiceUserKeytabUtil
{
    public static int Main(string[] args) => CommandLineApplication.Execute<ActiveDirectoryServiceUserKeytabUtil>(args);

    [Option(Description = "Domain", ShortName = "d", LongName = "domain")]
    internal string? Domain { get; set; }
    
    [Required]
    [Option(Description = "Username", ShortName = "u", LongName = "user")]
    internal required string User { get; set; }

    [Required]
    [Option(Description = "SPN", ShortName = "s", LongName = "spn")]
    internal required string Spn { get; set; }

    [Required]
    [Option(Description = "Keytab file", ShortName = "o", LongName = "output")]
    internal required string Output { get; set; }
    
    async Task<int> OnExecuteAsync()
    {
        string domain;

        var userDomain = User.Split("@", 2);
        var user = userDomain[0];

        if (Domain == null)
        {
            if (userDomain.Length == 1)
            {
                await Console.Error.WriteLineAsync("--domain or --user user@DOMAIN is required");
                return 1;
            }

            domain = userDomain[1];
        }
        else
        {
            domain = Domain;
        }

        var password = Prompt.GetPassword($"Please input the password for user '{user}@{domain}':");
        if (password.Length == 0)
        {
            await Console.Error.WriteLineAsync("Password can't be empty");
            return 1;
        }

        string? salt = null;

        var client = new KerberosClient();

        KerberosPasswordCredential krbUser;

        try
        {
            // We use a fake password, no normal user would be able to enter 0x01 as an password,
            // Kerberos.NET reports in this case the ETYPE-INFO2 information
            krbUser = new KerberosPasswordCredential(user, "\x01", domain);
            await client.Authenticate(krbUser);
        }
        catch (KerberosProtocolException e)
        {
            switch (e.Error.ErrorCode)
            {
                case KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                    await Console.Error.WriteLineAsync("User not know to kerberos");
                    return 1;
                case KerberosErrorCode.KDC_ERR_PREAUTH_FAILED when e.Error.EData.HasValue:
                {
                    var errorData = KrbMethodData.Decode(e.Error.EData.Value);

                    foreach (var entry in errorData.MethodData)
                    {
                        var typeinfo2 = KrbETypeInfo2.Decode(entry.Value);
                        salt = typeinfo2.ETypeInfo[0].Salt;
                        break;
                    }

                    break;
                }
                default:
                {
                    // Just log the error and continue
                    await Console.Error.WriteLineAsync(e.Message);
                    break;
                }
            }
        }

        // Fallback to use default salt algorithm - this normally should never happen, maybe we should bail instead?
        if (salt != null)
        {
            var principal = new PrincipalName(PrincipalNameType.NT_ENTERPRISE,
                realm: domain,
                names: [user]);
        
            var key = new KerberosKey(principal: principal, password: [0x01], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96, saltType: SaltType.Rfc4120);

            salt = key.Salt;
        }

        Console.WriteLine("Salt: "+salt);

        krbUser = new KerberosPasswordCredential(user, password, domain);
        try
        {
            await client.Authenticate(krbUser);
        }
        catch (KerberosProtocolException e)
        {
            if (e.Error.ErrorCode == KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP)
            {
                await Console.Error.WriteLineAsync($"User doesn't support secure encryption types." +
                                                   $" Maybe {user} only supports RC4!" +
                                                   $" If this is the case you can change your password and try again.");
                return 1;
            }

            await Console.Error.WriteLineAsync("Login failed: " + e.Message);
            return 1;
        }

        KrbApReq ticket;
        try
        {
            ticket = await client.GetServiceTicket(Spn);
        }
        catch (KerberosProtocolException)
        {
            await Console.Error.WriteLineAsync("SPN not found in KDC");
            return 1;
        }
        var kvno = ticket.Ticket.EncryptedPart.KeyVersionNumber.GetValueOrDefault(0);
        Console.WriteLine("Kvno: "+kvno);

        var serviceKey = new KerberosKey(
            password: password,
            salt: salt,
            etype: ticket.Ticket.EncryptedPart.EType
        );

        try
        {
            ticket.Ticket.EncryptedPart.Decrypt(serviceKey, KeyUsage.Ticket, KrbEncTicketPart.DecodeApplication);
        }
        catch (SecurityException e)
        {
            await Console.Error.WriteLineAsync($"user {user} is not the owner of spn: {Spn}");
            return 1;
        }

        // Now create a keytab for aes128 and aes256 (RFC3962 and RFC8009)
        var encTypes = new[] { EncryptionType.AES128_CTS_HMAC_SHA1_96, EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.AES128_CTS_HMAC_SHA256_128, EncryptionType.AES256_CTS_HMAC_SHA384_192 };

        var keytab = new KeyTable();
        var state = "created";
        int count = 0;
        
        if (File.Exists(Output))
        {
            keytab = new KeyTable(new FileStream(Output, FileMode.Open));
            state = "updated";
        }

        var spnPrincipal = new PrincipalName(PrincipalNameType.NT_PRINCIPAL,
            realm: domain,
            names: [Spn]);

        foreach (var encType in encTypes)
        {
            var existingKey = keytab.Entries.Any(k => k.EncryptionType == encType && Equals(k.Principal, spnPrincipal) && k.Version == kvno);
            if (existingKey)
                continue;

            var key = new KerberosKey(
                principalName: spnPrincipal,
                password: password,
                salt: salt,
                etype: encType,
                kvno: kvno
            );

            var entry = new KeyEntry(key);

            keytab.Entries.Add(entry);
            count++;
        }

        await using var fs = File.Create(Output);
        await using var bw = new BinaryWriter(fs);
        keytab.Write(bw);

        Console.WriteLine($"Keytab '{Output}' {state}. Added {count} keys.");

        return 0;
    }

}