using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace EI.SI
{
    class ServerWithProtocolSI
    {
        private const short SERVER_PORT = 9999;

        private Dictionary<int, double> accounts;
        private TcpListener tcpListener;
        private RSACryptoServiceProvider serverRsaProvider;

        // could be in a different scope due to client related stuff
        private TcpClient tcpClient;
        private NetworkStream networkStream;
        private ProtocolSI protocol;
        private RSACryptoServiceProvider clientRsaProvider;
        private AesCryptoServiceProvider aes;
        private SymmetricsSI ssInstance;
        private byte[] messageBytes;

        private void CreateAccounts()
        {
            accounts = new Dictionary<int, double>()
            {
                {2, 500.0},
                {5, 15.50},
                {123, 1000.0}
            };
        }

        ServerWithProtocolSI()
        {
            CreateAccounts();

            try
            {
                Console.Write("<-> Starting server... ");
                serverRsaProvider = new RSACryptoServiceProvider();

                tcpListener = new TcpListener(IPAddress.Any, SERVER_PORT);
                tcpListener.Start();

                Console.WriteLine("done");
                
                // client scope: this could be wrapped into a loop
                {
                    Console.Write("<== Waiting for the client to connect... ");
                    tcpClient = tcpListener.AcceptTcpClient();
                    networkStream = tcpClient.GetStream();
                    Console.WriteLine("done");

                    protocol = new ProtocolSI();

                    // Exchanging RSA public keys
                    Console.Write("<-- Receiving RSA client public key... ");
                    networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                    clientRsaProvider = new RSACryptoServiceProvider();
                    clientRsaProvider.FromXmlString(protocol.GetStringFromData());
                    Console.WriteLine("done");

                    Console.Write("--> Sending RSA server public key... ");
                    messageBytes = protocol.Make(ProtocolSICmdType.PUBLIC_KEY, serverRsaProvider.ToXmlString(false));
                    networkStream.Write(messageBytes, 0, messageBytes.Length);
                    Console.WriteLine("done");

                    // Receiving AES secrets
                    Console.Write("<-- Receiving AES key... ");
                    networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                    aes = new AesCryptoServiceProvider();
                    ssInstance = new SymmetricsSI(aes);
                    aes.Key = serverRsaProvider.Decrypt(protocol.GetData(), true);
                    Console.WriteLine("done");
                    Console.WriteLine(" -- Received: {0} .", ProtocolSI.ToHexString(aes.Key));

                    Console.Write("--> Sending an ACK command... ");
                    messageBytes = protocol.Make(ProtocolSICmdType.ACK);
                    networkStream.Write(messageBytes, 0, messageBytes.Length);
                    Console.WriteLine("done");

                    Console.Write("<-- Receiving AES IV... ");
                    networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                    aes.IV = serverRsaProvider.Decrypt(protocol.GetData(), true);
                    Console.WriteLine("done");
                    Console.WriteLine(" -- Received: {0} .", ProtocolSI.ToHexString(aes.IV));

                    Console.Write("--> Sending an ACK command... ");
                    messageBytes = protocol.Make(ProtocolSICmdType.ACK);
                    networkStream.Write(messageBytes, 0, messageBytes.Length);
                    Console.WriteLine("done");

                    Console.Write("<-- Waiting for an account balance request... ");
                    networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                    byte[] encryptedData = protocol.GetData();
                    byte[] clearData = ssInstance.Decrypt(encryptedData);
                    int accountId = BitConverter.ToInt32(clearData, 0);
                    Console.WriteLine("done");
                    Console.WriteLine(" -- Received Data: {0} .", ProtocolSI.ToHexString(encryptedData));
                    Console.WriteLine(" -- Account ID: {0} = {1} .", accountId.ToString(), ProtocolSI.ToHexString(clearData));

                    Console.Write("--> Sending the account balance... ");
                    clearData = BitConverter.GetBytes(accounts[accountId]);
                    encryptedData = ssInstance.Encrypt(clearData);
                    messageBytes = protocol.Make(ProtocolSICmdType.SYM_CIPHER_DATA, encryptedData);
                    networkStream.Write(messageBytes, 0, messageBytes.Length);
                    Console.WriteLine("done");
                    Console.WriteLine("--  Account Balance: {0} = {1} .", BitConverter.ToDouble(clearData, 0).ToString(), ProtocolSI.ToHexString(clearData));
                    Console.WriteLine("--  Sent Data: {0} .", ProtocolSI.ToHexString(encryptedData));

                    Console.Write("<-- Waiting for a digital signature request... ");
                    networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                    Console.WriteLine("done");

                    Console.Write("--> Sending digital signature... ");
                    // use previous clearData which is the balance converted to bytes
                    byte[] signature = serverRsaProvider.SignData(clearData, new SHA256CryptoServiceProvider());
                    encryptedData = ssInstance.Encrypt(signature);
                    messageBytes = protocol.Make(ProtocolSICmdType.SYM_CIPHER_DATA, encryptedData);
                    networkStream.Write(messageBytes, 0, messageBytes.Length);
                    Console.WriteLine("done");
                    Console.WriteLine("--  Signature: {0} .", Convert.ToBase64String(signature));
                    Console.WriteLine("--  Sent Data: {0} .", ProtocolSI.ToHexString(encryptedData));

                    Console.Write("<-- Receiving digital signature status... ");
                    networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                    Console.WriteLine(protocol.GetCmdType() == ProtocolSICmdType.ACK
                        ? "verified"
                        : "failed");

                    Console.Write("--> Sending EOT... ");
                    messageBytes = protocol.Make(ProtocolSICmdType.EOT);
                    networkStream.Write(messageBytes, 0, messageBytes.Length);
                    Console.WriteLine("done");
                }
            }
            catch (Exception ex)
                when (
                    ex is SocketException
                    || ex is CryptographicException
                )
            {
                Console.WriteLine("\n===\nException: {0}\nStackTrace:\n{1}\n", ex.Message, ex.StackTrace);
            }
            finally
            {
                Console.Write("<-> Closing all the connections and streams... ");
                networkStream?.Dispose();
                tcpClient?.Close();
                tcpListener?.Stop();
                Console.WriteLine("done");
            }
        }

        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine("Hey, I'm the server!\n");

            new ServerWithProtocolSI();

            Console.Write("\nPress any key to exit... ");
            Console.ReadKey();
        }

    }
}
