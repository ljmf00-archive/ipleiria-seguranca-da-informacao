using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace EI.SI
{
    class ClientWithProtocolSI
    {
        private const string SERVER_HOSTNAME = "127.0.0.1";
        private const short SERVER_PORT = 9999;
        private const int CLIENT_ACCOUNT_ID = 123;

        private TcpClient tcpClient;
        private NetworkStream networkStream;
        private ProtocolSI protocol;
        private RSACryptoServiceProvider clientRsaProvider;
        private RSACryptoServiceProvider serverRsaProvider;
        private AesCryptoServiceProvider aes;
        private SymmetricsSI ssInstance;
        private byte[] messageBytes;

        ClientWithProtocolSI()
        {
            try
            {
                Console.Write("<-> Starting client... ");
                clientRsaProvider = new RSACryptoServiceProvider();
                aes = new AesCryptoServiceProvider();
                ssInstance = new SymmetricsSI(aes);
                Console.WriteLine("done");

                Console.Write("==> Connecting to the server... ");
                tcpClient = new TcpClient(SERVER_HOSTNAME, SERVER_PORT);
                networkStream = tcpClient.GetStream();
                Console.WriteLine("done");

                protocol = new ProtocolSI();

                // Exchanging RSA public keys
                Console.Write("--> Sending RSA client public key... ");
                messageBytes = protocol.Make(ProtocolSICmdType.PUBLIC_KEY, clientRsaProvider.ToXmlString(false));
                networkStream.Write(messageBytes, 0, messageBytes.Length);
                Console.WriteLine("done");

                Console.Write("<-- Receiving RSA server public key... ");
                networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                serverRsaProvider = new RSACryptoServiceProvider();
                serverRsaProvider.FromXmlString(protocol.GetStringFromData());
                Console.WriteLine("done");

                // Sending AES secrets
                Console.Write("--> Sending AES key... ");
                messageBytes = protocol.Make(ProtocolSICmdType.SECRET_KEY, serverRsaProvider.Encrypt(aes.Key, true));
                networkStream.Write(messageBytes, 0, messageBytes.Length);
                Console.WriteLine("done");
                Console.WriteLine("--  Sent: {0} .", ProtocolSI.ToHexString(aes.Key));

                Console.Write("<-- Waiting for an ACK command... ");
                networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                Console.WriteLine("done");

                Console.Write("--> Sending AES IV... ");
                messageBytes = protocol.Make(ProtocolSICmdType.IV, serverRsaProvider.Encrypt(aes.IV, true));
                networkStream.Write(messageBytes, 0, messageBytes.Length);
                Console.WriteLine("done");
                Console.WriteLine("--  Sent: {0} .", ProtocolSI.ToHexString(aes.IV));

                Console.Write("<-- Waiting for an ACK command... ");
                networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                Console.WriteLine("done");

                Console.Write("--> Requesting account balance... ");
                byte[] clearData = BitConverter.GetBytes(CLIENT_ACCOUNT_ID);
                byte[] encryptedData = ssInstance.Encrypt(clearData);
                messageBytes = protocol.Make(ProtocolSICmdType.SYM_CIPHER_DATA, encryptedData);
                networkStream.Write(messageBytes, 0, messageBytes.Length);
                Console.WriteLine("done");
                Console.WriteLine("--  Account ID: {0} = {1} .", BitConverter.ToInt32(clearData, 0).ToString(), ProtocolSI.ToHexString(clearData));
                Console.WriteLine("--  Sent Data: {0} .", ProtocolSI.ToHexString(encryptedData));

                Console.Write("<-- Waiting for the account balance... ");
                networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                encryptedData = protocol.GetData();
                clearData = ssInstance.Decrypt(encryptedData);
                double balance = BitConverter.ToDouble(clearData, 0);
                Console.WriteLine("done");
                Console.WriteLine(" -- Received Data: {0} .", ProtocolSI.ToHexString(encryptedData));
                Console.WriteLine(" -- Account Balance: {0} = {1} .", balance.ToString(), ProtocolSI.ToHexString(clearData));

                Console.Write("--> Requesting digital signature... ");
                // missing something like ProtocolSICmdType.REQUEST_DIGITAL_SIGNATURE
                // due to that, I used ProtocolSICmdType.DIGITAL_SIGNATURE as a REQUEST_DIGITAL_SIGNATURE
                // and the received digital signature is actually ProtocolSICmdType.SYM_CIPHER_DATA
                // because its encrypted with a symmetric algorithm.
                messageBytes = protocol.Make(ProtocolSICmdType.DIGITAL_SIGNATURE);
                networkStream.Write(messageBytes, 0, messageBytes.Length);
                Console.WriteLine("done");

                Console.Write("<-- Receiving encrypted digital signature... ");
                networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                encryptedData = protocol.GetData();
                byte[] signature = ssInstance.Decrypt(encryptedData);
                Console.WriteLine("done");
                Console.WriteLine(" -- Received Data: {0} .", ProtocolSI.ToHexString(encryptedData));
                Console.WriteLine(" -- Signature: {0} .", Convert.ToBase64String(signature));

                Console.Write("<-> Verify digital signature... ");
                // use previous clearData which is the balance converted to bytes
                bool signatureStatus =
                    serverRsaProvider.VerifyData(clearData, new SHA256CryptoServiceProvider(), signature);
                Console.WriteLine(signatureStatus ? "verified" : "failed");

                Console.Write("--> Sending digital signature status... ");
                messageBytes = protocol.Make(signatureStatus ? ProtocolSICmdType.ACK : ProtocolSICmdType.NACK);
                networkStream.Write(messageBytes, 0, messageBytes.Length);
                Console.WriteLine("done");

                Console.Write("<-- Waiting for an EOT command... ");
                networkStream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                Console.WriteLine("done");
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
                Console.WriteLine("done");
            }
        }

        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine("Hey, I'm the client!\n");

            new ClientWithProtocolSI();

            Console.Write("\nPress any key to exit... ");
            Console.ReadKey();
        }

    }
}
