using System;
using System.IO;
using System.Security.Cryptography;

namespace EI.SI
{
  public class SymmetricsSI : IDisposable
  {
    private bool disposed = false;
    private SymmetricAlgorithm sa = (SymmetricAlgorithm) null;

    public SymmetricsSI(SymmetricAlgorithm sa)
    {
      this.sa = sa;
    }

    public byte[] Encrypt(byte[] plainbytes)
    {
      MemoryStream memoryStream = (MemoryStream) null;
      CryptoStream cryptoStream = (CryptoStream) null;
      try
      {
        memoryStream = new MemoryStream();
        cryptoStream = new CryptoStream((Stream) memoryStream, this.sa.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(plainbytes, 0, plainbytes.Length);
        cryptoStream.Close();
        return memoryStream.ToArray();
      }
      catch (Exception ex)
      {
        throw new Exception("SymmetricsSI.Encrypt :: ", ex);
      }
      finally
      {
        cryptoStream?.Clear();
        memoryStream?.Dispose();
      }
    }

    public byte[] Encrypt2(byte[] plainbytes)
    {
      MemoryStream memoryStream1 = (MemoryStream) null;
      MemoryStream memoryStream2 = (MemoryStream) null;
      CryptoStream cryptoStream = (CryptoStream) null;
      try
      {
        memoryStream1 = new MemoryStream(plainbytes);
        memoryStream2 = new MemoryStream();
        cryptoStream = new CryptoStream((Stream) memoryStream1, this.sa.CreateEncryptor(), CryptoStreamMode.Read);
        cryptoStream.CopyTo((Stream) memoryStream2);
        cryptoStream.Flush();
        if (!cryptoStream.HasFlushedFinalBlock)
          cryptoStream.FlushFinalBlock();
        return memoryStream2.ToArray();
      }
      catch (Exception ex)
      {
        throw new Exception("SymmetricsSI.Encrypt2 :: ", ex);
      }
      finally
      {
        cryptoStream?.Clear();
        memoryStream2?.Dispose();
        memoryStream1?.Dispose();
      }
    }

    public byte[] Decrypt(byte[] cipherData)
    {
      MemoryStream memoryStream = (MemoryStream) null;
      CryptoStream cryptoStream = (CryptoStream) null;
      try
      {
        memoryStream = new MemoryStream(cipherData);
        cryptoStream = new CryptoStream((Stream) memoryStream, this.sa.CreateDecryptor(), CryptoStreamMode.Read);
        byte[] array = new byte[memoryStream.Length];
        int newSize = cryptoStream.Read(array, 0, array.Length);
        cryptoStream.Close();
        Array.Resize<byte>(ref array, newSize);
        return array;
      }
      catch (Exception ex)
      {
        throw new Exception("SymmetricsSI.Decrypt :: ", ex);
      }
      finally
      {
        cryptoStream?.Clear();
        memoryStream?.Dispose();
      }
    }

    public byte[] Decrypt2(byte[] cipherData)
    {
      MemoryStream memoryStream1 = (MemoryStream) null;
      MemoryStream memoryStream2 = (MemoryStream) null;
      CryptoStream cryptoStream = (CryptoStream) null;
      try
      {
        memoryStream1 = new MemoryStream(cipherData);
        memoryStream2 = new MemoryStream();
        cryptoStream = new CryptoStream((Stream) memoryStream1, this.sa.CreateDecryptor(), CryptoStreamMode.Read);
        cryptoStream.CopyTo((Stream) memoryStream2);
        cryptoStream.Flush();
        if (!cryptoStream.HasFlushedFinalBlock)
          cryptoStream.FlushFinalBlock();
        return memoryStream2.ToArray();
      }
      catch (Exception ex)
      {
        throw new Exception("SymmetricsSI.Decrypt2 :: ", ex);
      }
      finally
      {
        cryptoStream?.Clear();
        memoryStream1?.Dispose();
        memoryStream2?.Dispose();
      }
    }

    public void Dispose()
    {
      this.Dispose(true);
      GC.SuppressFinalize((object) this);
    }

    private void Dispose(bool disposing)
    {
      if (this.disposed)
        return;
      if (!disposing)
        ;
      this.disposed = true;
    }
  }
}
