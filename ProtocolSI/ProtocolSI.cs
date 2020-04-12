using System;
using System.Globalization;
using System.Text;

namespace EI.SI
{
  public class ProtocolSI
  {
    private byte[] buffer = (byte[]) null;
    private const int BUFFER_LENGTH = 1403;
    private const int COMMAND_LENGTH = 1;
    private const int DATA_LENGTH = 2;
    private const int MAX_DATA_LENGTH = 1400;

    public byte[] Buffer
    {
      get
      {
        return this.buffer;
      }
      set
      {
        this.SetBuffer(value);
      }
    }

    public ProtocolSI()
    {
      this.buffer = new byte[1403];
    }

    public byte[] Make(
      ProtocolSICmdType protocolSICmdType,
      byte[] data,
      int numOfBytesToPackFromData)
    {
      if (data.Length > 1400)
        throw new Exception("O tamanho dos dados é maior que MAX_DATA_LENGTH (" + 1400.ToString() + ")");
      if (numOfBytesToPackFromData > data.Length)
        throw new Exception("O número de bytes a copiar é maior que o tamanho dos dados");
      byte[] numArray = new byte[3 + numOfBytesToPackFromData];
      numArray[0] = (byte) protocolSICmdType;
      numArray[1] = (byte) (numOfBytesToPackFromData / 256);
      numArray[2] = (byte) (numOfBytesToPackFromData % 256);
      Array.Copy((Array) data, 0, (Array) numArray, 3, numOfBytesToPackFromData);
      return numArray;
    }

    public byte[] Make(ProtocolSICmdType protocolSICmdType, byte[] data)
    {
      return this.Make(protocolSICmdType, data, data.Length);
    }

    public byte[] Make(ProtocolSICmdType protocolSICmdType, int data)
    {
      return this.Make(protocolSICmdType, ProtocolSI.ConvertIntToByteArray(data));
    }

    public byte[] Make(ProtocolSICmdType protocolSICmdType, double data)
    {
      return this.Make(protocolSICmdType, ProtocolSI.ConvertDoubleToByteArray(data));
    }

    public byte[] Make(ProtocolSICmdType protocolSICmdType, string data)
    {
      return this.Make(protocolSICmdType, ProtocolSI.ConvertStringToByteArray(data));
    }

    public byte[] Make(ProtocolSICmdType protocolSICmdType)
    {
      return this.Make(protocolSICmdType, 0);
    }

    public byte[] GetBuffer()
    {
      return this.Buffer;
    }

    public ProtocolSICmdType GetCmdType()
    {
      return (ProtocolSICmdType) this.buffer[0];
    }

    public int GetDataLength()
    {
      return (int) this.buffer[1] * 256 + (int) this.buffer[2];
    }

    public byte[] GetData()
    {
      int dataLength = this.GetDataLength();
      if (dataLength > 1400)
        throw new Exception("O tamanho dos dados é maior que MAX_DATA_LENGTH (" + 1400.ToString() + ")");
      byte[] numArray = new byte[dataLength];
      Array.Copy((Array) this.buffer, 3, (Array) numArray, 0, dataLength);
      return numArray;
    }

    public int GetIntFromData()
    {
      return ProtocolSI.ConvertByteArrayToInt(this.GetData());
    }

    public double GetDoubleFromData()
    {
      return ProtocolSI.ConvertByteArrayToDouble(this.GetData());
    }

    public string GetStringFromData()
    {
      return ProtocolSI.ConvertByteArrayToString(this.GetData());
    }

    public void SetBuffer(byte[] data)
    {
      int length = data.Length;
      if (length > 1403)
        length = 1403;
      try
      {
        Array.Copy((Array) data, (Array) this.buffer, length);
      }
      catch
      {
        Array.Clear((Array) this.buffer, 0, this.buffer.Length);
      }
    }

    public static string ToHexString(byte[] bytes)
    {
      return ProtocolSI.ToHexString(bytes, '-');
    }

    public static string ToHexString(byte[] bytes, char separator)
    {
      StringBuilder stringBuilder = new StringBuilder();
      for (int index = 0; index < bytes.Length; ++index)
        stringBuilder.Append(string.Format("{0,2:X2}{1}", (object) bytes[index], (object) separator));
      return stringBuilder.ToString().TrimEnd(separator);
    }

    public static string ToString(byte[] bytes)
    {
      try
      {
        return Encoding.UTF8.GetString(bytes).TrimEnd(new char[1]);
      }
      catch (Exception ex)
      {
        throw new Exception("ProtocoloSI.ToString :: ", ex);
      }
    }

    public static byte[] GetNewDataArray()
    {
      return new byte[1400];
    }

    public static byte[] ConvertStringToByteArray(string data)
    {
      return Encoding.UTF8.GetBytes(data);
    }

    public static string ConvertByteArrayToString(byte[] data)
    {
      return Encoding.UTF8.GetString(data);
    }

    public static byte[] ConvertIntToByteArray(int data)
    {
      return Encoding.UTF8.GetBytes(data.ToString((IFormatProvider) CultureInfo.InvariantCulture));
    }

    public static int ConvertByteArrayToInt(byte[] data)
    {
      int result = 0;
      int.TryParse(ProtocolSI.ConvertByteArrayToString(data), NumberStyles.Integer, (IFormatProvider) CultureInfo.InvariantCulture, out result);
      return result;
    }

    public static byte[] ConvertDoubleToByteArray(double data)
    {
      return Encoding.UTF8.GetBytes(data.ToString((IFormatProvider) CultureInfo.InvariantCulture));
    }

    public static double ConvertByteArrayToDouble(byte[] data)
    {
      double result = 0.0;
      double.TryParse(ProtocolSI.ConvertByteArrayToString(data), NumberStyles.Float, (IFormatProvider) CultureInfo.InvariantCulture, out result);
      return result;
    }
  }
}
