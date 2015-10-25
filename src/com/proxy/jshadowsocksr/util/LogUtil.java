package com.proxy.jshadowsocksr.util;

import java.nio.ByteBuffer;

public class LogUtil
{
    public static void byteHexDump(String tag, byte[] bt)
    {
        System.err.print(tag + "'s hex dump: ");
        if (bt == null)
        {
            System.err.println("NULL");
            return;
        }
        System.err.printf("(%d) ", bt.length);
        for (byte b : bt)
        {
            System.err.printf("%x ", b);
        }
        System.err.println();
    }

    public static void bufHexDump(String tag, ByteBuffer buf)
    {
        System.err.print(tag + "'s hex dump: ");
        System.err.printf("(%d) ", buf.limit());
        int pos = buf.position();
        int lim = buf.limit();
        for (int i = pos; i < lim; i++)
        {
            System.err.printf("%x ", buf.get(i));
        }
        System.err.println();
    }

    public static void log(String log)
    {
        System.out.println(log);
    }

    public static void err(String err)
    {
        System.err.println(err);
    }

}
