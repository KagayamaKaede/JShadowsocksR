package com.proxy.jshadowsocksr.crypto.crypto;

public final class CryptoChooser
{
    public static AbsCrypto getMatchCrypto(String cryptMethod, byte[] key)
    {
        if (cryptMethod.startsWith("aes-"))
        {
            return new AESCrypto(cryptMethod, key);
        }
        else if (cryptMethod.equals("chacha20") || cryptMethod.equals("salsa20"))
        {
            return new SalsaAndChachaCrypto(cryptMethod, key);
        }
        //....
        return null;
    }
}
