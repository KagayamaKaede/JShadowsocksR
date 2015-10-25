package com.proxy.jshadowsocksr.crypto.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AESCrypto extends AbsCrypto
{
    private int bit;
    private String mode;
    private byte[] key;

    /**
     * @param cryptMethod must be aes-bit-mode,e.g. aes-256-cfb
     * @param key         crypt key
     */
    public AESCrypto(String cryptMethod, byte[] key)
    {
        super(cryptMethod, key);
        String[] cpt = cryptMethod.split("-");
        //
        bit = Integer.valueOf(cpt[1]);
        mode = cpt[2];
        this.key = key;
        init();
    }

    private StreamCipher encrypt;
    private StreamCipher decrypt;

    private void init()
    {
        switch (mode)
        {
            case "cfb":
                encrypt = new CFBBlockCipher(new AESFastEngine(), bit);//save power...may be...=_=
                decrypt = new CFBBlockCipher(new AESFastEngine(), bit);
                break;
        }
    }

    @Override public void updateEncryptIV(byte[] iv)
    {
        encrypt.init(true, new ParametersWithIV(new KeyParameter(key), iv));
    }

    @Override public void updateDecryptIV(byte[] iv)
    {
        decrypt.init(false, new ParametersWithIV(new KeyParameter(key), iv));
    }

    @Override public byte[] encrypt(byte[] data)
    {
        byte[] out = new byte[data.length];
        try
        {
            encrypt.processBytes(data, 0, data.length, out, 0);
            return out;
        }
        catch (DataLengthException ignored)
        {
        }
        return null;
    }

    @Override public byte[] decrypt(byte[] data)
    {
        byte[] out = new byte[data.length];
        try
        {
            decrypt.processBytes(data, 0, data.length, out, 0);
            return out;
        }
        catch (Exception ignored)
        {
        }
        return null;
    }
}
