package com.proxy.jshadowsocksr;

import com.proxy.jshadowsocksr.crypto.CryptoInfo;
import com.proxy.jshadowsocksr.crypto.crypto.AbsCrypto;
import com.proxy.jshadowsocksr.crypto.crypto.CryptoChooser;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Encryptor
{
    private Map<String, byte[]> cachedKeys = new HashMap<>();

    private byte[] eIV;
    private boolean ivSent = false;
    private boolean ivNotRecv = true;

    private AbsCrypto crypto;

    public Encryptor(String pwd, String cryptMethod)
    {
        int[] cryptMethodInfo = new CryptoInfo().getCipherInfo(cryptMethod);
        if (cryptMethodInfo != null)
        {
            eIV = randomBytes(cryptMethodInfo[1]);
            byte[] key;

            String k = cryptMethod + ":" + pwd;

            if (cachedKeys.containsKey(k))
            {
                key = cachedKeys.get(k);
            }
            else
            {
                byte[] passbf = pwd.getBytes(Charset.forName("UTF-8"));
                key = new byte[cryptMethodInfo[0]];
                EVP_BytesToKey(passbf, key);
                cachedKeys.put(k, key);
            }
            crypto = CryptoChooser.getMatchCrypto(cryptMethod, key);
        }
    }

    public byte[] encrypt(byte[] buf)
    {
        if (buf.length == 0)
        {
            return buf;
        }
        if (ivSent)
        {
            return crypto.encrypt(buf);
        }
        ivSent = true;
        buf = crypto.encrypt(buf);
        byte[] toSend = new byte[eIV.length + buf.length];
        System.arraycopy(eIV, 0, toSend, 0, eIV.length);
        System.arraycopy(buf, 0, toSend, eIV.length, buf.length);
        return toSend;
    }

    public byte[] decrypt(byte[] buf)
    {
        if (buf.length == 0)
        {
            return buf;
        }
        if (ivNotRecv)
        {
            byte[] div = Arrays.copyOfRange(buf, 0, eIV.length);
            byte[] data = Arrays.copyOfRange(buf, eIV.length, buf.length);
            crypto.updateDecryptIV(div);
            ivNotRecv = false;
            return crypto.decrypt(data);
        }
        return crypto.decrypt(buf);
    }

    private byte[] randomBytes(int len)
    {
        byte[] bs = new byte[len];
        new SecureRandom().nextBytes(bs);
        return bs;
    }

    private void EVP_BytesToKey(byte[] password, byte[] key)
    {
        byte[] result = new byte[password.length + 16];
        int i = 0;
        byte[] md5 = null;
        while (i < key.length)
        {
            try
            {
                MessageDigest md = MessageDigest.getInstance("MD5");
                if (i == 0)
                {
                    md5 = md.digest(password);
                }
                else
                {
                    System.arraycopy(md5, 0, result, 0, md5.length);
                    System.arraycopy(password, 0, result, md5.length, password.length);
                    md5 = md.digest(result);
                }
                System.arraycopy(md5, 0, key, i, md5.length);
                i += md5.length;
            }
            catch (NoSuchAlgorithmException ignored)
            {
            }
        }
    }
}
