package com.proxy.jshadowsocksr.main;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.proxy.jshadowsocksr.SSRLocal;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class Main
{
    /* Sample
{
  "server" : "1.2.3.4",
  "server_port" : 1025,
  "local_address" : "127.0.0.1",
  "local_port" : 1088,
  "password" : "csdh78cstc7dscys7csdc",
  "method" : "chacha20",
  "obfs" : "plain"
}
     */
    public static void main(String... args) throws FileNotFoundException
    {
        File local = new File("local.json");
        if (local.exists())
        {
            String json = new Scanner(local).useDelimiter("\\Z").next();
            JSONObject jobj = JSON.parseObject(json);
            String localAddr = jobj.getString("local_address");
            Integer localPort = (Integer) jobj.getOrDefault("local_port", -1);
            String remoteAddr = jobj.getString("server");
            Integer remotePort = (Integer) jobj.getOrDefault("server_port", -1);
            String passwd = jobj.getString("password");
            String cryptMethod = jobj.getString("method");
            String obfs = jobj.getString("obfs");//TODO

            if (localAddr != null && localPort > 0 &&
                remoteAddr != null && remotePort > 0 &&
                passwd != null && cryptMethod != null &&
                obfs != null)
            {
                SSRLocal ssr =
                        new SSRLocal(localAddr, remoteAddr, localPort, remotePort, passwd, cryptMethod, false);
                ssr.start();
            }
        }

    }
}
