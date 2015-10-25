package com.proxy.jshadowsocksr;

import com.proxy.jshadowsocksr.util.LogUtil;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class SSRLocal extends Thread
{
    private AsynchronousServerSocketChannel assc;
    private String locIP;
    private String rmtIP;
    private String pwd;
    private String cryptMethod;
    private int rmtPort;
    private int locPort;

    private boolean isUdpRelay;

    public SSRLocal(String locIP, String rmtIP, int rmtPort, int locPort, String pwd, String cryptMethod,
                    boolean isUdpRelay)
    {
        this.locIP = locIP;
        this.rmtIP = rmtIP;
        this.rmtPort = rmtPort;
        this.locPort = locPort;
        this.isUdpRelay = isUdpRelay;
        this.pwd = pwd;
        this.cryptMethod = cryptMethod;
    }

    class ChannelAttach
    {
        public ByteBuffer localReadBuf = ByteBuffer.allocate(32 + 8192);
        public ByteBuffer remoteReadBuf = ByteBuffer.allocate(32 + 8192);
        public final Encryptor crypto = new Encryptor(pwd, cryptMethod);
        public AsynchronousSocketChannel localSkt = null;
        public AsynchronousSocketChannel remoteSkt = null;
    }

    @Override public void run()
    {
        try
        {
            assc = AsynchronousServerSocketChannel.open(
                    AsynchronousChannelGroup.withFixedThreadPool(
                            Runtime.getRuntime().availableProcessors()
                            , Executors.defaultThreadFactory()));
            assc.setOption(StandardSocketOptions.SO_REUSEADDR, true);
            assc.bind(new InetSocketAddress(locIP, locPort));
            assc.accept(new ChannelAttach(), new CompletionHandler<AsynchronousSocketChannel, ChannelAttach>()
            {
                @Override public void completed(AsynchronousSocketChannel result, ChannelAttach attach)
                {
                    assc.accept(new ChannelAttach(), this);
                    //
                    attach.localSkt = result;
                    try
                    {
                        if (!doAuth(attach))
                        {
                            cleanSession(attach);
                            return;
                        }
                        if (!processCMD(attach))
                        {
                            cleanSession(attach);
                        }
                    }
                    catch (Exception e)
                    {
                        cleanSession(attach);
                    }
                }

                @Override public void failed(Throwable exc, ChannelAttach attachment)
                {
                    LogUtil.err("Accept Failed,Server Stopping...");
                    stopSSRLocal();
                }
            });
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    private boolean doAuth(final ChannelAttach attach) throws Exception
    {
        attach.localReadBuf.limit(1 + 1 + 255);
        Future<Integer> readFuture = attach.localSkt.read(attach.localReadBuf);
        if (readFuture.get() < 3)
        {
            return false;
        }
        attach.localReadBuf.flip();
        if (attach.localReadBuf.get() != 0x05)//Socks Version
        {
            return false;
        }

        int methodCnt = attach.localReadBuf.get();
        if (attach.localReadBuf.limit() - attach.localReadBuf.position() < methodCnt)
        {
            return false;
        }
        else if (attach.localReadBuf.limit() - attach.localReadBuf.position() > methodCnt)
        {
            return false;
        }

        byte[] resp = new byte[]{0x05, (byte) 0xFF};

        while (methodCnt-- != 0)
        {
            if (attach.localReadBuf.get() == 0x00)//Auth_None
            {
                resp[1] = 0x00;
                break;
            }
        }

        Future<Integer> writeFuture = attach.localSkt.write(ByteBuffer.wrap(resp));
        attach.localReadBuf.clear();
        int wcnt = writeFuture.get();
        return wcnt == 2;
    }

    private boolean processCMD(final ChannelAttach attach) throws Exception
    {
        attach.localReadBuf.limit(3);//Only Read VER,CMD,RSV
        Future<Integer> futureRead = attach.localSkt.read(attach.localReadBuf);
        int rcnt = futureRead.get();
        if (rcnt < 3)
        {
            return false;
        }

        attach.localReadBuf.flip();
        if (attach.localReadBuf.get() != 0x05)//Socks Version
        {
            return false;
        }

        int cmd = attach.localReadBuf.get();
        if (attach.localReadBuf.get() != 0x00)
        {   //RSV must be 0
            return false;
        }

        switch (cmd)
        {
            case 0x03:
                InetSocketAddress isa = ((InetSocketAddress) attach.localSkt.getLocalAddress());
                byte[] addr = isa.getAddress().getAddress();
                byte[] respb = new byte[4 + addr.length + 2];
                respb[0] = 0x05;
                if (isa.getAddress().getHostAddress().contains(":"))
                {
                    respb[3] = 0x04;
                }
                else
                {
                    respb[3] = 0x01;
                }
                System.arraycopy(addr, 0, respb, 4, addr.length);
                respb[respb.length - 1] = (byte) (locPort & 0xFF);
                respb[respb.length - 2] = (byte) ((locPort >> 8) & 0xFF);
                Future<Integer> wfuture = attach.localSkt.write(ByteBuffer.wrap(respb));
                wfuture.get();
                return true;
            case 0x01:
                //Response CMD
                Future<Integer> writeToLocalFuture = attach.localSkt
                        .write(ByteBuffer.wrap(new byte[]{0x5, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}));
                writeToLocalFuture.get();
                //
                //Connect To Remote
                attach.remoteSkt = AsynchronousSocketChannel.open();
                attach.remoteSkt.setOption(StandardSocketOptions.SO_REUSEADDR, true);
                attach.remoteSkt.setOption(StandardSocketOptions.TCP_NODELAY, true);
                Future<Void> coneectFuture = attach.remoteSkt.connect(
                        new InetSocketAddress(rmtIP, rmtPort));
                coneectFuture.get();// sync connect
                //
                //Forward CMD
                byte[] cmdToSend =
                        new byte[attach.localReadBuf.limit() - attach.localReadBuf.position()];
                attach.localReadBuf.get(cmdToSend);
                cmdToSend = attach.crypto.encrypt(cmdToSend);
                Future<Integer> writeFuture = attach.remoteSkt.write(ByteBuffer.wrap(cmdToSend));
                writeFuture.get();//sync send cmd
                //
                //Ready to pipe data between localSkt and RemoteSkt
                attach.localReadBuf.clear();

                if (!checkSessionAlive(attach))
                {
                    return false;
                }
                attach.localSkt.read(attach.localReadBuf, attach, rfl);
                attach.remoteSkt.read(attach.remoteReadBuf, attach, rfr);
                return true;
            case 0x02:
                //May be need reply 0x07(Cmd Not Support)
            default:
                LogUtil.err("What ?");
                return false;
        }
    }

    private boolean checkSessionAlive(ChannelAttach attach)
    {
        return attach.localSkt != null &&
               attach.remoteSkt != null &&
               attach.localSkt.isOpen() &&
               attach.remoteSkt.isOpen();
    }

    private void cleanSession(ChannelAttach attach)
    {
        try
        {
            attach.remoteSkt.close();
            attach.localSkt.close();
        }
        catch (Exception ignored)
        {
        }
        attach.remoteSkt = null;
        attach.localSkt = null;
        attach.localReadBuf = null;
        attach.remoteReadBuf = null;
    }

    public void stopSSRLocal()
    {
        try
        {
            assc.close();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        assc = null;
        LogUtil.err("Server Stop Normally!");
    }

    private ReadFromLocalCompletionHandler rfl = new ReadFromLocalCompletionHandler();
    private ReadFromRemoteCompletionHandler rfr = new ReadFromRemoteCompletionHandler();
    private WriteToLocalCompletionHandler wtl = new WriteToLocalCompletionHandler();
    private WriteToRemoteCompletionHandler wtr = new WriteToRemoteCompletionHandler();

    class ReadFromLocalCompletionHandler implements CompletionHandler<Integer, ChannelAttach>
    {
        @Override public void completed(Integer result, ChannelAttach attach)
        {
            if (result < 1 || !checkSessionAlive(attach))
            {
                return;
            }

            attach.localReadBuf.flip();
            byte[] toRemote = new byte[attach.localReadBuf.limit()];
            attach.localReadBuf.get(toRemote);
            attach.localReadBuf.clear();
            //
            toRemote = attach.crypto.encrypt(toRemote);
            attach.remoteSkt.write(ByteBuffer.wrap(toRemote), attach, wtr);
        }


        @Override public void failed(Throwable exc, ChannelAttach attach)
        {
            LogUtil.err("RFL");
            exc.printStackTrace();
            cleanSession(attach);
        }
    }

    class ReadFromRemoteCompletionHandler implements CompletionHandler<Integer, ChannelAttach>
    {
        @Override public void completed(Integer result, ChannelAttach attach)
        {
            if (result < 1 || !checkSessionAlive(attach))
            {
                return;
            }

            attach.remoteReadBuf.flip();
            byte[] toLocal = new byte[attach.remoteReadBuf.limit()];
            attach.remoteReadBuf.get(toLocal);
            attach.remoteReadBuf.clear();
            //
            toLocal = attach.crypto.decrypt(toLocal);
            attach.localSkt.write(ByteBuffer.wrap(toLocal), attach, wtl);
        }

        @Override public void failed(Throwable exc, ChannelAttach attach)
        {
            LogUtil.err("RFR");
            exc.printStackTrace();
            cleanSession(attach);
        }
    }

    class WriteToLocalCompletionHandler implements CompletionHandler<Integer, ChannelAttach>
    {
        @Override public void completed(Integer result, ChannelAttach attach)
        {
            if (result < 1 || !checkSessionAlive(attach))
            {
                return;
            }

            LogUtil.err("To local ok," + result);
            attach.remoteSkt.read(attach.remoteReadBuf, attach, rfr);
        }

        @Override public void failed(Throwable exc, ChannelAttach attach)
        {
            LogUtil.err("WTL");
            exc.printStackTrace();
            cleanSession(attach);
        }
    }

    class WriteToRemoteCompletionHandler implements CompletionHandler<Integer, ChannelAttach>
    {
        @Override public void completed(Integer result, ChannelAttach attach)
        {
            if (result < 1 || !checkSessionAlive(attach))
            {
                return;
            }

            LogUtil.err("To remote ok," + result);
            attach.localSkt.read(attach.localReadBuf, attach, rfl);
        }

        @Override public void failed(Throwable exc, ChannelAttach attach)
        {
            LogUtil.err("WTR");
            exc.printStackTrace();
            cleanSession(attach);
        }
    }
}
