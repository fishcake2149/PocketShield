package com.pocketshield.app

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.*
import java.net.*
import java.util.concurrent.Executors

class DnsVpnService : VpnService() {
 companion object { @Volatile var running=false; @Volatile var blocked=0L }
 private var tunnel: ParcelFileDescriptor?=null
 private var worker: Thread?=null
 private val upstream=Executors.newFixedThreadPool(4)
 @Volatile private var active=false
 override fun onStartCommand(intent:Intent?, flags:Int, startId:Int):Int {
  if(intent?.action=="STOP"){ shutdown(); stopSelf(); return START_NOT_STICKY }
  if(active)return START_STICKY
  val channel="pocketshield"
  val nm=getSystemService(NotificationManager::class.java)
  nm.createNotificationChannel(NotificationChannel(channel,"광고 차단 상태",NotificationManager.IMPORTANCE_LOW))
  val pi=PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
  val notification=Notification.Builder(this,channel)
   .setSmallIcon(android.R.drawable.ic_lock_lock)
   .setContentTitle("PocketShield 실행 중")
   .setContentText("DNS 광고 필터가 활성화되었습니다")
   .setContentIntent(pi).setOngoing(true).build()
  startForeground(7,notification)
  FilterStore.load(this)
  try {
   tunnel=Builder().setSession("PocketShield").addAddress("10.111.0.2",32)
    .addDnsServer("10.111.0.1").addRoute("10.111.0.1",32).setMtu(1500).establish()
   if(tunnel==null)throw IllegalStateException("VPN 생성 실패")
   active=true; running=true
   worker=Thread { process() }.apply { name="PocketShield-DNS"; start() }
  }catch(_:Exception){ shutdown();stopSelf();return START_NOT_STICKY }
  return START_STICKY
 }
 private fun process(){
  val fd=tunnel ?: return
  val input=java.io.FileInputStream(fd.fileDescriptor)
  val output=java.io.FileOutputStream(fd.fileDescriptor)
  val lock=Any()
  val buf=ByteArray(32767)
  try { while(active){
   val n=input.read(buf); if(n<28)continue
   val packet=buf.copyOf(n)
   if(((packet[0].toInt() and 255) ushr 4)!=4)continue
   val ihl=(packet[0].toInt() and 15)*4
   if(ihl<20||n<ihl+8||(packet[9].toInt() and 255)!=17)continue
   val total=u16(packet,2); if(total>n||total<ihl+8)continue
   if((u16(packet,6) and 0x3fff)!=0)continue
   val dstPort=u16(packet,ihl+2); if(dstPort!=53)continue
   val len=u16(packet,ihl+4); if(len<8||ihl+len>total)continue
   val dns=packet.copyOfRange(ihl+8,ihl+len)
   val host=queryName(dns)
   val source=packet.copyOfRange(12,16)
   val dest=packet.copyOfRange(16,20)
   val clientPort=u16(packet,ihl)
   upstream.execute {
    try {
     val response=if(host!=null && FilterStore.blocked(host)){
      blocked++
      dns.copyOf().also { r ->
       if(r.size>=12){
        r[2]=((r[2].toInt() and 1) or 0x81).toByte()
        r[3]=0x83.toByte()
        r[6]=0;r[7]=0;r[8]=0;r[9]=0;r[10]=0;r[11]=0
       }
      }
     }else{
      DatagramSocket().use { socket ->
       protect(socket)
       socket.soTimeout=4000
       socket.send(DatagramPacket(dns,dns.size,InetAddress.getByName("1.1.1.1"),53))
       val reply=ByteArray(4096)
       val received=DatagramPacket(reply,reply.size)
       socket.receive(received)
       reply.copyOf(received.length)
      }
     }
     val result=replyPacket(dest,source,53,clientPort,response)
     synchronized(lock){ if(active)output.write(result) }
    }catch(_:Exception){}
   }
  }}catch(_:Exception){}finally { running=false }
 }
 private fun queryName(d:ByteArray):String?{
  if(d.size<17||u16(d,4)!=1)return null
  var i=12
  val labels=mutableListOf<String>()
  while(i<d.size){
   val l=d[i].toInt() and 255
   i++
   if(l==0)break
   if(l>63||i+l>d.size)return null
   val label=String(d,i,l,Charsets.US_ASCII)
   if(!label.matches(Regex("[A-Za-z0-9_-]+")))return null
   labels.add(label)
   i+=l
   if(labels.size>40)return null
  }
  if(i+4>d.size)return null
  return labels.joinToString(".")
 }
 private fun u16(b:ByteArray,i:Int)=((b[i].toInt() and 255) shl 8) or (b[i+1].toInt() and 255)
 private fun put16(b:ByteArray,i:Int,v:Int){b[i]=(v ushr 8).toByte();b[i+1]=v.toByte()}
 private fun checksum(b:ByteArray,offset:Int,length:Int):Int{
  var sum=0L
  var i=offset
  while(i<offset+length){
   sum+=((b[i].toInt() and 255) shl 8)+(if(i+1<offset+length)(b[i+1].toInt() and 255)else 0)
   i+=2
  }
  while(sum>65535)sum=(sum and 65535)+(sum ushr 16)
  return sum.inv().toInt() and 65535
 }
 private fun replyPacket(src:ByteArray,dst:ByteArray,srcPort:Int,dstPort:Int,data:ByteArray):ByteArray{
  val b=ByteArray(28+data.size)
  b[0]=0x45;b[8]=64;b[9]=17
  put16(b,2,b.size)
  System.arraycopy(src,0,b,12,4)
  System.arraycopy(dst,0,b,16,4)
  put16(b,20,srcPort)
  put16(b,22,dstPort)
  put16(b,24,8+data.size)
  System.arraycopy(data,0,b,28,data.size)
  put16(b,10,checksum(b,0,20))
  val pseudo=ByteArray(12+8+data.size)
  System.arraycopy(src,0,pseudo,0,4)
  System.arraycopy(dst,0,pseudo,4,4)
  pseudo[9]=17
  put16(pseudo,10,8+data.size)
  System.arraycopy(b,20,pseudo,12,8+data.size)
  val udpSum=checksum(pseudo,0,pseudo.size)
  put16(b,26,if(udpSum==0)65535 else udpSum)
  return b
 }
 private fun shutdown(){
  active=false;running=false
  try{tunnel?.close()}catch(_:Exception){}
  tunnel=null;worker?.interrupt();worker=null
  stopForeground(STOP_FOREGROUND_REMOVE)
 }
 override fun onDestroy(){shutdown();upstream.shutdownNow();super.onDestroy()}
 override fun onRevoke(){shutdown();stopSelf();super.onRevoke()}
}
