package com.pocketshield.app

import android.app.*
import android.content.*
import android.net.VpnService
import android.os.*
import android.view.Gravity
import android.widget.*

class MainActivity : Activity() {
 private lateinit var status: TextView
 private lateinit var counter: TextView
 private val handler = Handler(Looper.getMainLooper())
 private val tick = object : Runnable {
  override fun run() {
   status.text = if (DnsVpnService.running) "차단 실행 중" else "중지됨"
   counter.text = "차단된 DNS 요청: ${DnsVpnService.blocked}"
   handler.postDelayed(this,1000)
  }
 }
 override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  val layout = LinearLayout(this).apply {
   orientation=LinearLayout.VERTICAL; setPadding(36,48,36,24); gravity=Gravity.CENTER_HORIZONTAL
  }
  val title=TextView(this).apply { text="PocketShield"; textSize=30f }
  status=TextView(this).apply { textSize=20f }
  counter=TextView(this).apply { textSize=18f }
  val start=Button(this).apply {
   text="광고 차단 켜기"
   setOnClickListener {
    val i=VpnService.prepare(this@MainActivity)
    if(i!=null) startActivityForResult(i,1) else startVpn()
   }
  }
  val stop=Button(this).apply {
   text="광고 차단 끄기"
   setOnClickListener { startService(Intent(this@MainActivity,DnsVpnService::class.java).setAction("STOP")) }
  }
  val update=Button(this).apply {
   text="필터 업데이트"
   setOnClickListener {
    FilterStore.update(this@MainActivity) { msg ->
     runOnUiThread { Toast.makeText(this@MainActivity,msg,Toast.LENGTH_LONG).show() }
    }
   }
  }
  val note=TextView(this).apply {
   text="실험용 DNS 차단기입니다. 일반 VPN과 동시 사용 불가. 암호화 DNS 및 일부 앱 광고는 차단하지 못합니다."
   textSize=13f
  }
  listOf(title,status,counter,start,stop,update,note).forEach { layout.addView(it) }
  setContentView(layout)
  if(Build.VERSION.SDK_INT>=33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)
   requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),2)
 }
 private fun startVpn(){ startForegroundService(Intent(this,DnsVpnService::class.java).setAction("START")) }
 override fun onActivityResult(requestCode:Int,resultCode:Int,data:Intent?) {
  super.onActivityResult(requestCode,resultCode,data)
  if(requestCode==1&&resultCode==RESULT_OK)startVpn()
 }
 override fun onResume(){ super.onResume(); handler.post(tick) }
 override fun onPause(){ handler.removeCallbacks(tick); super.onPause() }
}
