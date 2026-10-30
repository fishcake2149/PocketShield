package com.pocketshield.app

import android.content.Context
import java.net.URL
import java.util.concurrent.Executors

object FilterStore {
 private val executor=Executors.newSingleThreadExecutor()
 @Volatile private var domains: Set<String> = emptySet()
 fun load(context:Context){
  if(domains.isEmpty()) {
   try { domains=context.openFileInput("domains.txt").bufferedReader().useLines { it.filter { x->x.isNotBlank() }.toSet() } }
   catch(_:Exception){}
  }
 }
 fun blocked(host:String):Boolean {
  val h=host.lowercase().trimEnd('.')
  var part=h
  while(true){
   if(part in domains)return true
   val dot=part.indexOf('.')
   if(dot<0)return false
   part=part.substring(dot+1)
  }
 }
 fun update(context:Context,done:(String)->Unit){
  executor.execute {
   try {
    val url=URL("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
    val conn=url.openConnection().apply { connectTimeout=12000; readTimeout=20000 }
    val set=conn.getInputStream().bufferedReader().useLines { lines ->
     lines.mapNotNull { line ->
      val t=line.trim().split(Regex("\\s+"))
      if(t.size>=2 && (t[0]=="0.0.0.0"||t[0]=="127.0.0.1") && t[1].contains('.') && !t[1].startsWith("#"))t[1].lowercase() else null
     }.toSet()
    }
    require(set.size>1000) { "필터 목록이 너무 작습니다" }
    context.openFileOutput("domains.txt",Context.MODE_PRIVATE).bufferedWriter().use { out->set.forEach { out.appendLine(it) } }
    domains=set
    done("필터 ${set.size}개 업데이트 완료")
   }catch(e:Exception){done("업데이트 실패: ${e.message}")}
  }
 }
}
