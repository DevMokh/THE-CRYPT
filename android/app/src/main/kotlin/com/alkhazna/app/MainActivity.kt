package com.alkhazna.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "vault/secure")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "setSecure" -> {
                        val on = call.argument<Boolean>("on") ?: true
                        runOnUiThread {
                            if (on) {
                                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            } else {
                                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            }
                        }
                        result.success(null)
                    }

                    // نسخ مع وضع علامة "حساس" عشان الكيبورد وأندرويد 13+ ما يعرضوش المحتوى
                    "copy" -> {
                        val text = call.argument<String>("text") ?: ""
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = ClipData.newPlainText("", text)
                        if (Build.VERSION.SDK_INT >= 23) {
                            val extras = PersistableBundle()
                            extras.putBoolean("android.content.extra.IS_SENSITIVE", true)
                            clip.description.extras = extras
                        }
                        cm.setPrimaryClip(clip)
                        result.success(null)
                    }

                    // مسح الحافظة لو لسه فيها نفس النص (أو لو أندرويد منع القراءة في الخلفية)
                    "clearIf" -> {
                        val expected = call.argument<String>("text") ?: ""
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val current: String? = try {
                            cm.primaryClip?.getItemAt(0)?.text?.toString()
                        } catch (e: Exception) {
                            null
                        }
                        if (current == null || current == expected) {
                            if (Build.VERSION.SDK_INT >= 28) {
                                cm.clearPrimaryClip()
                            } else {
                                cm.setPrimaryClip(ClipData.newPlainText("", ""))
                            }
                        }
                        result.success(null)
                    }

                    else -> result.notImplemented()
                }
            }
    }
}
